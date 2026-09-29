import pytest
import psycopg
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback
from rowback.executor import RowbackExecutor
from rowback.models import ClassifiedStatement, StatementClass, PolicyDecision, StatementEvaluation

@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer("postgres:16-alpine") as postgres:
        yield postgres

@pytest.fixture(scope="module")
def dsn(postgres):
    return postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")

@pytest.fixture(scope="module")
def runtime_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"mcp_agent:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn, runtime_dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("DROP ROLE IF EXISTS rowback_control")
        cur.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    
    install_rowback(dsn, control_role="rowback_control", agent_role="mcp_agent")

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                CREATE TABLE public.test_ddl (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                );
            """)
        cur.execute("SELECT rowback.register_table('public', 'test_ddl', 'id', 'mcp_agent');")
        cur.execute("INSERT INTO public.test_ddl (data) VALUES ('A'), ('B')")

def test_drop_table_undo(dsn, runtime_dsn, setup_db):
    executor = RowbackExecutor(dsn, runtime_dsn)

    stmt = ClassifiedStatement(sql="DROP TABLE public.test_ddl;", stmt_class=StatementClass.DDL_REVERSIBLE, tables=["public.test_ddl"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.REQUIRE_APPROVAL, reason="Test")
    eval.decision = PolicyDecision.ALLOW

    res = executor.execute(eval)
    assert res.status == "denied"
    assert "Hard Gate Denied" in res.message

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'test_ddl'")
            assert cur.fetchone()[0] == 1

def test_truncate_undo(dsn, runtime_dsn, setup_db):
    executor = RowbackExecutor(dsn, runtime_dsn)

    stmt = ClassifiedStatement(sql="TRUNCATE public.test_ddl;", stmt_class=StatementClass.DDL_REVERSIBLE, tables=["public.test_ddl"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")

    res = executor.execute(eval)
    assert res.status == "denied"
    assert "Hard Gate Denied" in res.message

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_ddl")
        assert cur.fetchone()[0] == 2

def test_drop_column_undo(dsn, runtime_dsn, setup_db):
    executor = RowbackExecutor(dsn, runtime_dsn)

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("ALTER TABLE public.test_ddl ADD COLUMN extra INT DEFAULT 42;")

    stmt = ClassifiedStatement(sql="ALTER TABLE public.test_ddl DROP COLUMN extra;", stmt_class=StatementClass.DDL_REVERSIBLE, tables=["public.test_ddl"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")

    res = executor.execute(eval)
    assert res.status == "denied"
    assert "Hard Gate Denied" in res.message

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'test_ddl' AND column_name = 'extra'")
            assert cur.fetchone()[0] == 1
