import pytest
import psycopg
from testcontainers.community.postgres import PostgresContainer
from undogate.capture.install import install_undogate
from undogate.executor import UndogateExecutor

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
def control_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"undogate_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE ROLE undogate_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    install_undogate(dsn, control_role="undogate_control", agent_role="mcp_agent")

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.read_users (id INT, name TEXT, password TEXT);")
        cur.execute("INSERT INTO public.read_users (id, name, password) VALUES (1, 'alice', 'secret');")
        cur.execute("GRANT SELECT ON public.read_users TO mcp_agent;")
        cur.execute("GRANT INSERT, UPDATE, DELETE ON public.read_users TO mcp_agent;")
        
        # A function that attempts to write
        cur.execute("""
            CREATE OR REPLACE FUNCTION public.attempt_write() RETURNS INT AS $$
            BEGIN
                INSERT INTO public.read_users (id, name, password) VALUES (99, 'hacker', '123');
                RETURN 1;
            END;
            $$ LANGUAGE plpgsql;
        """)
        cur.execute("GRANT EXECUTE ON FUNCTION public.attempt_write TO mcp_agent;")

def test_p0_read_only_path(dsn, control_dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)

    from undogate.sql.classify import classify_sql
    from undogate.policy import PolicyEngine
    from undogate.config import load_config
    policy = PolicyEngine(config=load_config())
    
    # We will verify that transaction_read_only is 'on'
    stmts = classify_sql("SELECT current_setting('transaction_read_only');")
    eval_result = policy.evaluate(stmts[0])
    res = executor.execute(eval_result, agent_label="test")
    
    assert res.status == "applied"
    assert res.data[0]['current_setting'] == 'on'
    
    # Verify statement_timeout works
    stmts = classify_sql("SELECT pg_sleep(6);")
    eval_result = policy.evaluate(stmts[0])
    res = executor.execute(eval_result, agent_label="test")
    
    assert res.status == "failed"
    assert "canceling statement due to statement timeout" in res.message.lower()

def test_p0_read_only_db_level_enforcement(dsn, control_dsn, runtime_dsn, setup_db, monkeypatch):
    # Bypass AST completely to prove DB-level enforcement
    # We construct a fake StatementEvaluation that is classified as READ,
    # but the SQL actually calls a function that does an INSERT.
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    from undogate.models import ClassifiedStatement, StatementClass
    from undogate.policy import StatementEvaluation, PolicyDecision
    
    stmt = ClassifiedStatement(sql="SELECT public.attempt_write();", stmt_class=StatementClass.READ, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Bypassed AST")
    
    res = executor.execute(eval_result, agent_label="test")
    
    assert res.status == "failed"
    assert "cannot execute INSERT in a read-only transaction" in res.message or "read-only" in res.message
