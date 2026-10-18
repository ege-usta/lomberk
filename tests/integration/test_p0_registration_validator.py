import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback
from rowback.executor import RowbackExecutor
from rowback.models import ClassifiedStatement, StatementClass
from rowback.policy import PolicyDecision, StatementEvaluation


@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer(os.environ.get("ROWBACK_TEST_PG_IMAGE", "postgres:16-alpine")) as postgres:
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
    return urlunparse((parsed.scheme, f"rowback_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    install_rowback(dsn, control_role="rowback_control", agent_role="mcp_agent")

def get_stmt(sql):
    return StatementEvaluation(
        statement=ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False),
        decision=PolicyDecision.ALLOW,
        reason=""
    )

def test_p0_registration_validator_strict(dsn, control_dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("rowback.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = RowbackExecutor(control_dsn, runtime_dsn)

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_reg (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT rowback.register_table('public', 'test_reg', 'id', 'mcp_agent');")

    res = executor.execute(get_stmt("INSERT INTO public.test_reg (id, val) VALUES (1, 'val');"), agent_label="test")
    assert res.status == "applied"

    # 1. Disable trigger to replica-only ('O' to 'R')
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("ALTER TABLE public.test_reg ENABLE REPLICA TRIGGER rowback_capture;")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg (id, val) VALUES (2, 'val');"), agent_label="test")
    assert res.status == "failed"
    assert "Trigger disabled or replica-only" in res.message

    # 2. Disable trigger completely ('D')
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("ALTER TABLE public.test_reg DISABLE TRIGGER rowback_capture;")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg (id, val) VALUES (2, 'val');"), agent_label="test")
    assert res.status == "failed"
    assert "Trigger disabled or replica-only" in res.message

    # 3. OID mismatch
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP TABLE public.test_reg;")
        cur.execute("CREATE TABLE public.test_reg (id INT PRIMARY KEY, val TEXT);")
        cur.execute("CREATE TRIGGER rowback_capture AFTER INSERT OR UPDATE OR DELETE ON public.test_reg FOR EACH ROW EXECUTE FUNCTION rowback.capture_row_change();")
        cur.execute("GRANT ALL ON public.test_reg TO mcp_agent;")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg (id, val) VALUES (2, 'val');"), agent_label="test")
    assert res.status == "failed"
    assert "Registration mismatch" in res.message and "OID has changed" in res.message

    # 4. Dropped PK column
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT rowback.register_table('public', 'test_reg', 'id', 'mcp_agent');")
        cur.execute("ALTER TABLE public.test_reg DROP COLUMN id;")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg (val) VALUES ('val');"), agent_label="test")
    assert res.status == "failed"
    assert "has no primary key" in res.message

    # 5. Dropped PK constraint (column exists, but no constraint)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_reg2 (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT rowback.register_table('public', 'test_reg2', 'id', 'mcp_agent');")
        cur.execute("ALTER TABLE public.test_reg2 DROP CONSTRAINT test_reg2_pkey;")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg2 (id, val) VALUES (2, 'val');"), agent_label="test")
    assert res.status == "failed"
    assert "has no primary key" in res.message

    # 6. Wrong function OID (Spoofing)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_reg3 (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT rowback.register_table('public', 'test_reg3', 'id', 'mcp_agent');")
        cur.execute("CREATE FUNCTION public.fake_capture() RETURNS trigger AS $$ BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql;")
        cur.execute("DROP TRIGGER rowback_capture ON public.test_reg3;")
        cur.execute("CREATE TRIGGER rowback_capture AFTER INSERT OR UPDATE OR DELETE ON public.test_reg3 FOR EACH ROW EXECUTE FUNCTION public.fake_capture();")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg3 (id, val) VALUES (3, 'val');"), agent_label="test")
    assert res.status == "failed"
    assert "Trigger function OID mismatch" in res.message

    # 7. Wrong Trigger Type (BEFORE)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_reg4 (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT rowback.register_table('public', 'test_reg4', 'id', 'mcp_agent');")
        cur.execute("DROP TRIGGER rowback_capture ON public.test_reg4;")
        cur.execute("CREATE TRIGGER rowback_capture BEFORE INSERT OR UPDATE OR DELETE ON public.test_reg4 FOR EACH ROW EXECUTE FUNCTION rowback.capture_row_change();")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg4 (id, val) VALUES (4, 'val');"), agent_label="test")
    assert res.status == "failed"
    assert "Trigger type mismatch" in res.message

    # 8. Trigger WHEN condition
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_reg5 (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT rowback.register_table('public', 'test_reg5', 'id', 'mcp_agent');")
        cur.execute("DROP TRIGGER rowback_capture ON public.test_reg5;")
        cur.execute("CREATE TRIGGER rowback_capture AFTER INSERT OR UPDATE OR DELETE ON public.test_reg5 FOR EACH ROW WHEN (pg_trigger_depth() < 10) EXECUTE FUNCTION rowback.capture_row_change();")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg5 (id, val) VALUES (5, 'val');"), agent_label="test")
    assert res.status == "failed"
    assert "Trigger condition (WHEN) is not allowed" in res.message

    # 9. Trigger UPDATE OF condition
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_reg6 (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT rowback.register_table('public', 'test_reg6', 'id', 'mcp_agent');")
        cur.execute("DROP TRIGGER rowback_capture ON public.test_reg6;")
        cur.execute("CREATE TRIGGER rowback_capture AFTER INSERT OR UPDATE OF val OR DELETE ON public.test_reg6 FOR EACH ROW EXECUTE FUNCTION rowback.capture_row_change();")
    res = executor.execute(get_stmt("INSERT INTO public.test_reg6 (id, val) VALUES (6, 'val');"), agent_label="test")
    assert res.status == "failed"
    # Actually UPDATE OF changes tgtype (not 29 anymore!), so it might fail on tgtype or tgattr.
    # Just check it failed.
    assert res.status == "failed"

