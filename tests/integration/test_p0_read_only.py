import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from lomberk.capture.install import install_lomberk
from lomberk.executor import LomberkExecutor


@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as postgres:
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
    return urlunparse((parsed.scheme, f"lomberk_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    install_lomberk(dsn, control_role="lomberk_control", agent_role="mcp_agent")

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
    monkeypatch.setattr("lomberk.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = LomberkExecutor(control_dsn, runtime_dsn)

    from lomberk.config import load_config
    from lomberk.policy import PolicyEngine
    from lomberk.sql.classify import classify_sql
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
    monkeypatch.setattr("lomberk.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = LomberkExecutor(control_dsn, runtime_dsn)
    from lomberk.models import ClassifiedStatement, StatementClass
    from lomberk.policy import PolicyDecision, StatementEvaluation

    stmt = ClassifiedStatement(sql="SELECT public.attempt_write();", stmt_class=StatementClass.READ, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Bypassed AST")

    res = executor.execute(eval_result, agent_label="test")

    assert res.status == "failed"
    assert "cannot execute INSERT in a read-only transaction" in res.message or "read-only" in res.message


def _read(executor, sql):
    from lomberk.config import load_config
    from lomberk.policy import PolicyEngine
    from lomberk.sql.classify import classify_sql
    return executor.execute(PolicyEngine(config=load_config()).evaluate(classify_sql(sql)[0]), agent_label="test")


def test_large_read_fetches_only_what_it_returns(control_dsn, runtime_dsn, setup_db):
    """A read never pulls more rows into the gateway than it hands back: row 200 would divide
    by zero, so the query only succeeds if the gateway stopped reading after the first page."""
    executor = LomberkExecutor(control_dsn, runtime_dsn)
    res = _read(executor, "SELECT 1 / (g - 200) AS v FROM generate_series(1, 300) g")
    assert res.status == "applied", res.message
    assert len(res.data) == 100
    assert "first 100 rows" in res.message
    res = _read(executor, "SELECT g FROM generate_series(1, 5) g")
    assert res.message == "Success" and len(res.data) == 5
    assert _read(executor, "EXPLAIN SELECT 1").status == "applied"


def test_huge_values_are_cut_to_fit_an_agent_context(control_dsn, runtime_dsn, setup_db):
    from lomberk.executor import RESULT_TOTAL_CHARS, RESULT_VALUE_CHARS
    executor = LomberkExecutor(control_dsn, runtime_dsn)
    res = _read(executor, "SELECT string_agg('x', '') AS big FROM generate_series(1, 50000)")
    assert res.status == "applied", res.message
    big = res.data[0]["big"]
    assert big.startswith("x" * RESULT_VALUE_CHARS) and "more characters" in big
    assert len(big) < RESULT_VALUE_CHARS + 120
    res = _read(executor, "SELECT jsonb_agg(g) AS j FROM generate_series(1, 20000) g")
    assert isinstance(res.data[0]["j"], str) and "more characters" in res.data[0]["j"]
    # Many mid-sized rows stop at the total budget, and the message says so.
    res = _read(executor, "SELECT string_agg('y', '') AS t FROM generate_series(1, 3000) g, generate_series(1, 100) r GROUP BY r")
    assert res.status == "applied", res.message
    assert sum(len(r["t"]) for r in res.data) <= RESULT_TOTAL_CHARS
    assert len(res.data) < 100 and f"first {len(res.data)} rows" in res.message
