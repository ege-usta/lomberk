import os
import threading

import psycopg
import pytest
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer

from lomberk.api import app
from lomberk.capture.install import install_lomberk


@pytest.fixture(scope="module")
def dsn():
    postgres = PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine"))
    postgres.start()
    with psycopg.connect(postgres.get_connection_url().replace("postgresql+psycopg2", "postgresql"), autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("ALTER SYSTEM SET max_prepared_transactions = 100")
        cur.execute("SELECT pg_reload_conf()")
    yield postgres.get_connection_url().replace("postgresql+psycopg2", "postgresql")
    postgres.stop()

@pytest.fixture(scope="module")
def runtime_dsn(dsn):
    return dsn.replace("test:test", "mcp_agent:secret")

@pytest.fixture(scope="function", autouse=True)
def setup_db(dsn, runtime_dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP SCHEMA IF EXISTS lomberk CASCADE")
        cur.execute("DROP SCHEMA IF EXISTS lomberk_trash CASCADE")
        try:
            cur.execute("DROP OWNED BY mcp_agent CASCADE")
        except psycopg.errors.UndefinedObject: pass
        try:
            cur.execute("DROP OWNED BY lomberk_control CASCADE")
        except psycopg.errors.UndefinedObject: pass
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("DROP ROLE IF EXISTS lomberk_control")
        cur.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")

    install_lomberk(dsn, control_role="lomberk_control", agent_role="mcp_agent")

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                CREATE TABLE IF NOT EXISTS public.api_users (
                    id SERIAL PRIMARY KEY,
                    email TEXT NOT NULL
                );
                TRUNCATE TABLE public.api_users CASCADE;
        """)
        cur.execute("GRANT ALL PRIVILEGES ON SCHEMA public TO mcp_agent")
        cur.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mcp_agent")
        cur.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_agent")
        cur.execute("SELECT lomberk.register_table('public', 'api_users', 'id', 'mcp_agent')")

@pytest.fixture
def client(dsn, runtime_dsn, monkeypatch):
    monkeypatch.setattr("lomberk.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    monkeypatch.setenv("LOMBERK_ADMIN_DSN", dsn.replace('test:test', 'lomberk_control:secret'))
    monkeypatch.setenv("LOMBERK_AGENT_DSN", runtime_dsn)
    monkeypatch.setenv("LOMBERK_API_KEY", "test-agent-key")
    monkeypatch.setenv("LOMBERK_ADMIN_KEY", "test-admin-key")

    # Reload config
    monkeypatch.setattr("lomberk.api._executor_instance", None)
    monkeypatch.setattr("lomberk.api._policy_engine_instance", None)

    # Trigger lifespan
    with TestClient(app) as client:
        yield client

def test_http_submit_idempotent_concurrent(client, dsn, monkeypatch):
    import psycopg

    ready_to_commit = threading.Event()
    commit_wait = threading.Event()

    original_exit = psycopg.Transaction.__exit__

    first_worker_passed = False

    def patched_exit(self, exc_type, exc_val, exc_tb):
        nonlocal first_worker_passed
        # Only block if it's the runtime user inserting the checkpoint
        if exc_type is None and self.connection and "mcp_agent" in self.connection.info.user:
            if not first_worker_passed:
                first_worker_passed = True
                ready_to_commit.set()
                commit_wait.wait(timeout=5.0)
        return original_exit(self, exc_type, exc_val, exc_tb)

    monkeypatch.setattr(psycopg.Transaction, "__exit__", patched_exit)

    results = []
    exceptions = []

    def worker1():
        try:
            res = client.post("/v1/execute", json={
                "sql": "INSERT INTO public.api_users (email) VALUES ('test_concurrent')",
                "operation_id": "req-111"
            }, headers={"X-API-Key": "test-agent-key"})
            results.append(res.json())
        except Exception as e:
            exceptions.append(e)

    def worker2():
        try:
            # Wait until worker1 is about to commit, holding the unique row
            ready_to_commit.wait(timeout=5.0)
            res = client.post("/v1/execute", json={
                "sql": "INSERT INTO public.api_users (email) VALUES ('test_concurrent')",
                "operation_id": "req-111"
            }, headers={"X-API-Key": "test-agent-key"})
            results.append(res.json())
        except Exception as e:
            exceptions.append(e)

    t1 = threading.Thread(target=worker1)
    t2 = threading.Thread(target=worker2)

    t1.start()
    t2.start()

    ready_to_commit.wait(timeout=5.0)
    import time
    time.sleep(0.5) # give worker2 time to hit the blocked lock
    commit_wait.set()

    t1.join(timeout=5.0)
    t2.join(timeout=5.0)

    assert not exceptions, exceptions

    # Check that exactly 1 row was inserted (table is NOT unique)
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.api_users WHERE email = 'test_concurrent'")
        assert cur.fetchone()[0] == 1

    assert len(results) == 2
    statuses = [r["results"][0]["status"] for r in results]
    assert "applied" in statuses
    # The other one gets idempotent replay


def test_different_payload_same_id_conflict(client):
    # Test 2: same principal and ID with different SQL/params/target -> conflict
    res1 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('u1@example.com')",
        "operation_id": "req-222"
    }, headers={"X-API-Key": "test-agent-key"})

    assert res1.json()["results"][0]["status"] == "applied", res1.json()["results"][0]["message"]

    res2 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('u2@example.com')",
        "operation_id": "req-222"
    }, headers={"X-API-Key": "test-agent-key"})

    assert res2.status_code == 409
    assert "Conflict:" in res2.json()["detail"]

def test_response_loss_retry(client, dsn):
    # Test 4: the response is lost after the first operation commits
    res1 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('u3@example.com')",
        "operation_id": "req-333"
    }, headers={"X-API-Key": "test-agent-key"})

    assert res1.json()["results"][0]["status"] == "applied", res1.json()["results"][0]["message"]

    # Client retries
    res2 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('u3@example.com')",
        "operation_id": "req-333"
    }, headers={"X-API-Key": "test-agent-key"})

    print(res2.json()); assert res2.json()["results"][0]["status"] == "applied"
    assert "Idempotent replay" in res2.json()["results"][0]["message"]

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.api_users WHERE email = 'u3@example.com'")
        assert cur.fetchone()[0] == 1


def test_response_loss_after_checkpoint_commit(client, dsn, monkeypatch):
    import psycopg
    original_exit = psycopg.Transaction.__exit__

    commit_count = 0
    def patched_exit(self, exc_type, exc_val, exc_tb):
        nonlocal commit_count
        original_exit(self, exc_type, exc_val, exc_tb)
        if exc_type is None and self.connection and "mcp_agent" in self.connection.info.user:
            commit_count += 1
            if commit_count == 1:
                raise psycopg.OperationalError("Simulated network drop after checkpoint commit")

    monkeypatch.setattr(psycopg.Transaction, "__exit__", patched_exit)

    res1 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('loss1')",
        "operation_id": "req-loss-1"
    }, headers={"X-API-Key": "test-agent-key"})

    assert res1.json()["results"][0]["status"] == "unknown"

    psycopg.Transaction.__exit__ = original_exit # restore network

    res2 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('loss1')",
        "operation_id": "req-loss-1"
    }, headers={"X-API-Key": "test-agent-key"})

    print(res2.json()); assert res2.json()["results"][0]["status"] == "applied"

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.api_users WHERE email = 'loss1'")
        assert cur.fetchone()[0] == 1

def test_response_loss_after_dml_commit(client, dsn, monkeypatch):
    import psycopg
    original_exit = psycopg.Transaction.__exit__

    commit_count = 0
    def patched_exit(self, exc_type, exc_val, exc_tb):
        nonlocal commit_count
        original_exit(self, exc_type, exc_val, exc_tb)
        if exc_type is None and self.connection and "mcp_agent" in self.connection.info.user:
            commit_count += 1
            if commit_count == 1:
                raise psycopg.OperationalError("Simulated network drop after DML commit")

    monkeypatch.setattr(psycopg.Transaction, "__exit__", patched_exit)

    res1 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('loss2')",
        "operation_id": "req-loss-2"
    }, headers={"X-API-Key": "test-agent-key"})

    assert res1.json()["results"][0]["status"] == "unknown"

    psycopg.Transaction.__exit__ = original_exit # restore network

    res2 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('loss2')",
        "operation_id": "req-loss-2"
    }, headers={"X-API-Key": "test-agent-key"})

    print(res2.json()); assert res2.json()["results"][0]["status"] == "applied"

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.api_users WHERE email = 'loss2'")
        assert cur.fetchone()[0] == 1

