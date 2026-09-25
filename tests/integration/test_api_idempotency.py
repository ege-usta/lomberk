import pytest
import os
import threading
from fastapi.testclient import TestClient
import psycopg
from testcontainers.postgres import PostgresContainer

from undogate.api import app, _API_KEY
from undogate.config import load_config
from undogate.capture.install import install_undogate

@pytest.fixture(scope="module")
def dsn():
    postgres = PostgresContainer("postgres:16-alpine")
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
        cur.execute("DROP SCHEMA IF EXISTS undogate CASCADE")
        cur.execute("DROP SCHEMA IF EXISTS undogate_trash CASCADE")
        try:
            cur.execute("DROP OWNED BY mcp_agent CASCADE")
        except psycopg.errors.UndefinedObject: pass
        try:
            cur.execute("DROP OWNED BY undogate_control CASCADE")
        except psycopg.errors.UndefinedObject: pass
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("DROP ROLE IF EXISTS undogate_control")
        cur.execute("CREATE ROLE undogate_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    
    install_undogate(dsn, control_role="undogate_control", agent_role="mcp_agent")

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                CREATE TABLE IF NOT EXISTS public.api_users (
                    id SERIAL PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL
                );
                TRUNCATE TABLE public.api_users CASCADE;
        """)
        cur.execute("GRANT ALL PRIVILEGES ON SCHEMA public TO mcp_agent")
        cur.execute("GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO mcp_agent")
        cur.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_agent")
        cur.execute("SELECT undogate.register_table('public', 'api_users', 'id', 'mcp_agent')")

@pytest.fixture
def client(dsn, runtime_dsn, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    monkeypatch.setenv("UNDOGATE_ADMIN_DSN", dsn.replace('test:test', 'undogate_control:secret'))
    monkeypatch.setenv("UNDOGATE_AGENT_DSN", runtime_dsn)
    monkeypatch.setenv("UNDOGATE_API_KEY", "test-agent-key")
    monkeypatch.setenv("UNDOGATE_ADMIN_KEY", "test-admin-key")
    
    # Reload config
    from undogate.api import _executor_instance, _policy_engine_instance
    monkeypatch.setattr("undogate.api._executor_instance", None)
    monkeypatch.setattr("undogate.api._policy_engine_instance", None)
    
    # Trigger lifespan
    with TestClient(app) as client:
        yield client

def test_http_submit_idempotent_concurrent(client, dsn):
    # Test 1: Gerçek HTTP/MCP submit aynı ID ardışık ve barrier ile eşzamanlı
    import threading
    barrier = threading.Barrier(2)
    
    results = []
    
    def worker():
        barrier.wait()
        res = client.post("/v1/execute", json={
            "sql": "INSERT INTO public.api_users (email) VALUES ('test@example.com')",
            "operation_id": "req-111"
        }, headers={"X-API-Key": "test-agent-key"})
        results.append(res.json())

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    
    # Check that exactly 1 row was inserted
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.api_users WHERE email = 'test@example.com'")
        assert cur.fetchone()[0] == 1
        
    # Check that both got successful response
    assert len(results) == 2
    for r in results:
        res_list = r["results"]
        assert len(res_list) == 1
        assert res_list[0]["status"] in ["applied", "approval_required", "approved"]
        if res_list[0]["status"] == "applied":
            assert "Idempotent replay" in res_list[0]["message"] or "Success" in res_list[0]["message"] or "Rows affected" in res_list[0]["message"]

def test_different_payload_same_id_conflict(client):
    # Test 2: Aynı principal/ID farklı SQL/params/target -> conflict
    res1 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('u1@example.com')",
        "operation_id": "req-222"
    }, headers={"X-API-Key": "test-agent-key"})
    
    assert res1.json()["results"][0]["status"] == "applied", res1.json()["results"][0]["message"]
    
    res2 = client.post("/v1/execute", json={
        "sql": "INSERT INTO public.api_users (email) VALUES ('u2@example.com')",
        "operation_id": "req-222"
    }, headers={"X-API-Key": "test-agent-key"})
    
    assert res2.json()["results"][0]["status"] == "failed"
    assert "Conflict:" in res2.json()["results"][0]["message"]

def test_response_loss_retry(client, dsn):
    # Test 4: İlk operation commit'i sonrası response kaybı
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
    
    assert res2.json()["results"][0]["status"] == "applied"
    assert "Idempotent replay" in res2.json()["results"][0]["message"]
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.api_users WHERE email = 'u3@example.com'")
        assert cur.fetchone()[0] == 1

