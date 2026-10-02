import os
import pytest
import psycopg
from fastapi.testclient import TestClient
from rowback.api import app, get_executor
from testcontainers.community.postgres import PostgresContainer
from rowback.capture.install import install_rowback
from rowback.executor import RowbackExecutor

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
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_api (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT rowback.register_table('public', 'test_api', 'id', 'mcp_agent');")

@pytest.fixture(scope="module")
def client(control_dsn, runtime_dsn, setup_db):
    import os
    os.environ["ROWBACK_AGENT_DSN"] = runtime_dsn
    os.environ["ROWBACK_ADMIN_DSN"] = control_dsn
    os.environ["ROWBACK_API_KEY"] = "test-api-key"
    os.environ["ROWBACK_ADMIN_KEY"] = "test-admin-key"
    
    executor = RowbackExecutor(control_dsn, runtime_dsn)
    
    app.dependency_overrides[get_executor] = lambda: executor
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

def test_api_unauthorized(client):
    res = client.get("/v1/checkpoints/pending")
    assert res.status_code == 401

def test_api_list_pending(client):
    res = client.get("/v1/checkpoints/pending", headers={"X-API-Key": "test-admin-key"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_status_not_found(client):
    res = client.get("/v1/checkpoints/cp_invalid/status", headers={"X-API-Key": "test-admin-key"})
    assert res.status_code == 404

def test_api_status_applied(client, control_dsn, runtime_dsn):
    # Execute a statement successfully and verify its status via API
    executor = RowbackExecutor(control_dsn, runtime_dsn)
    
    from rowback.models import ClassifiedStatement, StatementClass
    from rowback.policy import StatementEvaluation, PolicyDecision
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_api (id, val) VALUES (10, 'ok');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    
    # We must patch AST sentinel just for the executor instance if we can
    import rowback.sentinel
    original_firewall = rowback.sentinel.AISentinel._ast_firewall
    rowback.sentinel.AISentinel._ast_firewall = lambda self, sql: (True, "")
    try:
        res = executor.execute(eval_result, agent_label="test")
        assert res.status == "applied"
    finally:
        rowback.sentinel.AISentinel._ast_firewall = original_firewall
    
    api_res = client.get(f"/v1/checkpoints/{res.public_id}/status", headers={"X-API-Key": "test-admin-key"})
    assert api_res.status_code == 200
    assert api_res.json()["status"] == "applied"
    

def test_api_approve_outcome_unknown(client, control_dsn, runtime_dsn, monkeypatch):
    import psycopg
    executor = RowbackExecutor(control_dsn, runtime_dsn)
    
    # We create a pending checkpoint first
    with psycopg.connect(control_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM rowback.begin_checkpoint('INSERT INTO test_api VALUES(99, ''val'')', 'WRITE_DML', 'test', 'system', gen_random_uuid()::text)")
        row = cur.fetchone()
        assert row is not None
        cp_id, pub_id = row[0], row[1]
    
    original_exit = psycopg.Transaction.__exit__
    def mocked_exit(self, exc_type, exc_val, exc_tb):
        original_exit(self, exc_type, exc_val, exc_tb)
        raise psycopg.OperationalError("Simulated network loss after commit")
    
    monkeypatch.setattr(psycopg.Transaction, "__exit__", mocked_exit)
    
    # Also patch AST
    import rowback.sentinel
    monkeypatch.setattr("rowback.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    
    # Hit the approve endpoint
    api_res = client.post(f"/v1/checkpoints/{pub_id}/approve", json={"decision": "ALLOW"}, headers={"X-API-Key": "test-admin-key"})
    
    monkeypatch.undo()
    # Should get 502 with outcome_unknown
    print(api_res.text)
    assert api_res.status_code == 502
    assert api_res.json()["status"] == "unknown"
