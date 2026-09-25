import pytest
import psycopg
from fastapi.testclient import TestClient
from undogate.api import app, get_executor
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
        cur.execute("CREATE TABLE public.test_api (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT undogate.register_table('public', 'test_api', 'id', 'mcp_agent');")

@pytest.fixture(scope="module")
def client(control_dsn, runtime_dsn, setup_db):
    import os
    os.environ["UNDOGATE_AGENT_DSN"] = runtime_dsn
    os.environ["UNDOGATE_ADMIN_DSN"] = control_dsn
    os.environ["UNDOGATE_API_KEY"] = "test-api-key"
    os.environ["UNDOGATE_ADMIN_KEY"] = "test-admin-key"
    
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
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
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    from undogate.models import ClassifiedStatement, StatementClass
    from undogate.policy import StatementEvaluation, PolicyDecision
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_api (id, val) VALUES (10, 'ok');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    
    # We must patch AST sentinel just for the executor instance if we can
    import undogate.sentinel
    original_firewall = undogate.sentinel.AISentinel._ast_firewall
    undogate.sentinel.AISentinel._ast_firewall = lambda self, sql: (True, "")
    try:
        res = executor.execute(eval_result, agent_label="test")
        assert res.status == "applied"
    finally:
        undogate.sentinel.AISentinel._ast_firewall = original_firewall
    
    api_res = client.get(f"/v1/checkpoints/{res.public_id}/status", headers={"X-API-Key": "test-admin-key"})
    assert api_res.status_code == 200
    assert api_res.json()["status"] == "applied"
    

def test_api_approve_outcome_unknown(client, control_dsn, runtime_dsn, monkeypatch):
    import psycopg
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    # We create a pending checkpoint first
    with psycopg.connect(control_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM undogate.begin_checkpoint('INSERT INTO test_api VALUES(99, ''val'')', 'WRITE_DML', 'test')")
        row = cur.fetchone()
        assert row is not None
        cp_id, pub_id = row[0], row[1]
    
    original_exit = psycopg.Transaction.__exit__
    def mocked_exit(self, exc_type, exc_val, exc_tb):
        original_exit(self, exc_type, exc_val, exc_tb)
        raise psycopg.OperationalError("Simulated network loss after commit")
    
    monkeypatch.setattr(psycopg.Transaction, "__exit__", mocked_exit)
    
    # Also patch AST
    import undogate.sentinel
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    
    # Hit the approve endpoint
    api_res = client.post(f"/v1/checkpoints/{pub_id}/approve", json={"decision": "ALLOW"}, headers={"X-API-Key": "test-admin-key"})
    
    monkeypatch.undo()
    # Should get 502 with outcome_unknown
    print(api_res.text)
    assert api_res.status_code == 502
    assert api_res.json()["status"] == "outcome_unknown"
