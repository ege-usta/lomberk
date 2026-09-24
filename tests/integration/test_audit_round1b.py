import pytest
import psycopg
import json
import os
import urllib.error
from fastapi.testclient import TestClient

from undogate.models import ClassifiedStatement, StatementClass, StatementEvaluation, PolicyDecision

from testcontainers.community.postgres import PostgresContainer

from undogate.api import app
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
def setup_db(dsn, runtime_dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    
    install_undogate(dsn, agent_role='mcp_agent')
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS public.users (id SERIAL PRIMARY KEY, data TEXT, role TEXT, password TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS public.dangerous_function ()")
        cur.execute("INSERT INTO public.users (data) VALUES ('test_admin'); SELECT undogate.register_table('public', 'users', 'id', 'mcp_agent')")
        cur.execute("REVOKE SELECT, UPDATE ON public.users FROM mcp_agent")
        cur.execute("GRANT SELECT (id, data, role), UPDATE (id, data, role) ON public.users TO mcp_agent")

def test_llm_safe_boolean_mock(monkeypatch):
    from undogate.sentinel import AISentinel
    
    payloads = [
        {"safe": "false", "reason": "string false"},
        {"safe": 1, "reason": "int 1"},
        {"safe": None, "reason": "null"},
        {"reason": "missing safe"},
        "invalid_json"
    ]
    
    for p in payloads:
        class MockResponse:
            def read(self):
                return json.dumps({"choices": [{"message": {"content": json.dumps(p) if isinstance(p, dict) else p}}]}).encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass
            
        def mock_urlopen(*args, **kwargs):
            return MockResponse()
            
        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
        
        sentinel = AISentinel()
        sentinel.api_key = "test"
        safe, reason = sentinel.evaluate_intent("SELECT 1", [])
        assert safe is False
        assert "Invalid boolean format" in reason or "Unexpected error" in reason or "Network/API failure" in reason

def test_timeout_mock(monkeypatch):
    from undogate.sentinel import AISentinel
    def mock_timeout(*args, **kwargs):
        raise urllib.error.URLError("Timeout")
    monkeypatch.setattr("urllib.request.urlopen", mock_timeout)
    
    sentinel = AISentinel()
    sentinel.api_key = "test"
    safe, reason = sentinel.evaluate_intent("SELECT 1", [])
    assert safe is False
    assert "Network/API failure" in reason
    

def test_api_valid_approval_flow(monkeypatch, dsn, runtime_dsn, setup_db):
    monkeypatch.setenv("UNDOGATE_AGENT_DSN", runtime_dsn)
    monkeypatch.setenv("UNDOGATE_API_KEY", "agent")
    monkeypatch.setenv("UNDOGATE_ADMIN_KEY", "admin")
    
    with TestClient(app) as client:
        # Step 1: Agent tries valid DML write
        resp = client.post("/v1/execute", json={"sql": "UPDATE public.users SET data = 'updated' WHERE id = 1;"}, headers={"X-API-Key": "agent"})
        assert resp.status_code == 200
        res_data = resp.json()["results"][0]
        assert res_data["status"] == "approval_required"
        
        token = res_data["checkpoint_id"]
        
        # Step 2: Target row should remain unchanged
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT data FROM public.users WHERE id = 1")
            assert cur.fetchone()[0] == "test_admin"
            
        # Step 3: Admin approves
        approve_resp = client.post(f"/v1/checkpoints/{token}/approve", headers={"X-API-Key": "admin"})
        assert approve_resp.status_code == 200
        assert approve_resp.json()["status"] == "approved"
        assert approve_resp.json()["rows_affected"] == 1
        
        # Step 4: Target row should be updated
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT data FROM public.users WHERE id = 1")
            assert cur.fetchone()[0] == "updated"




def test_p0_quoted_identifier_injection(dsn, runtime_dsn, setup_db):
    from undogate.executor import UndogateExecutor
    import psycopg
    executor = UndogateExecutor(runtime_dsn)
    
    stmt = ClassifiedStatement(sql='UPDATE public."users; SELECT 1; --" SET data=\'x\' WHERE id=1', stmt_class=StatementClass.WRITE_DML, tables=[])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    
    res = executor.execute(eval)
    assert res.status == "failed"
    assert "does not exist" in res.message or "not registered" in res.message

def test_p0_sensitive_alias_leak(dsn, runtime_dsn, setup_db):
    from undogate.executor import UndogateExecutor
    import psycopg
    executor = UndogateExecutor(runtime_dsn)
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("UPDATE public.users SET password = 'real-synthetic-secret' WHERE id = 1")
        
    stmt = ClassifiedStatement(sql='SELECT password AS safe_val FROM public.users', stmt_class=StatementClass.READ, tables=["public.users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")
    
    res = executor.execute(eval)
    assert res.status == "failed"
    assert "Access denied: Query contains sensitive columns" in res.message

def test_p0_sensitive_returning_leak(dsn, runtime_dsn, setup_db):
    from undogate.executor import UndogateExecutor
    executor = UndogateExecutor(runtime_dsn)
    
    stmt = ClassifiedStatement(sql='UPDATE public.users SET data=\'x\' WHERE id=1 RETURNING password', stmt_class=StatementClass.WRITE_DML, tables=["public.users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    
    res = executor.execute(eval)
    assert res.status == "failed"
    assert "Access denied: Query contains sensitive columns" in res.message

def test_p0_whole_row_wildcard_leak(dsn, runtime_dsn, setup_db):
    from undogate.executor import UndogateExecutor
    executor = UndogateExecutor(runtime_dsn)
    
    stmt = ClassifiedStatement(sql='SELECT * FROM public.users', stmt_class=StatementClass.READ, tables=["public.users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")
    
    res = executor.execute(eval)
    assert res.status == "failed"
    assert "Access denied" in res.message or "permission denied" in res.message

def test_p0_runtime_missing_context(dsn, runtime_dsn, setup_db):
    import psycopg
    import pytest
    with psycopg.connect(runtime_dsn, autocommit=True) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.RaiseException, match="Undogate Security Violation"):
            cur.execute("INSERT INTO public.users (data) VALUES ('bypass')")

def test_p0_forged_context_rejected(dsn, runtime_dsn, setup_db):
    import psycopg
    import pytest
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT undogate.begin_checkpoint('SELECT 1', 'WRITE_DML', 'mcp_agent', 'pending')")
        cp_id = cur.fetchone()[0]
        
    with psycopg.connect(runtime_dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('undogate.checkpoint_id', %s, true)", (str(cp_id),))
        with pytest.raises(psycopg.errors.RaiseException, match="Invalid checkpoint context|Security Violation"):
            cur.execute("INSERT INTO public.users (data) VALUES ('forged')")

def test_p0_runtime_checkpoint_state_change(dsn, runtime_dsn, setup_db):
    import psycopg
    import pytest
    with psycopg.connect(runtime_dsn, autocommit=True) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            cur.execute("UPDATE undogate.checkpoints SET status = 'applied' WHERE id = 1")
