import pytest
import psycopg
import asyncio
import httpx
from fastapi.testclient import TestClient
from testcontainers.postgres import PostgresContainer
from undogate.api import app, verify_api_key, verify_admin_key, get_executor, get_policy_engine
import undogate.api
import undogate.config
from undogate.slack import SlackInteractionAdapter

@pytest.fixture(scope="module")
def postgres():
    postgres = PostgresContainer("postgres:16-alpine")
    postgres.start()
    yield postgres
    postgres.stop()

@pytest.fixture(scope="module")
def dsn(postgres):
    return postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")

@pytest.fixture(scope="module")
def runtime_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"mcp_agent:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def admin_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"undogate_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn, runtime_dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
        cur.execute("DROP ROLE IF EXISTS undogate_control")
        cur.execute("CREATE ROLE undogate_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
    
    from undogate.capture.install import install_undogate
    install_undogate(dsn, control_role='undogate_control', agent_role='mcp_agent')
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS public.users (id SERIAL PRIMARY KEY, data TEXT)")
        cur.execute("INSERT INTO public.users (data) VALUES ('val1')")
        cur.execute("SELECT undogate.register_table('public', 'users', 'id', 'mcp_agent')")
        cur.execute("GRANT ALL ON SCHEMA public TO mcp_agent")
        cur.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO mcp_agent")
        cur.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO mcp_agent")

@pytest.fixture
def auth_and_config(monkeypatch, runtime_dsn, admin_dsn):
    # Proper module-level auth setup for testing the real verification chain
    monkeypatch.setenv("UNDOGATE_AGENT_DSN", runtime_dsn)
    monkeypatch.setenv("UNDOGATE_ADMIN_DSN", admin_dsn)
    monkeypatch.setenv("UNDOGATE_API_KEY", "real_agent_key")
    monkeypatch.setenv("UNDOGATE_ADMIN_KEY", "real_admin_key")
    
    old_api_key = undogate.api._API_KEY
    old_admin_key = undogate.api._ADMIN_KEY
    undogate.api._API_KEY = "real_agent_key"
    undogate.api._ADMIN_KEY = "real_admin_key"
    
    original_load = undogate.config.load_config
    def mock_load(*a, **kw):
        cfg = original_load(*a, **kw)
        cfg.limits.max_rows_without_approval = 0
        cfg.protected_tables = ["public.users"]
        return cfg
        
    def override_get_executor():
        from undogate.executor import UndogateExecutor
        return UndogateExecutor(admin_dsn, runtime_dsn)
        
    def override_get_policy_engine():
        from undogate.policy import PolicyEngine
        return PolicyEngine(mock_load())

    app.dependency_overrides.clear()
    app.dependency_overrides[get_executor] = override_get_executor
    app.dependency_overrides[get_policy_engine] = override_get_policy_engine
    
    yield
    
    undogate.api._API_KEY = old_api_key
    undogate.api._ADMIN_KEY = old_admin_key
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_slack_adapter_db_concurrency_and_auth(setup_db, auth_and_config, dsn):
    # 1. First, create a pending checkpoint using sync TestClient
    with TestClient(app) as client:
        resp = client.post("/v1/execute", json={"sql": "INSERT INTO public.users (data) VALUES ('val2')"}, headers={"X-API-Key": "real_agent_key"})
        assert resp.status_code == 200, resp.text
        public_id = resp.json()["results"][0]["checkpoint_id"]

    # 2. Setup the async adapter hitting the real FastAPI app
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as acl:
        
        async def resolve_target(team, channel, ts):
            return public_id if channel == "C1" else None

        async def approve_cb(pid):
            # Uses real admin key to pass verify_admin_key
            r = await acl.post(f"/v1/checkpoints/{pid}/approve", headers={"X-API-Key": "real_admin_key"}); print("approve_cb returned", r.status_code, r.text)
            if r.status_code == 409 or (r.status_code == 400 and ("applied" in r.text or "approved" in r.text)):
                # Return conflict status, but poll actual status to determine authoritative UI state
                status_r = await acl.get(f"/v1/checkpoints/{pid}/status", headers={"X-API-Key": "real_admin_key"})
                print("STATUS_R:", status_r.text); auth_state = status_r.json().get("status", "unknown") if status_r.status_code == 200 else "unknown"
                return {"status": "conflict", "authoritative_state": auth_state}
            return {"status": r.json().get("status"), "authoritative_state": r.json().get("status")}
            
        async def reject_cb(pid):
            r = await acl.post(f"/v1/checkpoints/{pid}/reject", headers={"X-API-Key": "real_admin_key"})
            return r.json()
            
        update_calls = []
        async def update_cb(channel, ts, msg):
            update_calls.append(msg)

        adapter = SlackInteractionAdapter(
            {"U123"}, {"T1"}, resolve_target, approve_cb, reject_cb, update_cb
        )
        
        payload = {
            "team": {"id": "T1"}, "user": {"id": "U123"},
            "container": {"channel_id": "C1", "message_ts": "123"},
            "actions": [{"action_id": "approve_button", "value": public_id}]
        }
        
        # Test Negative Auth flow via the Slack adapter callback calling the API with bad key
        async def bad_approve_cb(pid):
            r = await acl.post(f"/v1/checkpoints/{pid}/approve", headers={"X-API-Key": "bad_key"})
            return {"status": "error", "message": r.text, "error_code": str(r.status_code)}
        
        bad_adapter = SlackInteractionAdapter(
            {"U123"}, {"T1"}, resolve_target, bad_approve_cb, reject_cb, update_cb
        )
        await bad_adapter.handle_interaction(payload)
        await bad_adapter.shutdown()
        
        # Verify 403 Invalid API key prevented execution
        assert any("execution securely aborted" in msg for msg in update_calls)
        update_calls.clear()

        # Test true database concurrency: Two concurrent interactions with real async clients
        await asyncio.gather(
            adapter.handle_interaction(payload),
            adapter.handle_interaction(payload)
        )
        await adapter.shutdown()

        # Ensure two updates (one from each task) and both report success due to authoritative state checking
        assert len(update_calls) == 2
        assert any("successfully applied" in msg for msg in update_calls)
        # The duplicate could return "busy", "applied", or "approved" depending on exact timing.
        # If it returns "applied" or "approved", it'll just say "successfully applied".
        # If it returns "busy" or "unknown", it will say "processed previously. Current state:".
        assert all("successfully applied" in msg or "processed previously" in msg for msg in update_calls)
        
        # Verify actual DB side-effects are exactly 1 capture execution
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.users")
            assert cur.fetchone()[0] == 2 # 1 initial + 1 inserted (duplicate insert rejected)
