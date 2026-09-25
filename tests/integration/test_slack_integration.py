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
    with TestClient(app) as client:
        resp = client.post("/v1/execute", json={"sql": "INSERT INTO public.users (data) VALUES ('val2')"}, headers={"X-API-Key": "real_agent_key"})
        assert resp.status_code == 200, resp.text
        public_id = resp.json()["results"][0]["checkpoint_id"]

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as acl:
        async def resolve_target(team, channel, ts):
            return public_id if channel == "C1" else None

        async def approve_cb(pid):
            r = await acl.post(f"/v1/checkpoints/{pid}/approve", headers={"X-API-Key": "real_admin_key"})
            return {"status": "conflict"} if r.status_code == 409 or (r.status_code == 400 and ("applied" in r.text or "approved" in r.text)) else {"status": r.json().get("status")}
            
        async def reject_cb(pid):
            r = await acl.post(f"/v1/checkpoints/{pid}/reject", headers={"X-API-Key": "real_admin_key"})
            return r.json()
            
        async def status_cb(pid):
            r = await acl.get(f"/v1/checkpoints/{pid}/status", headers={"X-API-Key": "real_admin_key"})
            return r.json().get("status", "unknown") if r.status_code == 200 else "unknown"

        update_calls = []
        async def update_cb(channel, ts, msg):
            update_calls.append(msg)

        adapter = SlackInteractionAdapter({"U123"}, {"T1"}, resolve_target, approve_cb, reject_cb, status_cb, update_cb)
        
        payload = {
            "team": {"id": "T1"}, "user": {"id": "U123"},
            "container": {"channel_id": "C1", "message_ts": "123"},
            "actions": [{"action_id": "approve_button", "value": public_id}]
        }
        
        # Test Negative Auth
        async def bad_approve_cb(pid):
            r = await acl.post(f"/v1/checkpoints/{pid}/approve", headers={"X-API-Key": "bad_key"})
            return {"status": "error"}
        
        bad_adapter = SlackInteractionAdapter({"U123"}, {"T1"}, resolve_target, bad_approve_cb, reject_cb, status_cb, update_cb)
        await bad_adapter.handle_interaction(payload)
        if bad_adapter._active_tasks: await asyncio.gather(*bad_adapter._active_tasks)
        await bad_adapter.shutdown()
        
        assert any("status is pending" in msg for msg in update_calls)
        update_calls.clear()

        # Test True Concurrency
        await asyncio.gather(adapter.handle_interaction(payload), adapter.handle_interaction(payload))
        if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
        await adapter.shutdown()

        assert len(update_calls) == 2
        # Because final_state is queried right before updating the UI, 
        # both calls will either say "successfully applied" or "status is busy" depending on the race.
        assert all("successfully applied" in msg or "status is busy" in msg or "status is applied" in msg for msg in update_calls)
        
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.users")
            assert cur.fetchone()[0] == 2


@pytest.mark.asyncio
async def test_api_lifespan_slack_transport(setup_db, auth_and_config):
    import undogate.api
    import os
    
    if "UNDOGATE_SLACK_APP_TOKEN" in os.environ:
        del os.environ["UNDOGATE_SLACK_APP_TOKEN"]
        
    async with undogate.api.lifespan(app):
        assert undogate.api._slack_transport_instance is None

@pytest.mark.asyncio
async def test_api_lifespan_slack_transport_exception_cleanup(monkeypatch, setup_db, auth_and_config):
    import undogate.api
    monkeypatch.setenv("UNDOGATE_SLACK_APP_TOKEN", "fake_token")
    
    def failing_factory(token):
        raise Exception("Failed to connect fake client")
        
    app.state.slack_client_factory = failing_factory
    
    async with undogate.api.lifespan(app):
        assert getattr(undogate.api, "_slack_transport_instance") is not None
        assert undogate.api._slack_transport_instance.client is None
        
    del app.state.slack_client_factory
