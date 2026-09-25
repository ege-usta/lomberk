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
async def test_api_lifespan_slack_transport_disabled(setup_db, auth_and_config, monkeypatch):
    import undogate.api
    # Even if token is present, it shouldn't connect if NOT enabled
    monkeypatch.setenv("UNDOGATE_SLACK_APP_TOKEN", "fake_token")
    monkeypatch.setenv("UNDOGATE_SLACK_BOT_TOKEN", "fake_token")
    monkeypatch.delenv("UNDOGATE_SLACK_ENABLED", raising=False)
    
    async with undogate.api.lifespan(app):
        assert getattr(undogate.api, "_slack_transport_instance", None) is None

@pytest.fixture(autouse=True)
def clean_app_state():
    import undogate.api
    app = undogate.api.app
    # Save original state if we want, but these are set per test
    yield
    for attr in ["slack_target_resolver", "slack_update_callback", "slack_client_factory", "_db_workers"]:
        if hasattr(app.state, attr):
            delattr(app.state, attr)

@pytest.mark.asyncio
async def test_api_lifespan_slack_transport_missing_dependencies(setup_db, auth_and_config, monkeypatch):
    import undogate.api
    monkeypatch.setenv("UNDOGATE_SLACK_ENABLED", "true")
    monkeypatch.setenv("UNDOGATE_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("UNDOGATE_SLACK_BOT_TOKEN", "fake")
    
    original_config = undogate.config.load_config()
    original_config.slack.admin_allowlist = ["U1"]
    original_config.slack.team_allowlist = []
    monkeypatch.setattr(undogate.api, "load_config", lambda: original_config)
    
    # 1. Missing team allowlist
    with pytest.raises(ValueError, match="team_allowlist is missing or empty"):
        async with undogate.api.lifespan(app):
            pass
            
    original_config.slack.team_allowlist = ["T1"]
    
    # 2. Missing update callback
    app.state.slack_target_resolver = lambda t, c, ts: "cp_test"
    with pytest.raises(ValueError, match="slack_update_callback dependency missing"):
        async with undogate.api.lifespan(app):
            pass
            
    # 3. Missing resolver
    del app.state.slack_target_resolver
    app.state.slack_update_callback = lambda c, ts, m: None
    with pytest.raises(ValueError, match="slack_target_resolver dependency missing"):
        async with undogate.api.lifespan(app):
            pass

@pytest.mark.asyncio
async def test_api_lifespan_slack_transport_successful_fake(setup_db, auth_and_config, monkeypatch):
    import undogate.api
    monkeypatch.setenv("UNDOGATE_SLACK_ENABLED", "true")
    monkeypatch.setenv("UNDOGATE_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("UNDOGATE_SLACK_BOT_TOKEN", "fake")
    
    original_config = undogate.config.load_config()
    original_config.slack.admin_allowlist = ["U1"]
    original_config.slack.team_allowlist = ["T1"]
    monkeypatch.setattr(undogate.api, "load_config", lambda: original_config)
    
    from unittest.mock import AsyncMock, MagicMock
    
    resolver_calls = []
    async def mock_resolver(t, c, ts):
        resolver_calls.append((t, c, ts))
        if c == "C_MISMATCH": return "cp_other"
        return "cp_test"
    app.state.slack_target_resolver = mock_resolver
    
    update_calls = []
    async def mock_update(c, ts, m):
        update_calls.append((c, ts, m))
    app.state.slack_update_callback = mock_update
    
    def fake_factory(token):
        m = MagicMock()
        m.connect = AsyncMock()
        m.close = AsyncMock()
        m.socket_mode_request_listeners = []
        return m
        
    app.state.slack_client_factory = fake_factory
    
    # Mock executor to observe business calls
    approve_called = False
    async def mock_approve(pid):
        nonlocal approve_called
        approve_called = True
        return MagicMock(status="applied")
    
    async with undogate.api.lifespan(app):
        adapter = undogate.api._slack_transport_instance.business_adapter
        
        # Override the bound callback for this test to avoid real DB execution
        # (Alternatively, we could let it hit the real DB if setup_db provides one)
        # We'll just override the adapter's approve_callback to intercept it.
        adapter.approve_callback = mock_approve
        
        # We also need to override status_callback so it doesn't query the real DB
        # if we aren't creating the checkpoint.
        adapter.status_callback = AsyncMock(return_value="applied")
        
        payload_match = {
            "team": {"id": "T1"}, "user": {"id": "U1"},
            "container": {"channel_id": "C1", "message_ts": "123"},
            "actions": [{"action_id": "approve_button", "value": "cp_test"}]
        }
        
        await adapter.handle_interaction(payload_match)
        # Wait for internal processing to finish
        import time
        for _ in range(50):
            if len(adapter._active_tasks) == 0: break
            await asyncio.sleep(0.01)
            
        assert resolver_calls == [("T1", "C1", "123")]
        assert approve_called is True
        adapter.status_callback.assert_called_once_with("cp_test")
        assert len(update_calls) == 1
        assert update_calls[0][0] == "C1"
        assert "successfully applied" in update_calls[0][2]
        
        # Test Mismatch Scenario
        resolver_calls.clear()
        update_calls.clear()
        approve_called = False
        adapter.status_callback.reset_mock()
        
        payload_mismatch = {
            "team": {"id": "T1"}, "user": {"id": "U1"},
            "container": {"channel_id": "C_MISMATCH", "message_ts": "999"},
            "actions": [{"action_id": "approve_button", "value": "cp_test"}]
        }
        await adapter.handle_interaction(payload_mismatch)
        for _ in range(50):
            if len(adapter._active_tasks) == 0: break
            await asyncio.sleep(0.01)
            
        assert resolver_calls == [("T1", "C_MISMATCH", "999")]
        assert approve_called is False  # Mutation did not happen
        adapter.status_callback.assert_not_called()
        assert len(update_calls) == 0  # No UI update on mismatch

@pytest.mark.asyncio
async def test_api_lifespan_slack_transport_exception_cleanup(setup_db, auth_and_config, monkeypatch):
    import undogate.api
    from undogate.config import load_config
    
    monkeypatch.setenv("UNDOGATE_SLACK_ENABLED", "true")
    monkeypatch.setenv("UNDOGATE_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("UNDOGATE_SLACK_BOT_TOKEN", "fake")
    
    import undogate.api
    original_config = load_config()
    original_config.slack.admin_allowlist = ["U123"]
    original_config.slack.team_allowlist = ["T1"]
    monkeypatch.setattr(undogate.api, "load_config", lambda: original_config)
    

    
    def failing_factory(token):
        raise Exception("Failed to connect fake client")
        
    app.state.slack_client_factory = failing_factory
    
    from unittest.mock import AsyncMock
    async def dummy_cb(*args, **kwargs): pass
    app.state.slack_update_callback = dummy_cb
    app.state.slack_target_resolver = dummy_cb
    
    async with undogate.api.lifespan(app):
        assert getattr(undogate.api, "_slack_transport_instance") is not None
        assert undogate.api._slack_transport_instance.client is None
        
    del app.state.slack_client_factory

@pytest.mark.asyncio
async def test_api_lifespan_thread_cancellation(setup_db, auth_and_config, monkeypatch):
    import undogate.api
    monkeypatch.setenv("UNDOGATE_SLACK_ENABLED", "true")
    monkeypatch.setenv("UNDOGATE_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("UNDOGATE_SLACK_BOT_TOKEN", "fake")
    
    original_config = undogate.config.load_config()
    original_config.slack.admin_allowlist = ["U_ADMIN"]
    original_config.slack.team_allowlist = ["T1"]
    monkeypatch.setattr(undogate.api, "load_config", lambda: original_config)
    
    from unittest.mock import AsyncMock, MagicMock
    def mock_factory(token):
        m = MagicMock()
        m.connect = AsyncMock()
        m.socket_mode_request_listeners = []
        return m
    app.state.slack_client_factory = mock_factory
    
    app.state.slack_update_callback = AsyncMock()
    app.state.slack_target_resolver = AsyncMock(return_value="cp_mock")
    
    async with undogate.api.lifespan(app):
        adapter = undogate.api._slack_transport_instance.business_adapter
        adapter.shutdown_timeout = 0.05  # Force very short wait
        
        import threading
        thread_started = threading.Event()
        thread_release = threading.Event()
        thread_finished = threading.Event()
        
        def slow_execute(*args):
            thread_started.set()
            # Wait for main test to tell us to proceed
            if not thread_release.wait(timeout=5.0):
                return MagicMock(status="failed_timeout")
            thread_finished.set()
            return MagicMock(status="applied")
            
        monkeypatch.setattr(undogate.api._executor_instance, "execute_pending", slow_execute)
        
        async def resolve_target(*args):
            return "cp_mock"
        adapter.target_resolver = resolve_target
        
        payload = {
            "team": {"id": "T1"}, "user": {"id": "U_ADMIN"},
            "container": {"channel_id": "C1", "message_ts": "123"},
            "actions": [{"action_id": "approve_button", "value": "cp_mock"}]
        }
        
        # Intercept the approve_callback to prove Cancellation happens
        cancellation_observed = False
        original_approve = adapter.approve_callback
        async def tracking_approve(*args, **kwargs):
            nonlocal cancellation_observed
            try:
                return await original_approve(*args, **kwargs)
            except asyncio.CancelledError:
                cancellation_observed = True
                raise
        adapter.approve_callback = tracking_approve
        
        await adapter.handle_interaction(payload)
        
        import time
        start_wait = time.time()
        while not thread_started.is_set():
            if time.time() - start_wait > 1.0:
                pytest.fail("Thread never started")
            await asyncio.sleep(0.01)
            
        interaction_task = list(adapter._active_tasks)[0]
        
        await adapter.shutdown()
        
        # Wait for the event loop to actually process the cancellation
        try:
            await interaction_task
        except asyncio.CancelledError:
            pass
            
        # Verification 1: Coroutine was cancelled
        assert interaction_task.cancelled() or cancellation_observed
        
        # Verification 2: Thread is still waiting (not killed!)
        assert not thread_finished.is_set()
        
        # Release the thread
        thread_release.set()
        
        # Verification 3: Thread can finish its work despite task cancellation
        start_wait = time.time()
        while not thread_finished.is_set():
            if time.time() - start_wait > 1.0:
                pytest.fail("Thread was killed upon task cancellation!")
            await asyncio.sleep(0.01)

