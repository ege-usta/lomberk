import asyncio
import os

import httpx
import psycopg
import pytest
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer

import lomberk.api
import lomberk.config
from lomberk.api import app, get_executor, get_policy_engine
from lomberk.ee.slack import SlackInteractionAdapter


@pytest.fixture(scope="module")
def postgres():
    postgres = PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine"))
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
    return urlunparse((parsed.scheme, f"lomberk_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn, runtime_dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
        cur.execute("DROP ROLE IF EXISTS lomberk_control")
        cur.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")

    from lomberk.capture.install import install_lomberk
    install_lomberk(dsn, control_role='lomberk_control', agent_role='mcp_agent')

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS public.users (id SERIAL PRIMARY KEY, data TEXT)")
        cur.execute("INSERT INTO public.users (data) VALUES ('val1')")
        cur.execute("SELECT lomberk.register_table('public', 'users', 'id', 'mcp_agent')")
        cur.execute("GRANT ALL ON SCHEMA public TO mcp_agent")
        cur.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO mcp_agent")
        cur.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO mcp_agent")

@pytest.fixture
def auth_and_config(monkeypatch, runtime_dsn, admin_dsn):
    monkeypatch.setenv("LOMBERK_AGENT_DSN", runtime_dsn)
    monkeypatch.setenv("LOMBERK_ADMIN_DSN", admin_dsn)
    monkeypatch.setenv("LOMBERK_API_KEY", "real_agent_key")
    monkeypatch.setenv("LOMBERK_ADMIN_KEY", "real_admin_key")

    old_api_key = lomberk.api._API_KEY
    old_admin_key = lomberk.api._ADMIN_KEY
    lomberk.api._API_KEY = "real_agent_key"
    lomberk.api._ADMIN_KEY = "real_admin_key"

    original_load = lomberk.config.load_config
    def mock_load(*a, **kw):
        cfg = original_load(*a, **kw)
        cfg.limits.max_rows_without_approval = 0
        cfg.protected_tables = ["public.users"]
        return cfg

    def override_get_executor():
        from lomberk.executor import LomberkExecutor
        return LomberkExecutor(admin_dsn, runtime_dsn)

    def override_get_policy_engine():
        from lomberk.policy import PolicyEngine
        return PolicyEngine(mock_load())

    app.dependency_overrides.clear()
    app.dependency_overrides[get_executor] = override_get_executor
    app.dependency_overrides[get_policy_engine] = override_get_policy_engine

    yield

    lomberk.api._API_KEY = old_api_key
    lomberk.api._ADMIN_KEY = old_admin_key
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
            _r = await acl.post(f"/v1/checkpoints/{pid}/approve", headers={"X-API-Key": "bad_key"})
            return {"status": "error"}

        bad_adapter = SlackInteractionAdapter({"U123"}, {"T1"}, resolve_target, bad_approve_cb, reject_cb, status_cb, update_cb)
        await bad_adapter.handle_interaction(payload)
        if bad_adapter._active_tasks: await asyncio.gather(*bad_adapter._active_tasks)
        await bad_adapter.shutdown()

        # Still pending after a failed click: the message (and its buttons) stay untouched.
        assert update_calls == []
        assert await status_cb(public_id) == "pending"

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
    import lomberk.api
    # Even if token is present, it shouldn't connect if NOT enabled
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "fake_token")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "fake_token")
    monkeypatch.delenv("LOMBERK_SLACK_ENABLED", raising=False)

    async with lomberk.api.lifespan(app):
        assert getattr(lomberk.api, "_slack_transport_instance", None) is None

@pytest.fixture(autouse=True)
def clean_app_state():
    import lomberk.api
    app = lomberk.api.app
    # Save original state if we want, but these are set per test
    yield
    for attr in ["slack_target_resolver", "slack_update_callback", "slack_client_factory", "_db_workers"]:
        if hasattr(app.state, attr):
            delattr(app.state, attr)

@pytest.mark.asyncio
async def test_api_lifespan_slack_transport_missing_dependencies(setup_db, auth_and_config, monkeypatch):
    import lomberk.api
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "fake")

    original_config = lomberk.config.load_config()
    original_config.slack.admin_allowlist = ["U1"]
    original_config.slack.team_allowlist = []
    monkeypatch.setattr(lomberk.api, "load_config", lambda: original_config)

    # 1. Missing team allowlist
    with pytest.raises(ValueError, match="team_allowlist is missing or empty"):
        async with lomberk.api.lifespan(app):
            pass

    original_config.slack.team_allowlist = ["T1"]

    # 2. Missing update callback
    async def fake_resolver(t, c, ts): return "cp_test"
    app.state.slack_target_resolver = fake_resolver
    with pytest.raises(ValueError, match="slack_update_callback dependency missing or not an async function"):
        async with lomberk.api.lifespan(app):
            pass

    # 3. Missing resolver
    del app.state.slack_target_resolver
    async def fake_update(c, ts, m): pass
    app.state.slack_update_callback = fake_update
    with pytest.raises(ValueError, match="slack_target_resolver dependency missing or not an async function"):
        async with lomberk.api.lifespan(app):
            pass

    # 4. Sync function bypass prevention
    app.state.slack_target_resolver = lambda t, c, ts: "cp_test"
    with pytest.raises(ValueError, match="slack_target_resolver dependency missing or not an async function"):
        async with lomberk.api.lifespan(app):
            pass

@pytest.mark.asyncio
async def test_api_lifespan_slack_transport_successful_fake(setup_db, auth_and_config, monkeypatch):
    import lomberk.api
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "fake")

    original_config = lomberk.config.load_config()
    original_config.slack.admin_allowlist = ["U1"]
    original_config.slack.team_allowlist = ["T1"]
    monkeypatch.setattr(lomberk.api, "load_config", lambda: original_config)

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

    async with lomberk.api.lifespan(app):
        adapter = lomberk.api._slack_transport_instance.business_adapter

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
    import lomberk.api
    from lomberk.config import load_config

    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "fake")

    original_config = load_config()
    original_config.slack.admin_allowlist = ["U123"]
    original_config.slack.team_allowlist = ["T1"]
    monkeypatch.setattr(lomberk.api, "load_config", lambda: original_config)



    def failing_factory(token):
        raise Exception("Failed to connect fake client")

    app.state.slack_client_factory = failing_factory

    async def dummy_cb(*args, **kwargs): pass
    app.state.slack_update_callback = dummy_cb
    app.state.slack_target_resolver = dummy_cb

    async with lomberk.api.lifespan(app):
        assert lomberk.api._slack_transport_instance is not None
        assert lomberk.api._slack_transport_instance.client is None

    del app.state.slack_client_factory

@pytest.mark.asyncio
async def test_api_lifespan_thread_cancellation(setup_db, auth_and_config, monkeypatch):
    import lomberk.api
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "fake")

    original_config = lomberk.config.load_config()
    original_config.slack.admin_allowlist = ["U_ADMIN"]
    original_config.slack.team_allowlist = ["T1"]
    monkeypatch.setattr(lomberk.api, "load_config", lambda: original_config)

    from unittest.mock import AsyncMock, MagicMock
    def mock_factory(token):
        m = MagicMock()
        m.connect = AsyncMock()
        m.socket_mode_request_listeners = []
        return m
    app.state.slack_client_factory = mock_factory

    app.state.slack_update_callback = AsyncMock()
    app.state.slack_target_resolver = AsyncMock(return_value="cp_mock")

    async with lomberk.api.lifespan(app):
        adapter = lomberk.api._slack_transport_instance.business_adapter
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

        monkeypatch.setattr(lomberk.api._executor_instance, "execute_pending", slow_execute)

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

        interaction_task = next(iter(adapter._active_tasks))

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


@pytest.mark.asyncio
async def test_api_lifespan_worker_drain_variants(setup_db, auth_and_config, monkeypatch, caplog):
    # Test worker completion within budget and exceeding budget on lifespan exit
    import logging

    import lomberk.api
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "fake")

    original_config = lomberk.config.load_config()
    original_config.slack.admin_allowlist = ["U1"]
    original_config.slack.team_allowlist = ["T1"]
    monkeypatch.setattr(lomberk.api, "load_config", lambda: original_config)

    from unittest.mock import AsyncMock, MagicMock
    app.state.slack_target_resolver = AsyncMock(return_value="cp_test")
    app.state.slack_update_callback = AsyncMock()
    app.state.slack_client_factory = lambda token: MagicMock(connect=AsyncMock(), close=AsyncMock(), socket_mode_request_listeners=[])

    # Variant 1: Finishes within budget
    with caplog.at_level(logging.INFO, logger="lomberk.api"):
        async with lomberk.api.lifespan(app):
            # inject a fake worker
            async def fake_worker(): await asyncio.sleep(0.05)
            t = asyncio.create_task(fake_worker())
            app.state._db_workers.add(t)
            t.add_done_callback(app.state._db_workers.discard)

        assert "Draining 1 outstanding DB workers" in caplog.text
        assert "Shutdown timeout" not in caplog.text
        assert len(app.state._db_workers) == 0

    caplog.clear()

    # Variant 2: Exceeds budget
    with caplog.at_level(logging.INFO, logger="lomberk.api"):
        async with lomberk.api.lifespan(app):
            # inject a fake worker
            async def slow_worker(): await asyncio.sleep(6.0) # > 5s
            t = asyncio.create_task(slow_worker())
            app.state._db_workers.add(t)
            t.add_done_callback(app.state._db_workers.discard)

            # mock wait to be faster in test
            original_wait = asyncio.wait
            async def fast_wait(ws, timeout=5.0):
                return await original_wait(ws, timeout=0.1)
            monkeypatch.setattr(asyncio, "wait", fast_wait)

        assert "Draining 1 outstanding DB workers" in caplog.text
        assert "Shutdown timeout: 1 DB workers remain outstanding/unknown." in caplog.text

        # Cleanup
        t.cancel()
        try: await t
        except asyncio.CancelledError: pass

@pytest.mark.asyncio
async def test_api_worker_tracking_capacity_and_exception(setup_db, auth_and_config, monkeypatch, caplog):

    import lomberk.api
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "fake")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "fake")

    original_config = lomberk.config.load_config()
    original_config.slack.admin_allowlist = ["U1"]
    original_config.slack.team_allowlist = ["T1"]
    monkeypatch.setattr(lomberk.api, "load_config", lambda: original_config)

    from unittest.mock import AsyncMock, MagicMock
    app.state.slack_target_resolver = AsyncMock(return_value="cp_test")
    app.state.slack_update_callback = AsyncMock()
    app.state.slack_client_factory = lambda token: MagicMock(connect=AsyncMock(), close=AsyncMock(), socket_mode_request_listeners=[])

    async with lomberk.api.lifespan(app):
        import threading

        from lomberk.ee.slack import TaskCapacityExceededError

        release_event = threading.Event()

        def hanging_execute(*args):
            release_event.wait(timeout=5.0)
            if args[0] == "cp_new":
                return MagicMock(status="applied")
            raise ValueError("Test detached exception")

        monkeypatch.setattr(lomberk.api._executor_instance, "execute_pending", hanging_execute)

        adapter = lomberk.api._slack_transport_instance.business_adapter

        tasks = []
        try:
            # Start 50 workers
            for i in range(50):
                tasks.append(asyncio.create_task(adapter.approve_callback(f"cp_{i}")))

            # Allow event loop to schedule them
            await asyncio.sleep(0.05)

            # Assert capacity is strictly full
            assert len(app.state._db_workers) == 50

            with pytest.raises(TaskCapacityExceededError):
                await adapter.approve_callback("cp_50")

            with pytest.raises(TaskCapacityExceededError):
                await adapter.status_callback("cp_50")

            # Cancel callers
            for t in tasks: t.cancel()
            await asyncio.sleep(0.01) # let cancellation propagate

            # Registry MUST still be full
            assert len(app.state._db_workers) == 50

            with pytest.raises(TaskCapacityExceededError):
                await adapter.approve_callback("cp_50")

        finally:
            # Release workers inside finally
            release_event.set()

            # Wait for internal worker completion
            for _ in range(50):
                if len(app.state._db_workers) == 0: break
                await asyncio.sleep(0.01)

            for t in tasks:
                try: await t
                except asyncio.CancelledError: pass

        # Registry must be completely zeroed
        assert len(app.state._db_workers) == 0

        # Test subsequent working request
        res = await adapter.approve_callback("cp_new")
        assert res == {"status": "applied"}

        # Verify exception from detached task was cleanly consumed
        assert "Background DB worker failed: ValueError" in caplog.text


@pytest.mark.asyncio
async def test_offline_pilot_e2e_flow(dsn, setup_db, auth_and_config, monkeypatch, caplog):
    # -------------------------------------------------------------------
    # Offline Pilot Runbook Test
    # -------------------------------------------------------------------
    import asyncio
    import os
    import uuid
    from unittest.mock import AsyncMock, MagicMock

    from fastapi.testclient import TestClient
    from offline_pilot import InMemoryBindingStore, OfflinePublisher, OfflineUpdater, PublishOutcomeUnknown
    from slack_sdk.socket_mode.request import SocketModeRequest

    import lomberk.api
    from lomberk.api import app

    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "fake_app_token")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "fake_bot_token")

    config = lomberk.config.load_config()
    config.slack.admin_allowlist = ["U_ADMIN"]
    config.slack.team_allowlist = ["T_VALID"]
    # Force real policy to block this table
    config.protected_tables = ["public.test_e2e"]
    monkeypatch.setattr(lomberk.api, "load_config", lambda: config)

    from lomberk.policy import PolicyEngine
    app.dependency_overrides[lomberk.api.get_policy_engine] = lambda: PolicyEngine(config)

    binding_store = InMemoryBindingStore()
    publisher = OfflinePublisher(binding_store)
    updater = OfflineUpdater()

    app.state.slack_target_resolver = binding_store.resolve
    app.state.slack_update_callback = updater.update_message

    fake_socket_client = MagicMock()
    fake_socket_client.connect = AsyncMock()
    fake_socket_client.close = AsyncMock()
    fake_socket_client.send_socket_mode_response = AsyncMock()
    fake_socket_client.socket_mode_request_listeners = []
    app.state.slack_client_factory = lambda token: fake_socket_client

    import psycopg
    admin_dsn = os.environ.get("LOMBERK_ADMIN_DSN")

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS public.test_e2e (id int PRIMARY KEY);")
        cur.execute("SELECT lomberk.register_table('public', 'test_e2e', 'id', 'mcp_agent');")
        # Do NOT grant to lomberk_control, only mcp_agent needs DML on business table
        cur.execute("GRANT ALL PRIVILEGES ON public.test_e2e TO mcp_agent;")
        conn.commit()

    client = TestClient(app)

    async def create_and_publish_checkpoint():
        req = {
            "operation_id": str(uuid.uuid4()),
            "sql": "INSERT INTO public.test_e2e VALUES (1);",
            "agent_label": "tester"
        }
        res = client.post("/v1/execute", json=req, headers={"X-API-Key": "real_agent_key"})
        assert res.status_code == 200, res.json()
        assert res.json()["results"][0]["status"] == "approval_required", res.json()
        pid = res.json()["results"][0]["checkpoint_id"]

        # Verify completely pending and empty before action
        with psycopg.connect(admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM lomberk.checkpoints WHERE public_id = %s", (pid,))
                assert cur.fetchone()[0] == "pending"
                cur.execute("SELECT count(*) FROM lomberk.row_changes WHERE checkpoint_id = (SELECT id FROM lomberk.checkpoints WHERE public_id = %s)", (pid,))
                assert cur.fetchone()[0] == 0
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM public.test_e2e")
                assert cur.fetchone()[0] == 0

        # Publish
        ts = await publisher.publish_checkpoint("T_VALID", "C_VALID", pid)
        return pid, ts

    async with lomberk.api.lifespan(app):
        transport = lomberk.api._slack_transport_instance
        adapter = transport.business_adapter

        async def deliver(payload, envelope_id):
            request = SocketModeRequest(type="interactive", envelope_id=envelope_id,
                                        payload={"type": "block_actions", **payload})
            for listener in fake_socket_client.socket_mode_request_listeners:
                await listener(fake_socket_client, request)
            tasks = tuple(adapter._active_tasks)
            if tasks:
                await asyncio.wait_for(asyncio.gather(*tasks), 5)


        # ---------------------------------------------------------
        # Case 1: Normal Approve
        # ---------------------------------------------------------
        pid1, ts1 = await create_and_publish_checkpoint()
        req1 = {
            "team": {"id": "T_VALID"},
            "user": {"id": "U_ADMIN"},
            "container": {"channel_id": "C_VALID", "message_ts": ts1},
            "actions": [{"action_id": "approve_button", "value": pid1}],
        }
        await deliver(req1, "envelope-1")
        # Wait for update
        update = await updater.wait_for_update(timeout=2.0)
        assert update is not None
        assert "successfully applied" in update[2]

        with psycopg.connect(admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM lomberk.checkpoints WHERE public_id = %s", (pid1,))
                assert cur.fetchone()[0] == "applied"
                cur.execute("SELECT count(*) FROM lomberk.row_changes WHERE checkpoint_id = (SELECT id FROM lomberk.checkpoints WHERE public_id = %s)", (pid1,))
                assert cur.fetchone()[0] == 1
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM public.test_e2e")
                assert cur.fetchone()[0] == 1

        # ---------------------------------------------------------
        # Case 2: Duplicate
        # ---------------------------------------------------------
        # Duplicate A: Exact same envelope
        before_updates = len(updater.updates)
        before_acks = fake_socket_client.send_socket_mode_response.await_count
        await deliver(req1, "envelope-1")
        assert len(updater.updates) == before_updates
        assert fake_socket_client.send_socket_mode_response.await_count == before_acks + 1

        # Duplicate B: Different envelope, same button value
        req1b = {
            "team": {"id": "T_VALID"},
            "user": {"id": "U_ADMIN"},
            "container": {"channel_id": "C_VALID", "message_ts": ts1}, # TS doesn't matter much for duplicate if public_id is same
            "actions": [{"action_id": "approve_button", "value": pid1}],
        }
        await deliver(req1b, "envelope-2")
        update_dup2 = await updater.wait_for_update(timeout=2.0)
        assert update_dup2 is not None

        # Verify absolutely no new row or capture
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM public.test_e2e")
                assert cur.fetchone()[0] == 1
        with psycopg.connect(admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM lomberk.row_changes WHERE checkpoint_id = (SELECT id FROM lomberk.checkpoints WHERE public_id = %s)", (pid1,))
                assert cur.fetchone()[0] == 1

        # Cleanup for next cases
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM public.test_e2e")
                conn.commit()

        # ---------------------------------------------------------
        # Case 3: Reject
        # ---------------------------------------------------------
        pid2, ts2 = await create_and_publish_checkpoint()
        req2 = {
            "team": {"id": "T_VALID"},
            "user": {"id": "U_ADMIN"},
            "container": {"channel_id": "C_VALID", "message_ts": ts2},
            "actions": [{"action_id": "reject_button", "value": pid2}],
        }
        await deliver(req2, "envelope-reject")
        update = await updater.wait_for_update(timeout=2.0)
        assert update is not None
        assert "rejected" in update[2]

        with psycopg.connect(admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM lomberk.checkpoints WHERE public_id = %s", (pid2,))
                assert cur.fetchone()[0] == "rejected"
                cur.execute("SELECT count(*) FROM lomberk.row_changes WHERE checkpoint_id = (SELECT id FROM lomberk.checkpoints WHERE public_id = %s)", (pid2,))
                assert cur.fetchone()[0] == 0
        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM public.test_e2e")
                assert cur.fetchone()[0] == 0

        # ---------------------------------------------------------
        # Case 4: Invalid target / unauthorized
        # ---------------------------------------------------------
        req3 = {
            "team": {"id": "T_VALID"},
            "user": {"id": "U_ADMIN"},
            "container": {"channel_id": "C_VALID", "message_ts": "TS_UNKNOWN"},
            "actions": [{"action_id": "approve_button", "value": "cp_unknown"}],
        }
        await deliver(req3, "envelope-invalid")
        update = await updater.wait_for_update(timeout=0.5)
        assert update is None, "Should not update UI for unknown binding"

        # ---------------------------------------------------------
        # Case 5: Binding lost (simulate restart)
        # ---------------------------------------------------------
        pid4, ts4 = await create_and_publish_checkpoint()
        binding_store.drop("T_VALID", "C_VALID", ts4) # Simulate memory clear on restart
        req4 = {
            "team": {"id": "T_VALID"},
            "user": {"id": "U_ADMIN"},
            "container": {"channel_id": "C_VALID", "message_ts": ts4},
            "actions": [{"action_id": "approve_button", "value": pid4}],
        }
        await deliver(req4, "envelope-lost")
        update = await updater.wait_for_update(timeout=0.5)
        assert update is None, "Should fail closed, no UI update, no execution"

        with psycopg.connect(admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT status FROM lomberk.checkpoints WHERE public_id = %s", (pid4,))
                assert cur.fetchone()[0] == "pending", "Must remain pending (unmutated)"

        # ---------------------------------------------------------
        # Case 6: Publisher loss (No binding formed)
        # ---------------------------------------------------------
        sends_before = publisher.message_counter
        bindings_before = dict(binding_store.store)
        with pytest.raises(PublishOutcomeUnknown):
            await publisher.publish_checkpoint("T_VALID", "C_VALID", pid4, lossy=True)
        assert publisher.message_counter == sends_before + 1
        assert binding_store.store == bindings_before

        # Independent authorization/target mutations; each must preserve DB state.
        import copy
        pid5, ts5 = await create_and_publish_checkpoint()
        baseline = {"team": {"id": "T_VALID"}, "user": {"id": "U_ADMIN"},
                    "container": {"channel_id": "C_VALID", "message_ts": ts5},
                    "actions": [{"action_id": "approve_button", "value": pid5}]}
        for index, (section, field, value) in enumerate([
            ("team", "id", "T_OTHER"), ("user", "id", "U_OTHER"),
            ("container", "channel_id", "C_OTHER"),
            ("container", "message_ts", "TS_OTHER"),
            ("actions", "value", pid4),
        ]):
            payload = copy.deepcopy(baseline)
            target = payload[section][0] if section == "actions" else payload[section]
            target[field] = value
            count_before = len(updater.updates)
            await deliver(payload, f"unauthorized-{index}")
            assert len(updater.updates) == count_before
            with psycopg.connect(admin_dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT status FROM lomberk.checkpoints WHERE public_id = %s", (pid5,))
                assert cur.fetchone()[0] == "pending"
                cur.execute("SELECT count(*) FROM lomberk.row_changes WHERE checkpoint_id = (SELECT id FROM lomberk.checkpoints WHERE public_id = %s)", (pid5,))
                assert cur.fetchone()[0] == 0
            with psycopg.connect(dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM public.test_e2e")
                assert cur.fetchone()[0] == 0
