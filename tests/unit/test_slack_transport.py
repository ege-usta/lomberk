import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from slack_sdk.socket_mode.request import SocketModeRequest
from rowback.ee.slack_transport import SlackTransport
from rowback.ee.slack import SlackInteractionAdapter, TaskCapacityExceededError

@pytest.fixture
def mock_adapter():
    adapter = MagicMock(spec=SlackInteractionAdapter)
    adapter.handle_interaction = AsyncMock()
    adapter.shutdown = AsyncMock()
    return adapter

@pytest.fixture
def mock_client_factory():
    def factory(token):
        client = MagicMock()
        client.connect = AsyncMock()
        client.close = AsyncMock()
        client.send_socket_mode_response = AsyncMock()
        client.socket_mode_request_listeners = []
        return client
    return factory

@pytest.mark.asyncio
async def test_slack_transport_disabled(mock_adapter, mock_client_factory):
    transport = SlackTransport("app-token", mock_adapter, mock_client_factory, enabled=False)
    await transport.connect()
    assert transport.client is None
    await transport.disconnect()

@pytest.mark.asyncio
async def test_slack_transport_ignores_non_interactive(mock_adapter, mock_client_factory):
    transport = SlackTransport("app-token", mock_adapter, mock_client_factory, enabled=True)
    req = SocketModeRequest(type="events_api", envelope_id="env_1", payload={})
    
    mock_client = mock_client_factory("token")
    await transport._process_request(mock_client, req)
    
    mock_client.send_socket_mode_response.assert_called_once()
    mock_adapter.handle_interaction.assert_not_called()
    assert "env_1" not in transport._processed_envelopes

@pytest.mark.asyncio
async def test_slack_transport_ack_first_failure_retry(mock_adapter, mock_client_factory):
    # If ACK fails AFTER admission, the business logic still runs. 
    # If it retries, it hits the ACCEPTED state and ACKs without business logic.
    transport = SlackTransport("app-token", mock_adapter, mock_client_factory, enabled=True)
    payload = {"type": "block_actions", "user": {"id": "U123"}}
    req = SocketModeRequest(type="interactive", envelope_id="env_ack_fail", payload=payload)
    
    mock_client = mock_client_factory("token")
    mock_client.send_socket_mode_response.side_effect = [Exception("Network down"), None]
    
    await transport._process_request(mock_client, req)
    
    mock_adapter.handle_interaction.assert_called_once()
    assert transport._processed_envelopes["env_ack_fail"][1] == "ACCEPTED"
    
    # Retry arrives
    await transport._process_request(mock_client, req)
    
    # Business logic is STILL 1
    mock_adapter.handle_interaction.assert_called_once()
    assert mock_client.send_socket_mode_response.call_count == 2

@pytest.mark.asyncio
async def test_slack_transport_capacity_full_retry(mock_adapter, mock_client_factory):
    # If capacity is full, do NOT ACK, and let it retry.
    transport = SlackTransport("app-token", mock_adapter, mock_client_factory, enabled=True)
    payload = {"type": "block_actions"}
    req = SocketModeRequest(type="interactive", envelope_id="env_cap", payload=payload)
    
    mock_client = mock_client_factory("token")
    
    # First call: capacity full
    mock_adapter.handle_interaction.side_effect = [TaskCapacityExceededError("Busy"), None]
    await transport._process_request(mock_client, req)
    
    # ACK is NOT called
    mock_client.send_socket_mode_response.assert_not_called()
    # envelope is NOT stored as accepted
    assert "env_cap" not in transport._processed_envelopes
    
    # Second call (retry): capacity open
    await transport._process_request(mock_client, req)
    
    mock_client.send_socket_mode_response.assert_called_once()
    assert transport._processed_envelopes["env_cap"][1] == "ACCEPTED"

@pytest.mark.asyncio
async def test_slack_transport_concurrent_same_envelope(mock_adapter, mock_client_factory):
    transport = SlackTransport("app-token", mock_adapter, mock_client_factory, enabled=True)
    payload = {"type": "block_actions"}
    req = SocketModeRequest(type="interactive", envelope_id="env_conc", payload=payload)
    mock_client = mock_client_factory("token")
    
    # To simulate concurrency, we make adapter.handle_interaction yield
    async def slow_handle(*args):
        await asyncio.sleep(0.02)
    mock_adapter.handle_interaction.side_effect = slow_handle
    
    t1 = asyncio.create_task(transport._process_request(mock_client, req))
    await asyncio.sleep(0.005) # Let t1 mark INFLIGHT
    
    # Start t2 while t1 is INFLIGHT
    t2 = asyncio.create_task(transport._process_request(mock_client, req))
    
    await asyncio.gather(t1, t2)
    
    # Business logic only executed ONCE because t2 was dropped immediately
    mock_adapter.handle_interaction.assert_called_once()
    # ACK only sent ONCE (by t1, after admission)
    mock_client.send_socket_mode_response.assert_called_once()

@pytest.mark.asyncio
async def test_slack_transport_startup_failure_cleanup(mock_adapter, mock_client_factory):
    def failing_factory(token):
        c = mock_client_factory(token)
        c.connect.side_effect = Exception("Auth failed")
        return c
        
    transport = SlackTransport("app-token", mock_adapter, failing_factory, enabled=True)
    
    with pytest.raises(Exception, match="Auth failed"):
        await transport.connect()
        
    # Client should be closed and set to None
    assert transport.client is None

@pytest.mark.asyncio
async def test_slack_transport_shutdown_failure(mock_adapter, mock_client_factory):
    transport = SlackTransport("app-token", mock_adapter, mock_client_factory, enabled=True)
    await transport.connect()
    
    mock_adapter.shutdown.side_effect = Exception("Adapter shutdown crash")
    client = transport.client
    
    await transport.disconnect()
    
    # client.close() MUST still be called despite adapter crash
    client.close.assert_called_once()
    assert transport.client is None

@pytest.mark.asyncio
async def test_slack_transport_dedup_eviction(mock_adapter, mock_client_factory):
    transport = SlackTransport("app-token", mock_adapter, mock_client_factory, enabled=True, max_dedup_size=2)
    mock_client = mock_client_factory("token")
    
    await transport._process_request(mock_client, SocketModeRequest(type="interactive", envelope_id="e1", payload={"type": "block_actions"}))
    await transport._process_request(mock_client, SocketModeRequest(type="interactive", envelope_id="e2", payload={"type": "block_actions"}))
    
    assert len(transport._processed_envelopes) == 2
    
    # Max size is 2, third will evict e1
    await transport._process_request(mock_client, SocketModeRequest(type="interactive", envelope_id="e3", payload={"type": "block_actions"}))
    
    assert len(transport._processed_envelopes) == 2
    assert "e1" not in transport._processed_envelopes
    assert "e2" in transport._processed_envelopes
    assert "e3" in transport._processed_envelopes
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from slack_sdk.socket_mode.request import SocketModeRequest
from rowback.ee.slack_transport import SlackTransport
from rowback.ee.slack import SlackInteractionAdapter

@pytest.fixture
def mock_adapter():
    adapter = MagicMock(spec=SlackInteractionAdapter)
    adapter.handle_interaction = AsyncMock()
    return adapter

@pytest.mark.asyncio
async def test_dedup_capacity_overwritten(mock_adapter, mock_client_factory):
    transport = SlackTransport("token", mock_adapter, mock_client_factory, enabled=True, max_dedup_size=1)
    mock_client = mock_client_factory("token")
    req_a = SocketModeRequest(type="interactive", envelope_id="A", payload={"type": "block_actions"})
    
    await transport._process_request(mock_client, req_a)
    assert mock_adapter.handle_interaction.call_count == 1
    
    # Send A again immediately
    await transport._process_request(mock_client, req_a)
    assert mock_adapter.handle_interaction.call_count == 1

@pytest.mark.asyncio
async def test_inflight_evicted_on_capacity(mock_adapter, mock_client_factory):
    transport = SlackTransport("token", mock_adapter, mock_client_factory, enabled=True, max_dedup_size=1)
    mock_client = mock_client_factory("token")
    
    ev = asyncio.Event()
    async def slow_handle(*a):
        await ev.wait()
    mock_adapter.handle_interaction.side_effect = slow_handle
    
    req_a = SocketModeRequest(type="interactive", envelope_id="A", payload={"type": "block_actions"})
    t1 = asyncio.create_task(transport._process_request(mock_client, req_a))
    await asyncio.sleep(0.01) # Let A become INFLIGHT
    
    req_b = SocketModeRequest(type="interactive", envelope_id="B", payload={"type": "block_actions"})
    await transport._process_request(mock_client, req_b)
    
    ev.set()
    await t1
    
    assert len(transport._processed_envelopes) <= 1
    
@pytest.mark.asyncio
async def test_inflight_evicted_on_ttl(mock_adapter, mock_client_factory, monkeypatch):
    import rowback.ee.slack_transport
    
    transport = SlackTransport("token", mock_adapter, mock_client_factory, enabled=True, dedup_ttl_seconds=1)
    mock_client = mock_client_factory("token")
    
    ev = asyncio.Event()
    async def slow_handle(*a):
        await ev.wait()
    mock_adapter.handle_interaction.side_effect = slow_handle
    
    # Mock the time function specifically where it's used instead of loop.time
    # Wait, the code uses `now = asyncio.get_event_loop().time()`.
    # Let's just mock `asyncio.get_event_loop` to return a mock loop with a custom `time` method?
    # Better: just set the internal dictionary timestamps manually for the test!
    
    req_a = SocketModeRequest(type="interactive", envelope_id="A", payload={"type": "block_actions"})
    
    t1 = asyncio.create_task(transport._process_request(mock_client, req_a))
    await asyncio.sleep(0.01) # Let A become INFLIGHT
    
    # Manually adjust the timestamp of A to simulate time passing
    transport._processed_envelopes["A"] = (0.0, "INFLIGHT")
    
    # Now send A again. The new request gets a real `now` (e.g. 1234567.89).
    # Since 1234567.89 - 0.0 > 1 (ttl), A would be evicted IF the code didn't protect INFLIGHT.
    
    t2 = asyncio.create_task(transport._process_request(mock_client, req_a))
    await asyncio.sleep(0.01)
    
    ev.set()
    await t1
    await t2
    
    assert mock_adapter.handle_interaction.call_count == 1

@pytest.mark.asyncio
async def test_slack_transport_connect_timeout_cleanup(mock_adapter, mock_client_factory):
    def hanging_factory(token):
        c = mock_client_factory(token)
        async def hang():
            await asyncio.sleep(1.0)
        c.connect.side_effect = hang
        return c
        
    transport = SlackTransport("app-token", mock_adapter, hanging_factory, enabled=True)
    transport.connect_timeout = 0.05
    
    with pytest.raises(TimeoutError):
        await transport.connect()
        
    assert transport.client is None

@pytest.mark.asyncio
async def test_slack_transport_connect_cancelled_cleanup(mock_adapter, mock_client_factory):
    def hanging_factory(token):
        c = mock_client_factory(token)
        async def hang():
            await asyncio.sleep(1.0)
        c.connect.side_effect = hang
        # We need to capture the client to assert it's closed
        hanging_factory.last_client = c
        return c
        
    transport = SlackTransport("app-token", mock_adapter, hanging_factory, enabled=True)
    
    t = asyncio.create_task(transport.connect())
    await asyncio.sleep(0.05)
    t.cancel()
    
    with pytest.raises(asyncio.CancelledError):
        await t
        
    # Verify cleanup happened despite CancelledError
    assert transport.client is None
    # Verify close was called
    client = hanging_factory.last_client
    client.close.assert_called_once()

@pytest.mark.asyncio
async def test_slack_transport_cleanup_ownership_and_drain(mock_adapter, mock_client_factory):
    # This test verifies that if connect is cancelled, it spawns a cleanup task.
    # If the shield is cancelled (double cancellation), the cleanup task survives
    # and is correctly drained by disconnect().
    close_started = asyncio.Event()
    close_finish = asyncio.Event()
    
    def hanging_factory(token):
        c = mock_client_factory(token)
        async def hang():
            await asyncio.sleep(1.0)
        c.connect.side_effect = hang
        
        async def slow_close():
            close_started.set()
            await close_finish.wait()
        c.close = slow_close
        return c
        
    transport = SlackTransport("app-token", mock_adapter, hanging_factory, enabled=True)
    
    t = asyncio.create_task(transport.connect())
    await asyncio.sleep(0.01) # Let connect start
    
    # Cancel connect (1st cancellation)
    t.cancel()
    
    # Wait until the inner cleanup task actually starts closing the client
    await close_started.wait()
    
    # Now the cleanup task is running, but the await asyncio.shield(ctask) is still blocking `t` from finishing.
    # If we cancel `t` again? `t` is already cancelled, it's raising CancelledError.
    with pytest.raises(asyncio.CancelledError):
        await t
        
    # The client should be None because we detached
    assert transport.client is None
    
    # We should have 1 active cleanup task
    assert len(transport._cleanup_tasks) == 1
    
    # Disconnect will await the cleanup tasks
    dt = asyncio.create_task(transport.disconnect())
    await asyncio.sleep(0.01)
    
    # It should be waiting for close_finish
    assert not dt.done()
    
    # Release the close
    close_finish.set()
    await dt
    
    # Cleanup task should be gone
    assert len(transport._cleanup_tasks) == 0


@pytest.mark.asyncio
async def test_slack_transport_true_double_cancellation(mock_adapter, mock_client_factory):
    close_started = asyncio.Event()
    
    def hanging_factory(token):
        c = mock_client_factory(token)
        async def hang():
            await asyncio.sleep(1.0)
        c.connect.side_effect = hang
        
        async def slow_close():
            close_started.set()
            await asyncio.sleep(5.0) # Unending close
        c.close = slow_close
        return c
        
    transport = SlackTransport("app-token", mock_adapter, hanging_factory, enabled=True)
    
    t = asyncio.create_task(transport.connect())
    await asyncio.sleep(0.01) # start connect
    
    t.cancel() # 1st cancel
    await close_started.wait() # wait for inner close to begin
    
    dt = asyncio.create_task(transport.disconnect())
    await asyncio.sleep(0.01) # start disconnect drain
    
    # Now cancel the disconnect itself (2nd cancel)
    dt.cancel()
    
    with pytest.raises(asyncio.CancelledError):
        await dt
        
    # the cleanup task should STILL be tracked despite double cancel
    assert len(transport._cleanup_tasks) == 1
    # manually cancel it to keep test fast
    for task in transport._cleanup_tasks:
        task.cancel()
