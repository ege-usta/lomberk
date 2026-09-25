import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock
from slack_sdk.socket_mode.request import SocketModeRequest
from undogate.slack_transport import SlackTransport
from undogate.slack import SlackInteractionAdapter, TaskCapacityExceededError

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
