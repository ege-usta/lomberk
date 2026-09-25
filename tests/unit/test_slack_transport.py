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

@pytest.mark.asyncio
async def test_slack_transport_disabled(mock_adapter):
    transport = SlackTransport("app-token", None, mock_adapter, enabled=False)
    await transport.connect()
    assert transport.client is None
    await transport.disconnect()

@pytest.mark.asyncio
async def test_slack_transport_ignores_non_interactive(mock_adapter):
    transport = SlackTransport("app-token", None, mock_adapter, enabled=True)
    req = SocketModeRequest(type="events_api", envelope_id="env_1", payload={})
    
    mock_client = MagicMock()
    mock_client.send_socket_mode_response = AsyncMock()
    
    await transport._process_request(mock_client, req)
    
    # Not interactive, so no ACK sent and no adapter hit
    mock_client.send_socket_mode_response.assert_not_called()
    mock_adapter.handle_interaction.assert_not_called()

@pytest.mark.asyncio
async def test_slack_transport_ignores_non_block_actions(mock_adapter):
    transport = SlackTransport("app-token", None, mock_adapter, enabled=True)
    req = SocketModeRequest(type="interactive", envelope_id="env_1", payload={"type": "message_action"})
    
    mock_client = MagicMock()
    mock_client.send_socket_mode_response = AsyncMock()
    
    await transport._process_request(mock_client, req)
    
    mock_client.send_socket_mode_response.assert_not_called()
    mock_adapter.handle_interaction.assert_not_called()

@pytest.mark.asyncio
async def test_slack_transport_ack_and_delegate(mock_adapter):
    transport = SlackTransport("app-token", None, mock_adapter, enabled=True)
    payload = {"type": "block_actions", "user": {"id": "U123"}}
    req = SocketModeRequest(type="interactive", envelope_id="env_1", payload=payload)
    
    mock_client = MagicMock()
    mock_client.send_socket_mode_response = AsyncMock()
    
    await transport._process_request(mock_client, req)
    
    # Must ACK first
    mock_client.send_socket_mode_response.assert_called_once()
    assert mock_client.send_socket_mode_response.call_args[0][0].envelope_id == "env_1"
    
    # Must delegate to business adapter
    mock_adapter.handle_interaction.assert_called_once_with(payload)

@pytest.mark.asyncio
async def test_slack_transport_dedup(mock_adapter):
    transport = SlackTransport("app-token", None, mock_adapter, enabled=True)
    payload = {"type": "block_actions"}
    req = SocketModeRequest(type="interactive", envelope_id="env_1", payload=payload)
    
    mock_client = MagicMock()
    mock_client.send_socket_mode_response = AsyncMock()
    
    # Call twice with same envelope
    await transport._process_request(mock_client, req)
    await transport._process_request(mock_client, req)
    
    # ACK sent twice for the protocol
    assert mock_client.send_socket_mode_response.call_count == 2
    
    # BUT business logic only executed once!
    mock_adapter.handle_interaction.assert_called_once()

@pytest.mark.asyncio
async def test_slack_transport_capacity_exceeded(mock_adapter):
    transport = SlackTransport("app-token", None, mock_adapter, enabled=True)
    payload = {"type": "block_actions"}
    req = SocketModeRequest(type="interactive", envelope_id="env_1", payload=payload)
    
    mock_client = MagicMock()
    mock_client.send_socket_mode_response = AsyncMock()
    
    # Adapter throws TaskCapacityExceededError
    mock_adapter.handle_interaction.side_effect = TaskCapacityExceededError("Busy")
    
    # Should not crash the listener
    await transport._process_request(mock_client, req)
    
    mock_client.send_socket_mode_response.assert_called_once()

