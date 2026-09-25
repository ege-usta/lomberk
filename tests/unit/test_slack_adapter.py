import pytest
import asyncio
from undogate.slack import SlackInteractionAdapter, UnauthorizedUserError, InvalidPayloadError, TaskCapacityExceededError

@pytest.fixture
def mock_callbacks():
    class Callbacks:
        def __init__(self):
            self.approve_calls = 0
            self.update_calls = []
            self.lock = asyncio.Lock()
            
        async def resolve_target(self, team, channel, ts):
            if channel == "valid_chan" and ts == "valid_ts":
                return "cp_123"
            return None

        async def approve(self, public_id):
            async with self.lock:
                self.approve_calls += 1
                if self.approve_calls == 1:
                    await asyncio.sleep(0.02)
                    return {"status": "applied", "authoritative_state": "applied"}
                else:
                    return {"status": "conflict", "authoritative_state": "applied"}
            
        async def reject(self, public_id):
            return {"status": "denied", "authoritative_state": "denied"}
            
        async def update(self, channel, ts, msg):
            if channel == "FAIL_CHANNEL":
                raise Exception("Slack API down")
            self.update_calls.append((channel, ts, msg))

    return Callbacks()

@pytest.mark.asyncio
async def test_slack_unauthorized_team(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.update)
    payload = {"team": {"id": "T99"}, "user": {"id": "U123"}, "actions": [{"action_id": "approve_button", "value": "cp_123"}], "container": {"channel_id": "C", "message_ts": "T"}}
    with pytest.raises(UnauthorizedUserError):
        await adapter.handle_interaction(payload)

@pytest.mark.asyncio
async def test_slack_invalid_payload_types(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.update)
    with pytest.raises(InvalidPayloadError, match="must be a dictionary"):
        await adapter.handle_interaction(None)
        
    with pytest.raises(InvalidPayloadError, match="Missing or invalid user"):
        await adapter.handle_interaction({"user": None, "team": {"id": "T1"}})

@pytest.mark.asyncio
async def test_slack_target_binding_failure(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.update)
    
    # Send a request with a valid cp_ but wrong channel/ts
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "hacked_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    with pytest.raises(InvalidPayloadError, match="Target binding validation failed"):
        await adapter.handle_interaction(payload)

@pytest.mark.asyncio
async def test_slack_concurrent_double_click(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.update)
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "valid_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    
    # Send two concurrent interactions
    ack1 = await adapter.handle_interaction(payload)
    ack2 = await adapter.handle_interaction(payload)
    
    assert ack1["acknowledged"] is True
    assert ack2["acknowledged"] is True
    
    await adapter.shutdown()
    
    assert mock_callbacks.approve_calls == 2
    assert len(mock_callbacks.update_calls) == 2
    
    messages = [call[2] for call in mock_callbacks.update_calls]
    assert any("successfully applied" in msg for msg in messages)
    assert messages.count(":white_check_mark: Checkpoint cp_123 successfully applied.") == 2

@pytest.mark.asyncio
async def test_slack_shutdown_bounded_drain(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.update, shutdown_timeout=0.01)
    
    # Mock a long running approve
    async def slow_approve(pid):
        await asyncio.sleep(0.5)
        return {"status": "applied"}
    adapter.approve_callback = slow_approve
    
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "valid_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    
    await adapter.handle_interaction(payload)
    
    # Ensure shutdown stops taking new requests
    with pytest.raises(TaskCapacityExceededError, match="Server is shutting down"):
        adapter._stopping = True
        await adapter.handle_interaction(payload)
        
    # Ensure shutdown drains and cancels pending tasks after timeout
    await adapter.shutdown()
    await asyncio.sleep(0.02)
    assert len(adapter._active_tasks) == 0
