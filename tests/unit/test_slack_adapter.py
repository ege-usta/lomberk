import pytest
import asyncio
from undogate.ee.slack import SlackInteractionAdapter, UnauthorizedUserError, InvalidPayloadError, TaskCapacityExceededError

@pytest.fixture
def mock_callbacks():
    class Callbacks:
        def __init__(self):
            self.approve_calls = 0
            self.update_calls = []
            self.lock = asyncio.Lock()
            self.current_state = "pending"
            self.resolver_event = asyncio.Event()
            self.resolver_event.set()
            
        async def resolve_target(self, team, channel, ts):
            await self.resolver_event.wait()
            if channel == "valid_chan" and ts == "valid_ts":
                return "cp_123"
            if channel == "error_chan":
                raise Exception("DB down")
            return None

        async def approve(self, public_id):
            async with self.lock:
                self.approve_calls += 1
                if self.approve_calls == 1:
                    await asyncio.sleep(0.02)
                    if self.current_state == "pending": self.current_state = "applied"
                    return {"status": "applied"}
                else:
                    return {"status": "conflict"}
            
        async def reject(self, public_id):
            self.current_state = "denied"
            return {"status": "denied"}
            
        async def status(self, public_id):
            return self.current_state

        async def update(self, channel, ts, msg):
            if channel == "FAIL_CHANNEL":
                raise Exception("Slack API down")
            self.update_calls.append((channel, ts, msg))

    return Callbacks()

@pytest.mark.asyncio
async def test_slack_unauthorized_team(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update)
    payload = {"team": {"id": "T99"}, "user": {"id": "U123"}, "actions": [{"action_id": "approve_button", "value": "cp_123"}], "container": {"channel_id": "C", "message_ts": "T"}}
    with pytest.raises(UnauthorizedUserError):
        await adapter.handle_interaction(payload)

@pytest.mark.asyncio
async def test_slack_invalid_payload_types(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update)
    with pytest.raises(InvalidPayloadError, match="must be a dictionary"):
        await adapter.handle_interaction(None)

@pytest.mark.asyncio
async def test_slack_target_binding_failure(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update)
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "hacked_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert len(mock_callbacks.update_calls) == 0

@pytest.mark.asyncio
async def test_slack_target_resolver_exception(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update)
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "error_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert len(mock_callbacks.update_calls) == 0

@pytest.mark.asyncio
async def test_slack_concurrent_double_click(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update)
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "valid_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    
    ack1 = await adapter.handle_interaction(payload)
    ack2 = await adapter.handle_interaction(payload)
    assert ack1["acknowledged"] is True
    assert ack2["acknowledged"] is True
    
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert mock_callbacks.approve_calls == 2
    assert len(mock_callbacks.update_calls) == 2
    messages = [call[2] for call in mock_callbacks.update_calls]
    assert messages.count(":white_check_mark: Checkpoint cp_123 successfully applied.") == 2

@pytest.mark.asyncio
async def test_slack_state_mappings(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update)
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "valid_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    
    mock_callbacks.current_state = "approved"
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert ":white_check_mark: Checkpoint cp_123 approved, pending execution verification." in mock_callbacks.update_calls[-1][2]
    
    adapter._stopping = False
    mock_callbacks.current_state = "unknown"
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert ":hourglass_flowing_sand: Checkpoint cp_123 status is unknown, pending verification." in mock_callbacks.update_calls[-1][2]

    adapter._stopping = False
    mock_callbacks.current_state = "undone"
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert ":rewind: Checkpoint cp_123 undone." in mock_callbacks.update_calls[-1][2]

@pytest.mark.asyncio
async def test_slack_out_of_order_callbacks_with_barrier(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update)
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "valid_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }

    mock_callbacks.current_state = "busy"
    
    # Task 1 starts
    # Override approve to not touch current_state
    async def mock_app(pid): return {"status": "conflict"}
    adapter.approve_callback = mock_app
    t1 = asyncio.create_task(adapter._process_interaction("T1", "valid_chan", "valid_ts", "cp_123", is_approve=True))
    # Give it a moment to lock and read 'busy'
    await asyncio.sleep(0.01)
    
    # Task 2 starts. It waits for the lock.
    t2 = asyncio.create_task(adapter._process_interaction("T1", "valid_chan", "valid_ts", "cp_123", is_approve=True))
    
    # Task 1 finishes its update, releasing lock.
    # Task 2 acquires lock. By this time current_state is 'applied'.
    mock_callbacks.current_state = "applied"
    
    await asyncio.gather(t1, t2)
    
    # The second update MUST be "applied". Task 1's "busy" should not overwrite Task 2.
    assert len(mock_callbacks.update_calls) == 2
    assert "busy" in mock_callbacks.update_calls[0][2]
    assert "successfully applied" in mock_callbacks.update_calls[1][2]

@pytest.mark.asyncio
async def test_slack_shutdown_resolver_race(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update, shutdown_timeout=0.01)
    mock_callbacks.resolver_event.clear()
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "valid_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    await adapter.handle_interaction(payload)
    await adapter.shutdown()
    mock_callbacks.resolver_event.set()
    await asyncio.sleep(0.02)
    assert mock_callbacks.approve_calls == 0
    assert len(mock_callbacks.update_calls) == 0
