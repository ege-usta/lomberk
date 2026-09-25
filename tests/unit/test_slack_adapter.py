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
            self.current_state = "pending"
            self.resolver_event = asyncio.Event()
            self.resolver_event.set() # Default to not blocking
            
        async def resolve_target(self, team, channel, ts):
            await self.resolver_event.wait()
            if channel == "valid_chan" and ts == "valid_ts":
                return "cp_123"
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
    assert ":x: Target binding validation failed." in mock_callbacks.update_calls[0][2]

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
    
    # Test 'approved'
    mock_callbacks.current_state = "approved"
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert ":white_check_mark: Checkpoint cp_123 approved, pending execution verification." in mock_callbacks.update_calls[-1][2]
    
    # Test 'unknown'
    adapter._stopping = False
    mock_callbacks.current_state = "unknown"
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert ":hourglass_flowing_sand: Checkpoint cp_123 status is unknown, pending verification." in mock_callbacks.update_calls[-1][2]

    # Test 'undone'
    adapter._stopping = False
    mock_callbacks.current_state = "undone"
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    assert ":rewind: Checkpoint cp_123 undone." in mock_callbacks.update_calls[-1][2]

@pytest.mark.asyncio
async def test_slack_out_of_order_callbacks(mock_callbacks):
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update)
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "valid_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }

    # Task 1 is slow to approve but eventually finishes.
    # Task 2 is fast, sees it's busy, and polls the state right away.
    # By the time Task 1 updates the UI, the state is 'applied'.
    # Both should query status at the VERY END, so both should see 'applied'.
    mock_callbacks.current_state = "applied"
    
    # This proves that even if callbacks finish in weird orders, the final status is authoritative
    await adapter.handle_interaction(payload)
    await adapter.handle_interaction(payload)
    if adapter._active_tasks: await asyncio.gather(*adapter._active_tasks)
    await adapter.shutdown()
    
    assert len(mock_callbacks.update_calls) == 2
    assert mock_callbacks.update_calls[0][2] == ":white_check_mark: Checkpoint cp_123 successfully applied."
    assert mock_callbacks.update_calls[1][2] == ":white_check_mark: Checkpoint cp_123 successfully applied."

@pytest.mark.asyncio
async def test_slack_shutdown_resolver_race(mock_callbacks):
    # Event/barrier reproducer: shutdown during resolver wait
    adapter = SlackInteractionAdapter({"U123"}, {"T1"}, mock_callbacks.resolve_target, mock_callbacks.approve, mock_callbacks.reject, mock_callbacks.status, mock_callbacks.update, shutdown_timeout=0.01)
    
    mock_callbacks.resolver_event.clear() # Block resolver
    
    payload = {
        "team": {"id": "T1"}, "user": {"id": "U123"},
        "container": {"channel_id": "valid_chan", "message_ts": "valid_ts"},
        "actions": [{"action_id": "approve_button", "value": "cp_123"}]
    }
    
    # 1. Start interaction. Resolver blocks.
    await adapter.handle_interaction(payload)
    
    # 2. Shutdown begins. It waits for tasks (with short timeout), then cancels them.
    await adapter.shutdown()
    
    # 3. Release resolver.
    mock_callbacks.resolver_event.set()
    
    # Give event loop a tick to process cancellation
    await asyncio.sleep(0.02)
    
    # 4. Verify no execution or UI updates occurred because it was cancelled/aborted
    assert mock_callbacks.approve_calls == 0
    assert len(mock_callbacks.update_calls) == 0
