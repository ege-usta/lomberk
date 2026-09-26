import asyncio
import logging
from typing import Dict, Tuple

logger = logging.getLogger("undogate.offline_pilot")

class InMemoryBindingStore:
    def __init__(self):
        self.store: Dict[Tuple[str, str, str], str] = {}
    
    async def resolve(self, team_id: str, channel_id: str, message_ts: str) -> str | None:
        return self.store.get((team_id, channel_id, message_ts))
        
    def bind(self, team_id: str, channel_id: str, message_ts: str, public_id: str):
        self.store[(team_id, channel_id, message_ts)] = public_id

    def drop(self, team_id: str, channel_id: str, message_ts: str):
        self.store.pop((team_id, channel_id, message_ts), None)


class OfflinePublisher:
    def __init__(self, binding_store: InMemoryBindingStore):
        self.binding_store = binding_store
        self.message_counter = 0

    async def publish_checkpoint(self, team_id: str, channel_id: str, public_id: str, lossy: bool = False) -> str:
        """Simulates sending a message to Slack and returns a fake message_ts.
        If lossy=True, simulates losing the response and not saving the binding.
        """
        self.message_counter += 1
        ts = f"offline_ts_{self.message_counter}"
        if not lossy:
            self.binding_store.bind(team_id, channel_id, ts, public_id)
        return ts


class OfflineUpdater:
    def __init__(self):
        self.updates = []
        self.event = asyncio.Event()
        
    async def update_message(self, channel_id: str, message_ts: str, text: str):
        self.updates.append((channel_id, message_ts, text))
        self.event.set()
        
    async def wait_for_update(self, timeout=2.0) -> Tuple[str, str, str] | None:
        """Waits for a single UI update callback to trigger, or times out."""
        try:
            await asyncio.wait_for(self.event.wait(), timeout)
            res = self.updates[-1]
            self.event.clear()
            return res
        except asyncio.TimeoutError:
            return None



async def run_standalone_demo():
    print("--- Undogate Offline Pilot ---")
    print("Initializing offline binding store and publisher...")
    store = InMemoryBindingStore()
    publisher = OfflinePublisher(store)
    updater = OfflineUpdater()
    
    print("\n[Step 1] API Request -> Pending Checkpoint")
    print("Simulated checkpoint created: cp_demo_123")
    
    print("\n[Step 2] Fake Publisher sends message -> binding formed")
    ts = await publisher.publish_checkpoint("T_DEMO", "C_DEMO", "cp_demo_123")
    print(f"Bound (T_DEMO, C_DEMO, {ts}) -> cp_demo_123")
    
    print("\n[Step 3] Incoming interaction (Approve)")
    resolved = await store.resolve("T_DEMO", "C_DEMO", ts)
    print(f"Resolved Socket Mode envelope to checkpoint: {resolved}")
    
    print("\n[Step 4] Trigger DB execution (Simulated)")
    await updater.update_message("C_DEMO", ts, f":white_check_mark: Checkpoint {resolved} successfully applied.")
    
    print("\n[Step 5] Awaiting UI update callback...")
    update = await updater.wait_for_update(timeout=2.0)
    print(f"UI Updated in channel {update[0]}, ts {update[1]}: {update[2]}")
    
    print("\nOffline Pilot components verified. E2E execution runs via test suite.")

if __name__ == "__main__":
    asyncio.run(run_standalone_demo())
