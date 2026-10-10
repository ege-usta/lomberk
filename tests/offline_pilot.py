"""Fake Slack pieces for the offline pilot. Test-only: it does not ship in the rowback package."""
import asyncio
import logging

logger = logging.getLogger("rowback.offline_pilot")

class InMemoryBindingStore:
    def __init__(self):
        self.store: dict[tuple[str, str, str], str] = {}

    async def resolve(self, team_id: str, channel_id: str, message_ts: str) -> str | None:
        return self.store.get((team_id, channel_id, message_ts))

    def bind(self, team_id: str, channel_id: str, message_ts: str, public_id: str):
        self.store[(team_id, channel_id, message_ts)] = public_id

    def drop(self, team_id: str, channel_id: str, message_ts: str):
        self.store.pop((team_id, channel_id, message_ts), None)


class PublishOutcomeUnknown(Exception):
    """The fake sender accepted the message, but its response was lost."""


class OfflinePublisher:
    def __init__(self, binding_store: InMemoryBindingStore):
        self.binding_store = binding_store
        self.message_counter = 0
        self.sent_messages: list[dict[str, str]] = []

    async def publish_checkpoint(self, team_id: str, channel_id: str, public_id: str, lossy: bool = False) -> str:
        """Simulates sending a message to Slack and returns a fake message_ts.
        If lossy=True, simulates losing the response and not saving the binding.
        """
        self.message_counter += 1
        ts = f"offline_ts_{self.message_counter}"
        self.sent_messages.append({"team": team_id, "channel": channel_id, "ts": ts, "public_id": public_id})
        if lossy:
            raise PublishOutcomeUnknown("Send outcome unknown; reconcile manually, do not resend.")
        self.binding_store.bind(team_id, channel_id, ts, public_id)
        return ts


class OfflineUpdater:
    def __init__(self):
        self.updates = []
        self.event = asyncio.Event()

    async def update_message(self, channel_id: str, message_ts: str, text: str):
        self.updates.append((channel_id, message_ts, text))
        self.event.set()

    async def wait_for_update(self, timeout=2.0) -> tuple[str, str, str] | None:
        """Waits for a single UI update callback to trigger, or times out."""
        try:
            await asyncio.wait_for(self.event.wait(), timeout)
            res = self.updates[-1]
            self.event.clear()
            return res
        except TimeoutError:
            return None



def main():
    """Run the real isolated DB scenario; never print simulated DB success."""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    scenario = root / "tests/integration/test_slack_integration.py"
    if not scenario.exists():
        raise SystemExit("Run from a source checkout with test dependencies and Docker installed.")
    print("Offline pilot: real disposable PostgreSQL, fake Slack transport. Docker required.", flush=True)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", f"{scenario}::test_offline_pilot_e2e_flow",
         "-v", "-s", "-p", "no:cacheprovider"], cwd=root, check=False,
    )
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
