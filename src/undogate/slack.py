import logging
import asyncio
from typing import Set, Dict, Any, Callable, Awaitable, Optional

logger = logging.getLogger("undogate.slack")

class UnauthorizedUserError(Exception): pass
class InvalidPayloadError(Exception):
    pass

class TaskCapacityExceededError(Exception): pass

class SlackInteractionAdapter:
    def __init__(
        self, 
        admin_allowlist: Set[str], 
        team_allowlist: Set[str],
        target_resolver: Callable[[str, str, str], Awaitable[Optional[str]]],
        approve_callback: Callable[[str], Awaitable[Dict[str, Any]]], 
        reject_callback: Callable[[str], Awaitable[Dict[str, Any]]],
        status_callback: Callable[[str], Awaitable[str]], 
        slack_update_callback: Callable[[str, str, str], Awaitable[None]],
        max_concurrent_tasks: int = 100,
        shutdown_timeout: float = 5.0
    ):
        self.admin_allowlist = admin_allowlist
        self.team_allowlist = team_allowlist
        self.target_resolver = target_resolver
        self.approve_callback = approve_callback
        self.reject_callback = reject_callback
        self.status_callback = status_callback
        self.slack_update_callback = slack_update_callback
        self.max_concurrent_tasks = max_concurrent_tasks
        self.shutdown_timeout = shutdown_timeout
        
        self._active_tasks: Set[asyncio.Task] = set()
        self._update_locks: Dict[tuple, Dict[str, Any]] = {}
        self._stopping = False

    def _validate_payload_structure(self, payload: Any) -> tuple[str, str, str, str, str, str]:
        if not isinstance(payload, dict): raise InvalidPayloadError("Payload must be a dictionary")
        user = payload.get("user")
        if not isinstance(user, dict) or not isinstance(user.get("id"), str): raise InvalidPayloadError("Missing or invalid user.id")
        team = payload.get("team")
        if not isinstance(team, dict) or not isinstance(team.get("id"), str): raise InvalidPayloadError("Missing or invalid team.id")
        actions = payload.get("actions")
        if not isinstance(actions, list) or len(actions) != 1: raise InvalidPayloadError("Exactly 1 action required.")
        action = actions[0]
        if not isinstance(action, dict): raise InvalidPayloadError("Action must be a dictionary.")
        action_id = action.get("action_id")
        public_id = action.get("value")
        if not isinstance(action_id, str) or not isinstance(public_id, str) or not public_id.startswith("cp_"):
            raise InvalidPayloadError("Invalid action_id or checkpoint ID format.")
        container = payload.get("container")
        if not isinstance(container, dict): raise InvalidPayloadError("Missing or invalid container.")
        channel_id = container.get("channel_id")
        message_ts = container.get("message_ts")
        if not isinstance(channel_id, str) or not isinstance(message_ts, str): raise InvalidPayloadError("Missing channel or message target binding.")
        return user["id"], team["id"], action_id, public_id, channel_id, message_ts

    async def handle_interaction(self, payload: dict) -> dict:
        if self._stopping: raise TaskCapacityExceededError("Server is shutting down. Rejecting new interactions.")
        user_id, team_id, action_id, public_id, channel_id, message_ts = self._validate_payload_structure(payload)

        if team_id not in self.team_allowlist: raise UnauthorizedUserError("Team not authorized.")
        if user_id not in self.admin_allowlist: raise UnauthorizedUserError("User not authorized.")
        if action_id not in ("approve_button", "reject_button"): raise InvalidPayloadError(f"Unknown action: {action_id}")
        if len(self._active_tasks) >= self.max_concurrent_tasks: raise TaskCapacityExceededError("Server is too busy.")

        is_approve = (action_id == "approve_button")
        
        task = asyncio.create_task(self._process_interaction(team_id, channel_id, message_ts, public_id, is_approve))
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)
        return {"acknowledged": True}

    async def _process_interaction(self, team_id: str, channel_id: str, message_ts: str, public_id: str, is_approve: bool):
        try:
            try:
                expected_public_id = await self.target_resolver(team_id, channel_id, message_ts)
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.error(f"Target resolver failed for {channel_id}/{message_ts}: {e}")
                return

            if not expected_public_id or expected_public_id != public_id:
                logger.warning(f"Target binding failed: payload {public_id} != expected {expected_public_id}")
                return

            if self._stopping:
                logger.warning("Aborting interaction processing; server is shutting down.")
                return

            if is_approve:
                await self.approve_callback(public_id)
            else:
                await self.reject_callback(public_id)
                
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.error(f"Internal error processing checkpoint {public_id}: {type(e).__name__}")
            
        target_key = (team_id, channel_id, message_ts)
        lock_entry = self._update_locks.setdefault(target_key, {"lock": asyncio.Lock(), "refs": 0})
        lock_entry["refs"] += 1
        
        try:
            async with lock_entry["lock"]:
                try:
                    final_state = await self.status_callback(public_id)
                    if final_state == "applied": msg = f":white_check_mark: Checkpoint {public_id} successfully applied."
                    elif final_state == "approved": msg = f":white_check_mark: Checkpoint {public_id} approved, pending execution verification."
                    elif final_state in ("denied", "rejected"): msg = f":x: Checkpoint {public_id} was rejected."
                    elif final_state == "undone": msg = f":rewind: Checkpoint {public_id} undone."
                    else: msg = f":hourglass_flowing_sand: Checkpoint {public_id} status is {final_state}, pending verification."
                    await self._safe_slack_update(channel_id, message_ts, msg)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    logger.error(f"Failed to query final state for {public_id}: {e}")
                    await self._safe_slack_update(channel_id, message_ts, ":rotating_light: Internal error resolving final state.")
        finally:
            lock_entry["refs"] -= 1
            if lock_entry["refs"] == 0:
                self._update_locks.pop(target_key, None)

    async def _safe_slack_update(self, channel_id: str, message_ts: str, msg: str):
        try:
            async with asyncio.timeout(3.0):
                await self.slack_update_callback(channel_id, message_ts, msg)
        except asyncio.TimeoutError:
            logger.error("Timeout updating Slack UI.")
        except Exception as e:
            logger.error(f"Failed to update Slack UI: {e}")

    async def shutdown(self):
        self._stopping = True
        if self._active_tasks:
            logger.info(f"Draining {len(self._active_tasks)} active Slack interactions...")
            done, pending = await asyncio.wait(self._active_tasks, timeout=self.shutdown_timeout)
            if pending:
                logger.warning(f"{len(pending)} Slack interaction tasks did not finish in time and will be cancelled.")
                for task in pending: task.cancel()
