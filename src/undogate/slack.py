import logging
import asyncio
from typing import Set, Dict, Any, Callable, Awaitable, Optional

logger = logging.getLogger("undogate.slack")

class UnauthorizedUserError(Exception):
    pass

class InvalidPayloadError(Exception):
    pass

class TaskCapacityExceededError(Exception):
    pass

class SlackInteractionAdapter:
    def __init__(
        self, 
        admin_allowlist: Set[str], 
        team_allowlist: Set[str],
        target_resolver: Callable[[str, str, str], Awaitable[Optional[str]]],
        approve_callback: Callable[[str], Awaitable[Dict[str, Any]]], 
        reject_callback: Callable[[str], Awaitable[Dict[str, Any]]], 
        slack_update_callback: Callable[[str, str, str], Awaitable[None]],
        max_concurrent_tasks: int = 100,
        shutdown_timeout: float = 5.0
    ):
        self.admin_allowlist = admin_allowlist
        self.team_allowlist = team_allowlist
        self.target_resolver = target_resolver
        self.approve_callback = approve_callback
        self.reject_callback = reject_callback
        self.slack_update_callback = slack_update_callback
        self.max_concurrent_tasks = max_concurrent_tasks
        self.shutdown_timeout = shutdown_timeout
        
        self._active_tasks: Set[asyncio.Task] = set()
        self._stopping = False

    def _validate_payload_structure(self, payload: Any) -> tuple[str, str, str, str, str, str]:
        if not isinstance(payload, dict):
            raise InvalidPayloadError("Payload must be a dictionary")

        user = payload.get("user")
        if not isinstance(user, dict) or not isinstance(user.get("id"), str):
            raise InvalidPayloadError("Missing or invalid user.id")

        team = payload.get("team")
        if not isinstance(team, dict) or not isinstance(team.get("id"), str):
            raise InvalidPayloadError("Missing or invalid team.id")

        actions = payload.get("actions")
        if not isinstance(actions, list) or len(actions) != 1:
            raise InvalidPayloadError("Exactly 1 action required.")
        
        action = actions[0]
        if not isinstance(action, dict):
            raise InvalidPayloadError("Action must be a dictionary.")

        action_id = action.get("action_id")
        public_id = action.get("value")
        
        if not isinstance(action_id, str) or not isinstance(public_id, str) or not public_id.startswith("cp_"):
            raise InvalidPayloadError("Invalid action_id or checkpoint ID format.")
            
        container = payload.get("container")
        if not isinstance(container, dict):
            raise InvalidPayloadError("Missing or invalid container.")
            
        channel_id = container.get("channel_id")
        message_ts = container.get("message_ts")
        
        if not isinstance(channel_id, str) or not isinstance(message_ts, str):
            raise InvalidPayloadError("Missing channel or message target binding.")

        return user["id"], team["id"], action_id, public_id, channel_id, message_ts

    async def handle_interaction(self, payload: dict) -> dict:
        if self._stopping:
            raise TaskCapacityExceededError("Server is shutting down. Rejecting new interactions.")

        user_id, team_id, action_id, public_id, channel_id, message_ts = self._validate_payload_structure(payload)

        if team_id not in self.team_allowlist:
            logger.warning(f"Unauthorized interaction attempt from unlisted team: {team_id}")
            raise UnauthorizedUserError("Team not authorized.")

        if user_id not in self.admin_allowlist:
            logger.warning(f"Unauthorized interaction attempt from unlisted user: {user_id}")
            raise UnauthorizedUserError("User not authorized.")

        if action_id not in ("approve_button", "reject_button"):
            logger.warning(f"Unknown action_id: {action_id}")
            raise InvalidPayloadError(f"Unknown action: {action_id}")
            
        # Target Binding: Ensure the Slack channel/message strictly matches the expected public_id
        expected_public_id = await self.target_resolver(team_id, channel_id, message_ts)
        if not expected_public_id or expected_public_id != public_id:
            logger.warning(f"Target binding failed: payload public_id {public_id} does not match bound target {expected_public_id}")
            raise InvalidPayloadError("Target binding validation failed.")

        if len(self._active_tasks) >= self.max_concurrent_tasks:
            logger.error("Slack Adapter task capacity exceeded.")
            raise TaskCapacityExceededError("Server is too busy.")

        is_approve = (action_id == "approve_button")
        
        task = asyncio.create_task(self._execute_and_update(public_id, channel_id, message_ts, is_approve))
        self._active_tasks.add(task)
        task.add_done_callback(self._active_tasks.discard)
            
        return {"acknowledged": True}

    async def _execute_and_update(self, public_id: str, channel_id: str, message_ts: str, is_approve: bool):
        try:
            if is_approve:
                result = await self.approve_callback(public_id)
            else:
                result = await self.reject_callback(public_id)
                
            status = result.get("status")
            authoritative_state = result.get("authoritative_state", status)
            
            # Use authoritative state to ensure UI doesn't regress
            if authoritative_state in ("applied", "approved"):
                msg = f":white_check_mark: Checkpoint {public_id} successfully applied."
            elif authoritative_state == "denied":
                msg = f":x: Checkpoint {public_id} was rejected."
            elif status == "conflict":
                # Do not blindly say "already processed". Reflect authoritative state.
                msg = f":warning: Checkpoint {public_id} processed previously. Current state: {authoritative_state}"
            elif status == "unknown":
                msg = f":hourglass_flowing_sand: Checkpoint {public_id} status is unknown. Verifying outcome..."
            else:
                msg = f":warning: Checkpoint {public_id} execution securely aborted. (Ref: {public_id})"
                
        except Exception as e:
            logger.error(f"Internal error processing checkpoint {public_id}: {type(e).__name__}")
            msg = f":rotating_light: Internal error processing checkpoint {public_id}."
            
        try:
            # Wrap slack update in a timeout to prevent hanging the drained tasks
            async with asyncio.timeout(3.0):
                await self.slack_update_callback(channel_id, message_ts, msg)
        except asyncio.TimeoutError:
            logger.error(f"Timeout updating Slack UI for {public_id}")
        except Exception as update_err:
            logger.error(f"Failed to update Slack UI for {public_id}: {update_err}")

    async def shutdown(self):
        """Bounded drain of active tasks."""
        self._stopping = True
        if self._active_tasks:
            logger.info(f"Draining {len(self._active_tasks)} active Slack interactions...")
            done, pending = await asyncio.wait(self._active_tasks, timeout=self.shutdown_timeout)
            if pending:
                logger.warning(f"{len(pending)} Slack interaction tasks did not finish in time and will be cancelled.")
                for task in pending:
                    task.cancel()
