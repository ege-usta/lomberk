import logging
import asyncio
from typing import Optional, Callable
from slack_sdk.socket_mode.aiohttp import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.socket_mode.request import SocketModeRequest
from undogate.slack import SlackInteractionAdapter, TaskCapacityExceededError

logger = logging.getLogger("undogate.slack_transport")

class SlackTransport:
    def __init__(
        self,
        app_token: str,
        web_client,
        business_adapter: SlackInteractionAdapter,
        enabled: bool = False,
        dedup_ttl_seconds: int = 60
    ):
        self.enabled = enabled
        self.app_token = app_token
        self.web_client = web_client
        self.business_adapter = business_adapter
        self.dedup_ttl_seconds = dedup_ttl_seconds
        
        self.client: Optional[SocketModeClient] = None
        self._processed_envelopes = {}
        self._shutdown_event = asyncio.Event()

    async def connect(self):
        if not self.enabled:
            logger.info("Slack Transport is disabled.")
            return

        logger.info("Initializing Slack Socket Mode Transport...")
        self.client = SocketModeClient(app_token=self.app_token, web_client=self.web_client)
        self.client.socket_mode_request_listeners.append(self._process_request)
        await self.client.connect()

    async def _process_request(self, client: SocketModeClient, req: SocketModeRequest):
        if req.type != "interactive":
            return
            
        payload = req.payload
        if not isinstance(payload, dict) or payload.get("type") != "block_actions":
            return
            
        envelope_id = req.envelope_id
        
        # Bounded deduplication: prevents retry from spawning execution
        # (DB idempotency is the ultimate safeguard, this just reduces noise)
        now = asyncio.get_event_loop().time()
        self._processed_envelopes = {k: v for k, v in self._processed_envelopes.items() if now - v < self.dedup_ttl_seconds}
        
        if envelope_id in self._processed_envelopes:
            logger.warning(f"Duplicate envelope_id {envelope_id} dropped at transport boundary.")
            response = SocketModeResponse(envelope_id=envelope_id)
            await client.send_socket_mode_response(response)
            return
            
        self._processed_envelopes[envelope_id] = now
        
        # Send ACK instantly. This strictly decouples ACK from durable execution.
        response = SocketModeResponse(envelope_id=envelope_id)
        await client.send_socket_mode_response(response)
        
        try:
            # Delegate to the business adapter
            await self.business_adapter.handle_interaction(payload)
        except TaskCapacityExceededError:
            logger.warning("Slack Transport dropped interaction due to capacity exhaustion.")
        except Exception as e:
            # All other payload/auth validation errors are handled by adapter logging
            # Do NOT log the raw payload or sensitive data here.
            logger.warning(f"Interaction processing aborted: {type(e).__name__}")

    async def disconnect(self):
        if not self.enabled or not self.client:
            return
        
        logger.info("Closing Slack Socket Mode Transport...")
        self._shutdown_event.set()
        await self.business_adapter.shutdown()
        
        if self.client:
            await self.client.close()
            self.client = None
