import logging
import asyncio
from typing import Optional, Callable
from collections import OrderedDict
from slack_sdk.socket_mode.aiohttp import SocketModeClient
from slack_sdk.socket_mode.response import SocketModeResponse
from slack_sdk.socket_mode.request import SocketModeRequest
from undogate.slack import SlackInteractionAdapter, TaskCapacityExceededError, InvalidPayloadError

logger = logging.getLogger("undogate.slack_transport")


class SlackTransport:
    def __init__(
        self,
        app_token: str,
        business_adapter: SlackInteractionAdapter,
        client_factory: Callable[[str], SocketModeClient],
        enabled: bool = False,
        dedup_ttl_seconds: int = 60,
        max_dedup_size: int = 10000
    ):
        self.enabled = enabled
        self.app_token = app_token
        self.business_adapter = business_adapter
        self.client_factory = client_factory
        self.dedup_ttl_seconds = dedup_ttl_seconds
        self.max_dedup_size = max_dedup_size
        
        self.client: Optional[SocketModeClient] = None
        self._processed_envelopes: OrderedDict[str, tuple[float, str]] = OrderedDict()
        self._shutdown_event = asyncio.Event()
        self._connect_lock = asyncio.Lock()

    def _evict_old_envelopes(self, now: float):
        items_to_remove = []
        for env_id, (ts, state) in self._processed_envelopes.items():
            if state != "INFLIGHT":
                # Only evict if TTL passed or if we are over capacity
                if now - ts > self.dedup_ttl_seconds or len(self._processed_envelopes) - len(items_to_remove) >= self.max_dedup_size:
                    items_to_remove.append(env_id)
        for env_id in items_to_remove:
            self._processed_envelopes.pop(env_id)

    async def connect(self):
        if not self.enabled:
            logger.info("Slack Transport is disabled.")
            return

        try:
            # We use a custom timeout if tests inject one, otherwise 10.0s
            timeout_val = getattr(self, "connect_timeout", 10.0)
            async with asyncio.timeout(timeout_val):
                async with self._connect_lock:
                    if self.client or self._shutdown_event.is_set():
                        return
                        
                    logger.info("Initializing Slack Socket Mode Transport...")
                    try:
                        self.client = self.client_factory(self.app_token)
                        self.client.socket_mode_request_listeners.append(self._process_request)
                        await self.client.connect()
                    except BaseException as e:
                        # Catch CancelledError, TimeoutError, Exception
                        logger.error(f"Failed or cancelled during Slack Transport connect: {type(e).__name__}")
                        client_to_close = self.client
                        self.client = None
                        if client_to_close:
                            try:
                                # Run the close inside a shielded task so it doesn't get aborted by the same CancelledError
                                async def _safe_close():
                                    try:
                                        async with asyncio.timeout(3.0):
                                            await client_to_close.close()
                                    except BaseException:
                                        pass
                                await asyncio.shield(_safe_close())
                            except BaseException:
                                pass
                        raise
        except asyncio.TimeoutError:
            logger.error("Timeout waiting for Slack transport connect.")
            raise

    async def _process_request(self, client: SocketModeClient, req: SocketModeRequest):
        if self._shutdown_event.is_set():
            return

        envelope_id = req.envelope_id
        if not envelope_id or not isinstance(envelope_id, str):
            logger.warning("Invalid or missing envelope_id.")
            return

        if req.type != "interactive" or not isinstance(req.payload, dict) or req.payload.get("type") != "block_actions":
            response = SocketModeResponse(envelope_id=envelope_id)
            try:
                await client.send_socket_mode_response(response)
            except Exception as e:
                logger.warning(f"Failed to ACK unsupported envelope {envelope_id}: {e}")
            return

        now = asyncio.get_event_loop().time()

        # 1. Check exact matches first! Do not evict before duplicate checking.
        if envelope_id in self._processed_envelopes:
            _, state = self._processed_envelopes[envelope_id]
            if state == "INFLIGHT":
                logger.warning(f"Concurrent request for envelope_id {envelope_id} dropped.")
                return
            elif state == "ACCEPTED":
                logger.info(f"Duplicate envelope_id {envelope_id} seen. Already ACCEPTED. Retrying ACK.")
                response = SocketModeResponse(envelope_id=envelope_id)
                try:
                    await client.send_socket_mode_response(response)
                except Exception as e:
                    logger.warning(f"Failed to send ACK for duplicate envelope {envelope_id}: {e}")
                return

        # 2. Evict expired or excess items (only evicts non-INFLIGHT)
        self._evict_old_envelopes(now)

        # 3. Capacity check: prevent exceeding max_dedup_size with NEW items
        if len(self._processed_envelopes) >= self.max_dedup_size:
            logger.warning(f"Transport dedup map full ({self.max_dedup_size}). Dropping {envelope_id} without ACK.")
            return

        # 4. Mark INFLIGHT
        self._processed_envelopes[envelope_id] = (now, "INFLIGHT")
        
        try:
            await self.business_adapter.handle_interaction(req.payload)
        except TaskCapacityExceededError:
            logger.warning(f"Transport dropped interaction {envelope_id} due to capacity. Will not ACK (let Slack retry).")
            self._processed_envelopes.pop(envelope_id, None)
            return
        except InvalidPayloadError:
            logger.warning(f"Invalid payload for {envelope_id}. ACKing to drop permanently.")
            self._processed_envelopes.pop(envelope_id, None)
            response = SocketModeResponse(envelope_id=envelope_id)
            try:
                await client.send_socket_mode_response(response)
            except Exception:
                pass
            return
        except Exception as e:
            logger.warning(f"Interaction {envelope_id} aborted synchronously: {type(e).__name__}")
            self._processed_envelopes.pop(envelope_id, None)
            return

        # 5. Admission successful. Must mark ACCEPTED.
        self._processed_envelopes[envelope_id] = (now, "ACCEPTED")

        # 6. Try to ACK.
        response = SocketModeResponse(envelope_id=envelope_id)
        try:
            await client.send_socket_mode_response(response)
        except Exception as e:
            logger.warning(f"Failed to ACK accepted envelope {envelope_id}: {e}")

    async def disconnect(self):
        self._shutdown_event.set()
        if not self.enabled:
            return

        try:
            async with asyncio.timeout(5.0):
                async with self._connect_lock:
                    logger.info("Closing Slack Socket Mode Transport...")
                    try:
                        await self.business_adapter.shutdown()
                    except Exception as e:
                        logger.error(f"Error during business adapter shutdown: {e}")
                    finally:
                        if self.client:
                            try:
                                async with asyncio.timeout(3.0):
                                    await self.client.close()
                            except asyncio.TimeoutError:
                                logger.error("Timeout closing Slack Socket Mode client.")
                            except Exception as e:
                                logger.error(f"Error closing Slack client: {e}")
                            finally:
                                self.client = None
        except asyncio.TimeoutError:
            logger.error("Timeout acquiring lock for disconnect.")
