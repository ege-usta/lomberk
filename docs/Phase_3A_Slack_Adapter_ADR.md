# Architecture Decision Record (ADR): Phase 3A - Slack Human-in-the-Loop Adapter

**Status:** Proposed (Awaiting Approval)
**Context:** Undogate requires a secure, out-of-band approval mechanism for database mutations that trigger `REQUIRE_APPROVAL`. The mechanism must bridge asynchronous human decisions in a Slack workspace with the strictly serializable, idempotent PostgreSQL execution engine.

This ADR defines the architectural constraints and operational flow for a single-workspace Slack adapter, ensuring absolute isolation, zero-PII leakage, and protection against network tampering or race conditions.

---

## 1. Team & Slack ID Mapping (Server-Side Allowlist)

**Decision:** The Slack Adapter will validate both the `team_id` (trusted installation) and the `user.id` against a strictly enforced, server-side allowlist.
**Mechanism:**
- When a payload arrives, it extracts `user.id` and `team.id`.
- If either does not match the server-side configuration, the action is aggressively rejected with a 403 / ignored.
- The Slack ID is treated as metadata, while execution relies strictly on the `undogate_control` API credentials.

## 2. Strict Target Binding & Immutable Payloads

**Decision:** The public ID, channel, and message target must be strictly bound. 
**Mechanism:**
- Slack payloads are inherently untrusted transport.
- The backend will validate that `action_id`, `public_id`, `channel_id`, and `message_ts` are the correct types and exactly one action is provided.
- Altering the payload (e.g., swapping `public_id` on a different message) must be rejected if state tracking (or DB state) doesn't match the expected checkpoint target.

## 3. Idempotency & Database as Ground Truth

**Decision:** The Slack Adapter delegates concurrency control to the existing PostgreSQL checkpoints system.
**Mechanism:**
- If a double click occurs, Request A and Request B will both dispatch to the API.
- Request B will fail due to `HTTP 409 Conflict` (idempotency constraint violation) or a domain error indicating the checkpoint is no longer `pending`.
- The adapter translates this specifically to an "Already processed" warning on the Slack UI without echoing raw DB error messages.

## 4. Supervised Fire-and-Forget & Crash Gaps

**Decision:** Slack Ack (envelope acknowledgment) must be strictly decoupled from DB execution using a bounded, supervised task manager.
**Mechanism:**
- **Crash Gap:** By ACKing the envelope immediately and delegating to an asynchronous task, there is a risk that the process crashes before the task finishes. This is a documented gap in this offline design.
- **Mitigation:** A supervised task list will track active requests to ensure graceful shutdown (`asyncio.gather` on SIGTERM).
- **Future Production Gaps:** For full durability, a persistent outbox/inbox or checkpoint reconciliation worker must be introduced in a future phase.
- Notification failures (updating the Slack message fails) will NOT rollback the DB transaction, as DB state and Slack UI are distinctly separate.

## 5. Zero-PII & Safe Error Masking

**Decision:** Slack payloads, adapter logs, and UI messages must never contain sensitive data or raw SQL errors.
**Mechanism:**
- Raw `result.message` or SQLSTATE errors from the database will **never** be passed back to the Slack UI.
- All internal DB errors will map to generic codes (e.g., "Internal execution error. See server logs for operation_id: ...").
- This strictly mitigates data leakage via error strings.

## 6. Socket Mode over HTTP Webhooks

**Decision:** The adapter will use **Socket Mode** (WebSocket) in production.
**Justification:**
- Avoids exposing internal tools to inbound internet traffic. 
- The offline design will currently simulate the JSON payloads passed by Socket Mode, without relying on live WebSocket code.
