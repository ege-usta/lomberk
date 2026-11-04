"""Posts pending checkpoints to Slack and owns the durable message bindings.

Outbox pattern: pending checkpoints are claimed in the database (one row per
checkpoint, so several gateway replicas never double-post), then posted with
chat.postMessage. A send whose outcome is unknown is marked `unknown` and never
re-sent; an operator reconciles it.
Only the bot's own messages are ever updated (chat:write scope).
"""
import asyncio
import logging

import psycopg

logger = logging.getLogger("rowback.ee.slack_publisher")

SQL_PREVIEW_CHARS = 1500
STALE_CLAIM = "2 minutes"  # a claim this old outlived its sender (crash/restart)


def _esc(value) -> str:
    """Slack mrkdwn escaping (api.slack.com/reference/surfaces/formatting#escaping):
    agent-controlled text must never render as a link, mention or broadcast."""
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline(value) -> str:
    return _esc(value).replace("`", "'")  # cannot close the surrounding code span


class SlackPublisher:
    def __init__(self, dsn: str, web_client, channel_id: str, team_allowlist: set[str],
                 include_sql: bool = False, poll_seconds: float = 2.0, batch_size: int = 20):
        self.dsn = dsn
        self.web = web_client
        self.channel_id = channel_id
        self.team_allowlist = set(team_allowlist)
        self.include_sql = include_sql
        self.poll_seconds = poll_seconds
        self.batch_size = batch_size

    # -- database (sync, run in a thread) ------------------------------------
    def _claim_batch(self) -> list[tuple]:
        with psycopg.connect(self.dsn) as conn:
            conn.execute(
                f"UPDATE rowback.slack_messages SET state = 'unknown' "
                f"WHERE state = 'publishing' AND claimed_at < now() - interval '{STALE_CLAIM}'")  # STALE_CLAIM is a module constant  # nosec B608
            return conn.execute("""
                WITH claimed AS (
                    INSERT INTO rowback.slack_messages (public_id, channel_id, state)
                    SELECT c.public_id, %s, 'publishing' FROM rowback.checkpoints c
                    WHERE c.status = 'pending'
                      AND NOT EXISTS (SELECT 1 FROM rowback.slack_messages m WHERE m.public_id = c.public_id)
                    ORDER BY c.id LIMIT %s
                    ON CONFLICT DO NOTHING
                    RETURNING public_id
                )
                SELECT c.public_id, c.agent_label, c.principal, c.classification, c.sql_text, c.created_at, p.preview
                FROM rowback.checkpoints c JOIN claimed USING (public_id)
                LEFT JOIN rowback.previews p USING (public_id) ORDER BY c.id
            """, (self.channel_id, self.batch_size)).fetchall()

    def _record(self, public_id: str, state: str, team_id: str | None = None, ts: str | None = None) -> None:
        with psycopg.connect(self.dsn) as conn:
            conn.execute(
                "UPDATE rowback.slack_messages SET state = %s, team_id = %s, message_ts = %s WHERE public_id = %s",
                (state, team_id, ts, public_id))

    def _lookup(self, team_id: str, channel_id: str, ts: str) -> str | None:
        with psycopg.connect(self.dsn) as conn:
            row = conn.execute(
                "SELECT public_id FROM rowback.slack_messages "
                "WHERE team_id = %s AND channel_id = %s AND message_ts = %s AND state = 'bound'",
                (team_id, channel_id, ts)).fetchone()
        return row[0] if row else None

    # -- Slack ---------------------------------------------------------------
    def _blocks(self, public_id, agent_label, principal, classification, sql_text, created_at, preview=None) -> tuple[str, list]:
        text = f"Rowback approval needed: {public_id}"
        detail = (f"*Approval needed* `{public_id}`\n"
                  f"Agent: `{_inline(agent_label)}` ({_inline(principal)}) · {_inline(classification)} · {created_at:%Y-%m-%d %H:%M:%S %Z}")
        if preview:
            # Counts only: row values stay out of Slack, like SQL does unless include_sql is set.
            tables = ", ".join(f"`{_inline(t)}` ({int(n)})" for t, n in preview["tables"].items())
            detail += f"\nWould change *{int(preview['rows'])}* row(s): {tables}"
        if self.include_sql:
            preview = sql_text if len(sql_text) <= SQL_PREVIEW_CHARS else sql_text[:SQL_PREVIEW_CHARS] + " …"
            detail += f"\n```{_esc(preview).replace('```', '` ` `')}```"
        else:
            detail += f"\nReview the SQL before deciding: `rowback show {public_id}`"
        return text, [
            {"type": "section", "text": {"type": "mrkdwn", "text": detail}},
            {"type": "actions", "elements": [
                {"type": "button", "action_id": "approve_button", "style": "primary",
                 "text": {"type": "plain_text", "text": "Approve"}, "value": public_id},
                {"type": "button", "action_id": "reject_button", "style": "danger",
                 "text": {"type": "plain_text", "text": "Reject"}, "value": public_id},
            ]},
        ]

    async def publish_pending(self) -> int:
        """One outbox pass. Returns how many messages were bound."""
        bound = 0
        for row in await asyncio.to_thread(self._claim_batch):
            public_id = row[0]
            text, blocks = self._blocks(*row)
            try:
                resp = await self.web.chat_postMessage(channel=self.channel_id, text=text, blocks=blocks)
                ts = resp["ts"]
                team = (resp.get("message") or {}).get("team")
                if not team and len(self.team_allowlist) == 1:
                    team = next(iter(self.team_allowlist))
                if not ts or not team:
                    raise ValueError("Slack response lacked message ts/team")
            except Exception as e:
                logger.error("Slack publish outcome unknown for %s (%s); not retrying", public_id, type(e).__name__)
                await asyncio.to_thread(self._record, public_id, "unknown")
                continue
            await asyncio.to_thread(self._record, public_id, "bound", team, ts)
            bound += 1
        return bound

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await self.publish_pending()
            except Exception as e:
                logger.error("Slack publisher pass failed: %s", type(e).__name__)
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.poll_seconds)
            except TimeoutError:
                pass

    # -- adapter callbacks ---------------------------------------------------
    async def resolve(self, team_id: str, channel_id: str, ts: str) -> str | None:
        return await asyncio.to_thread(self._lookup, team_id, channel_id, ts)

    async def update(self, channel_id: str, ts: str, text: str) -> None:
        # Replacing blocks removes the buttons; the message reflects the authoritative DB state.
        await self.web.chat_update(channel=channel_id, ts=ts, text=text,
                                   blocks=[{"type": "section", "text": {"type": "mrkdwn", "text": text}}])
