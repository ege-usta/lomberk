"""Production Slack approval path: pending checkpoints are posted by the built-in
outbox publisher, bindings live in the database (survive restarts), only the bound
(team, channel, ts) authorizes a click, and the approver's Slack ID is audited."""
import asyncio
import json
import logging
import os
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

import lomberk.api
from lomberk.capture.install import install_lomberk
from lomberk.config import LomberkConfig
from lomberk.ee.slack import UnauthorizedUserError
from lomberk.ee.slack_publisher import SlackPublisher
from lomberk.policy import PolicyEngine
from lomberk.sql.classify import classify_sql


class FakeWeb:
    def __init__(self, fail_posts: int = 0):
        self.posts, self.updates, self.fail_posts = [], [], fail_posts

    async def chat_postMessage(self, **kw):
        self.posts.append(kw)
        if self.fail_posts:
            self.fail_posts -= 1
            raise TimeoutError("response lost")
        return {"ts": f"1700000000.{len(self.posts):06d}", "message": {"team": "T1"}}

    async def chat_update(self, **kw):
        self.updates.append(kw)


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        dsn = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        p = urlparse(dsn)

        def as_role(role):
            return urlunparse((p.scheme, f"{role}:secret@{p.hostname}:{p.port}", p.path, "", "", ""))

        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("CREATE ROLE lomberk_control LOGIN PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent LOGIN PASSWORD 'secret'")
        install_lomberk(dsn, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(dsn, autocommit=True) as conn:
            conn.execute("CREATE TABLE public.users (id INT PRIMARY KEY, name TEXT)")
            conn.execute("INSERT INTO public.users VALUES (1, 'alice'), (2, 'bob')")
            conn.execute("SELECT lomberk.register_table('public', 'users', 'id', 'mcp_agent')")
        yield dsn, as_role("lomberk_control"), as_role("mcp_agent")


def hold(executor, sql):
    res = executor.execute(PolicyEngine(LomberkConfig(protected_tables=["public.users"])).evaluate(classify_sql(sql)[0]),
                           principal="agent")
    assert res.status == "approval_required", res.message
    return res.public_id


async def wait_for(pred, timeout=8.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return
        await asyncio.sleep(0.05)
    raise AssertionError("condition not met in time")


def click(public_id, ts, user="U_BOSS", action="approve_button", channel="C_APPROVALS"):
    return {"team": {"id": "T1"}, "user": {"id": user},
            "container": {"channel_id": channel, "message_ts": ts},
            "actions": [{"action_id": action, "value": public_id}]}


@pytest.mark.asyncio
async def test_slack_publish_click_approve_end_to_end(db, monkeypatch, caplog):
    admin, control, agent = db
    monkeypatch.setenv("LOMBERK_ADMIN_DSN", control)
    monkeypatch.setenv("LOMBERK_AGENT_DSN", agent)
    monkeypatch.setenv("LOMBERK_API_KEY", "k-agent")
    monkeypatch.setenv("LOMBERK_ADMIN_KEY", "k-admin")
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_SLACK_APP_TOKEN", "xapp-fake")
    monkeypatch.setenv("LOMBERK_SLACK_BOT_TOKEN", "xoxb-fake")
    cfg = LomberkConfig(protected_tables=["public.users"])
    cfg.slack.admin_allowlist, cfg.slack.team_allowlist, cfg.slack.channel_id = ["U_BOSS"], ["T1"], "C_APPROVALS"
    monkeypatch.setattr(lomberk.api, "load_config", lambda: cfg)
    monkeypatch.setattr("lomberk.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))

    web = FakeWeb()
    app = lomberk.api.app

    def socket_factory(token):
        m = MagicMock()
        m.connect, m.close, m.socket_mode_request_listeners = AsyncMock(), AsyncMock(), []
        return m

    app.state.slack_client_factory = socket_factory
    app.state.slack_web_client_factory = lambda token: web
    try:
        with caplog.at_level(logging.INFO, logger="lomberk_audit"):
            async with lomberk.api.lifespan(app):
                adapter = lomberk.api._slack_transport_instance.business_adapter
                public_id = await asyncio.to_thread(hold, lomberk.api._executor_instance, "DELETE FROM public.users WHERE id = 2")
                await wait_for(lambda: len(web.posts) == 1)
                post = web.posts[0]
                assert post["channel"] == "C_APPROVALS"
                assert "DELETE" not in json.dumps(post), "SQL must not leave for Slack unless include_sql"
                buttons = post["blocks"][1]["elements"]
                assert {b["value"] for b in buttons} == {public_id}
                await wait_for(lambda: web.updates == [] and _state(admin, public_id) == "bound")
                ts = _ts(admin, public_id)

                with pytest.raises(UnauthorizedUserError):
                    await adapter.handle_interaction(click(public_id, ts, user="U_INTERN"))
                # Forged target: right checkpoint id, wrong message -> fail closed, nothing runs
                await adapter.handle_interaction(click(public_id, "1600000000.000001"))
                await asyncio.sleep(0.3)
                assert _status(admin, public_id) == "pending"

                await adapter.handle_interaction(click(public_id, ts))
                await wait_for(lambda: len(web.updates) == 1)
                assert web.updates[0]["ts"] == ts and "successfully applied" in web.updates[0]["text"]
                assert _status(admin, public_id) == "applied"
                await asyncio.sleep(2.5)  # another publisher pass must not re-post
                assert len(web.posts) == 1
    finally:
        for attr in ("slack_client_factory", "slack_web_client_factory"):
            if hasattr(app.state, attr):
                delattr(app.state, attr)

    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == "lomberk_audit"]
    assert ("lomberk.approved", "slack:U_BOSS") in [(e["event_type"], e["actor"]) for e in events]


@pytest.mark.asyncio
async def test_unknown_send_outcome_is_never_resent_and_bindings_survive_restart(db, monkeypatch):
    admin, control, agent = db
    monkeypatch.setattr("lomberk.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))
    from lomberk.executor import LomberkExecutor
    ex = LomberkExecutor(control, agent)
    lost = hold(ex, "UPDATE public.users SET name = 'x' WHERE id = 1")
    ok = hold(ex, "UPDATE public.users SET name = 'y' WHERE id = 1")

    web = FakeWeb(fail_posts=1)
    pub = SlackPublisher(control, web, "C_APPROVALS", {"T1"})
    assert await pub.publish_pending() == 1
    assert await pub.publish_pending() == 0
    assert len(web.posts) == 2, "the lost send must not be retried"
    assert _state(admin, lost) == "unknown" and _state(admin, ok) == "bound"

    restarted = SlackPublisher(control, FakeWeb(), "C_APPROVALS", {"T1"})
    ts = _ts(admin, ok)
    assert await restarted.resolve("T1", "C_APPROVALS", ts) == ok
    assert await restarted.resolve("T2", "C_APPROVALS", ts) is None
    assert await restarted.resolve("T1", "C_OTHER", ts) is None


def _row(dsn, public_id, col):
    with psycopg.connect(dsn) as conn:
        row = conn.execute(f"SELECT {col} FROM lomberk.slack_messages WHERE public_id = %s", (public_id,)).fetchone()
    return row[0] if row else None


def _state(dsn, public_id):
    return _row(dsn, public_id, "state")


def _ts(dsn, public_id):
    return _row(dsn, public_id, "message_ts")


def _status(dsn, public_id):
    with psycopg.connect(dsn) as conn:
        return conn.execute("SELECT status FROM lomberk.checkpoints WHERE public_id = %s", (public_id,)).fetchone()[0]


def test_agent_controlled_fields_cannot_inject_slack_markup():
    import datetime
    evil = "x` <!channel> <https://evil.example|SAFE, click> & `"
    for include_sql in (False, True):
        pub = SlackPublisher("unused", FakeWeb(), "C", {"T1"}, include_sql=include_sql)
        _, blocks = pub._blocks("cp_1", evil, evil, evil, f"SELECT '{evil}'",
                                datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC))
        text = blocks[0]["text"]["text"]
        assert "<!" not in text and "<http" not in text, text
        agent_line = text.splitlines()[1]
        assert agent_line.count("`") == 2, agent_line  # label cannot close its code span
        assert "&lt;!channel&gt;" in text


def test_preview_reaches_slack_as_counts_only():
    import datetime
    preview = {"rows": 3, "tables": {"public.users": 1, "public.payments": 2}, "truncated": False,
               "sample": [{"table": "public.users", "op": "delete", "key": {"id": "1"}, "row": {"email": "a@secret.io"}}]}
    pub = SlackPublisher("unused", FakeWeb(), "C", {"T1"})
    _, blocks = pub._blocks("cp_1", "agent", "p", "WRITE_DML", "DELETE FROM public.users WHERE id = 1",
                            datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC), preview)
    text = blocks[0]["text"]["text"]
    assert "Would change *3* row(s): `public.users` (1), `public.payments` (2)" in text
    assert "a@secret.io" not in text  # row values never leave for Slack
