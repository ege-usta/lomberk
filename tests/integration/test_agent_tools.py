"""The agent's own tools: what it may see of its writes and tables, and waiting for a human's decision."""
import asyncio
import os
import re

import psycopg
import pytest
from mcp import Client
from testcontainers.community.postgres import PostgresContainer

from lomberk.capture.install import install_lomberk
from lomberk.config import LomberkConfig
from lomberk.executor import LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.server import build_mcp


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE lomberk_control LOGIN PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent LOGIN PASSWORD 'secret'")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE TABLE public.orders (id INT PRIMARY KEY, total INT, api_token TEXT)")
            conn.execute("INSERT INTO public.orders SELECT g, g * 10, 'x' FROM generate_series(1, 5) g")
            conn.execute("SELECT lomberk.register_table('public', 'orders', 'id', 'mcp_agent', ARRAY['api_token'])")
            conn.execute("CREATE TABLE public.notes (id INT PRIMARY KEY, body TEXT)")
            conn.execute("SELECT lomberk.register_table('public', 'notes', 'id', 'mcp_agent')")
        host = url.split("@", 1)[1]
        yield f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


def server(db, principal="mcp_agent"):
    control, agent = db
    config = LomberkConfig(protected_tables=["public.orders"], limits={"max_rows_without_approval": 3})
    executor = LomberkExecutor(control, agent, max_rows_without_approval=3, protected_tables=config.protected_tables)
    return build_mcp(lambda: (executor, PolicyEngine(config)), principal=principal), executor


async def call(client, tool, **args):
    return (await client.call_tool(tool, args)).content[0].text


def test_describe_tables_shows_only_what_the_agent_can_use(db):
    mcp, _ = server(db)

    async def run():
        async with Client(mcp) as c:
            return await call(c, "describe_tables")
    out = asyncio.run(run())
    assert "public.orders (key id) [protected" in out and "id integer, total integer; 1 column(s) hidden" in out
    assert "public.notes (key id): id integer, body text" in out and "more than 3 row(s)" in out
    assert "api_token" not in out


def test_wait_for_approval_returns_the_decision(db):
    mcp, executor = server(db)
    progress = []

    async def run():
        async with Client(mcp) as c:
            held = await call(c, "execute_sql", sql="UPDATE public.orders SET total = 0 WHERE id = 1")
            assert "APPROVAL REQUIRED" in held and "wait_for_approval" in held
            token = re.search(r"cp_[a-z0-9]+", held).group(0)
            assert "waiting for a human to approve" in await call(c, "checkpoint_status", token=token)
            timed_out = await call(c, "wait_for_approval", token=token, timeout_seconds=1)
            assert "Still waiting after 1 s" in timed_out and f"lomberk approve {token}" in timed_out

            async def approve_soon():
                await asyncio.sleep(1)
                await asyncio.to_thread(executor.execute_pending, token, "human")
            approver = asyncio.create_task(approve_soon())
            res = await c.call_tool("wait_for_approval", {"token": token, "timeout_seconds": 20},
                                    progress_callback=lambda p, t, m: progress.append(m) or asyncio.sleep(0))
            await approver
            return token, res.content[0].text, await call(c, "list_my_changes")
    token, done, changes = asyncio.run(run())
    assert f"{token}" in done and "applied, 1 row(s)" in done and f"lomberk undo {token}" in done
    assert progress and token in progress[0]
    assert token in changes and "UPDATE public.orders SET total = 0 WHERE id = 1" in changes


def test_an_agent_sees_only_its_own_checkpoints(db):
    mine, _ = server(db, principal="agent_a")
    theirs, _ = server(db, principal="agent_b")

    async def run():
        async with Client(mine) as a, Client(theirs) as b:
            held = await call(a, "execute_sql", sql="UPDATE public.orders SET total = 1 WHERE id = 2")
            token = re.search(r"cp_[a-z0-9]+", held).group(0)
            return (token, await call(b, "checkpoint_status", token=token), await call(b, "list_my_changes"),
                    await call(b, "wait_for_approval", token=token, timeout_seconds=1))
    token, status, changes, waited = asyncio.run(run())
    assert status == waited == f"No checkpoint {token} was made by this agent."
    assert changes == "You haven't made any writes through Lomberk yet."
