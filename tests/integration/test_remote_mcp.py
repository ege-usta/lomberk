"""Enterprise deployment model: the gateway runs as its own service and the agent
holds only a URL + agent key. Verifies the remote MCP endpoint end to end over real
HTTP, and that the agent key can neither approve nor undo."""
import socket
import threading
import time
from urllib.parse import urlparse, urlunparse

import httpx2
import psycopg
import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback

AGENT_KEY = "agent-key-remote-test"
ADMIN_KEY = "admin-key-remote-test"


@pytest.fixture(scope="module")
def gateway(tmp_path_factory):
    with PostgresContainer("postgres:16-alpine") as pg:
        dsn = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        p = urlparse(dsn)

        def as_role(role):
            return urlunparse((p.scheme, f"{role}:secret@{p.hostname}:{p.port}", p.path, "", "", ""))

        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE ROLE rowback_control LOGIN PASSWORD 'secret'")
            cur.execute("CREATE ROLE mcp_agent LOGIN PASSWORD 'secret'")
        install_rowback(dsn, control_role="rowback_control", agent_role="mcp_agent")
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE TABLE public.accounts (id INT PRIMARY KEY, balance INT)")
            cur.execute("INSERT INTO public.accounts SELECT g, 100 FROM generate_series(1, 30) g")
            cur.execute("SELECT rowback.register_table('public', 'accounts', 'id', 'mcp_agent')")

        mp = pytest.MonkeyPatch()
        cfg = tmp_path_factory.mktemp("cfg")
        (cfg / "rowback.yaml").write_text("limits:\n  max_rows_without_approval: 5\n")
        mp.chdir(cfg)
        mp.setenv("ROWBACK_ADMIN_DSN", as_role("rowback_control"))
        mp.setenv("ROWBACK_AGENT_DSN", as_role("mcp_agent"))
        mp.setenv("ROWBACK_API_KEY", AGENT_KEY)
        mp.setenv("ROWBACK_ADMIN_KEY", ADMIN_KEY)
        mp.setattr("rowback.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))

        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config("rowback.api:app", host="127.0.0.1", port=port, log_level="warning"))
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                if httpx2.get(f"{base}/readyz").status_code == 200:
                    break
            except httpx2.TransportError:
                pass
            time.sleep(0.1)
        else:
            raise RuntimeError("gateway did not become ready")
        yield base, dsn
        server.should_exit = True
        thread.join(timeout=5)
        mp.undo()


async def call(base, key, sql):
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=30) as http,
        streamable_http_client(f"{base}/mcp", http_client=http) as streams,
        ClientSession(streams[0], streams[1]) as session,
    ):
        await session.initialize()
        res = await session.call_tool("execute_sql", {"sql": sql})
        return res.content[0].text


def test_health_probes(gateway):
    base, _ = gateway
    assert httpx2.get(f"{base}/healthz").json() == {"status": "ok"}
    assert httpx2.get(f"{base}/readyz").json() == {"status": "ready"}


@pytest.mark.parametrize("key", [None, "wrong-key", ADMIN_KEY])
def test_mcp_endpoint_rejects_missing_or_wrong_agent_key(gateway, key):
    base, _ = gateway
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    r = httpx2.post(f"{base}/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_remote_agent_read_and_small_write(gateway):
    base, _ = gateway
    out = await call(base, AGENT_KEY, "SELECT count(*) AS n FROM public.accounts")
    assert '"n": 30' in out, out
    out = await call(base, AGENT_KEY, "UPDATE public.accounts SET balance = 99 WHERE id = 1")
    assert out.startswith("Success."), out


@pytest.mark.asyncio
async def test_remote_mass_write_held_agent_cannot_approve_admin_can_undo(gateway):
    base, dsn = gateway
    out = await call(base, AGENT_KEY, "UPDATE public.accounts SET balance = 0 WHERE 1=1")
    assert out.startswith("APPROVAL REQUIRED"), out
    token = out.split("Token: ")[1].split(".")[0]

    with psycopg.connect(dsn) as conn:
        assert conn.execute("SELECT count(*) FROM public.accounts WHERE balance = 0").fetchone()[0] == 0

    for path in ("approve", "undo"):
        r = httpx2.post(f"{base}/v1/checkpoints/{token}/{path}", headers={"X-API-Key": AGENT_KEY})
        assert r.status_code == 403, (path, r.text)

    r = httpx2.post(f"{base}/v1/checkpoints/{token}/approve", headers={"X-API-Key": ADMIN_KEY})
    assert r.json() == {"status": "approved", "rows_affected": 30}, r.text
    r = httpx2.post(f"{base}/v1/checkpoints/{token}/undo", headers={"X-API-Key": ADMIN_KEY})
    assert r.json()["status"] == "undone", r.text
    r = httpx2.post(f"{base}/v1/checkpoints/{token}/undo", headers={"X-API-Key": ADMIN_KEY})
    assert r.status_code == 409

    with psycopg.connect(dsn) as conn:
        assert conn.execute("SELECT count(*) FROM public.accounts WHERE balance = 0").fetchone()[0] == 0
