import psycopg
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from testcontainers.community.postgres import PostgresContainer

from undogate.capture.install import install_undogate
from undogate.executor import UndogateExecutor


@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer("postgres:16-alpine") as postgres:
        yield postgres

@pytest.fixture(scope="module")
def dsn(postgres):
    return postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")

@pytest.fixture(scope="module")
def runtime_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"mcp_agent:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn, runtime_dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    
    install_undogate(dsn, agent_role="mcp_agent")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE public.users (
                id SERIAL PRIMARY KEY,
                data TEXT
            );
            CREATE TABLE public.unprotected (
                id SERIAL PRIMARY KEY,
                data TEXT
            );
        """)
        cur.execute("INSERT INTO public.users (data) VALUES ('test_admin');")
        cur.execute("SELECT undogate.register_table('public', 'users', 'id', 'mcp_agent');")

@pytest.mark.asyncio
async def test_mcp_execute_unregistered_fails(dsn, runtime_dsn, setup_db):
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "src/undogate/cli.py", "serve"],
        env={"UNDOGATE_AGENT_DSN": runtime_dsn}
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            res = await session.call_tool("execute_sql", {"sql": "INSERT INTO public.unprotected (data) VALUES ('mcp_test');"})
            text = res.content[0].text
            assert "FAILED" in text or "invalid state transition" in text
            assert "not registered" in text or "permission denied" in text or "invalid state transition" in text
            
            with psycopg.connect(dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT count(*) FROM public.unprotected WHERE data = 'mcp_test'")
                    assert cur.fetchone()[0] == 0

@pytest.mark.asyncio
async def test_mcp_execute_require_approval(dsn, runtime_dsn, setup_db):
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "src/undogate/cli.py", "serve"],
        env={"UNDOGATE_AGENT_DSN": runtime_dsn}
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            res = await session.call_tool("execute_sql", {"sql": "UPDATE public.users SET data = 'mcp_test2' WHERE id = 1;"})
            text = res.content[0].text
            assert "APPROVAL REQUIRED" in text
            
            import re
            match = re.search(r"Token: (cp_[a-z0-9]+)", text)
            assert match is not None
            token = match.group(1)
            
            # Row should still be the old value before approval
            with psycopg.connect(dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT data FROM public.users WHERE id = 1")
                assert cur.fetchone()[0] == 'test_admin'
            
            executor = UndogateExecutor(dsn)
            exec_res = executor.execute_pending(token)
            assert exec_res.status == "applied"
            
            # Row should be updated after approval
            with psycopg.connect(dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT data FROM public.users WHERE id = 1")
                assert cur.fetchone()[0] == 'mcp_test2'
