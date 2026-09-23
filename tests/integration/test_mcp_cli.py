
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
def setup_db(dsn):
    install_undogate(dsn)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                CREATE TABLE public.test_mcp (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                );
            """)
        cur.execute("SELECT undogate.attach_trigger_to_table('public', 'test_mcp');")

@pytest.mark.asyncio
async def test_mcp_execute_allow(dsn, setup_db):
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "src/undogate/cli.py", "serve"],
        env={"UNDOGATE_ADMIN_DSN": dsn}
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            res = await session.call_tool("execute_sql", {"sql": "INSERT INTO public.test_mcp (data) VALUES ('mcp_test');"})
            text = res.content[0].text
            assert "Success" in text
            assert "Rows affected: 1" in text
            
            with psycopg.connect(dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT count(*) FROM public.test_mcp WHERE data = 'mcp_test'")
                    assert cur.fetchone()[0] == 1

@pytest.mark.asyncio
async def test_mcp_execute_require_approval(dsn, setup_db):
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "src/undogate/cli.py", "serve"],
        env={"UNDOGATE_ADMIN_DSN": dsn}
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # DROP TABLE requires approval
            res = await session.call_tool("execute_sql", {"sql": "DROP TABLE public.test_mcp;"})
            text = res.content[0].text
            assert "APPROVAL REQUIRED" in text
            
            # Extract token
            import re
            match = re.search(r"Token: (cp_[a-z0-9]+)", text)
            assert match is not None
            token = match.group(1)
            
            # Verify table still exists
            with psycopg.connect(dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'test_mcp'")
                    assert cur.fetchone()[0] == 1
                    
            # Test CLI approve programmatically
            executor = UndogateExecutor(dsn)
            exec_res = executor.execute_pending(token)
            assert exec_res.status == "applied"
            
            # Verify table dropped
            with psycopg.connect(dsn) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'test_mcp'")
                    assert cur.fetchone()[0] == 0
