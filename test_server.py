import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    server_params = StdioServerParameters(
        command="uv",
        args=["run", "python", "src/undogate/server.py"],
        env={"UNDOGATE_ADMIN_DSN": "postgresql://test:test@localhost/test"}
    )
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            print("Initialized")
            tools = await session.list_tools()
            print([t.name for t in tools.tools])

asyncio.run(main())
