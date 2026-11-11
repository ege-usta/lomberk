"""What the MCP server tells a client about itself."""
import asyncio
from importlib.metadata import version

from lomberk.api import app as rest_app
from lomberk.server import build_mcp, package_version


def test_mcp_and_rest_report_the_installed_version():
    assert package_version() == version("lomberk")
    assert rest_app.version == version("lomberk")
    mcp = build_mcp(lambda: (None, None))
    assert mcp.version == version("lomberk") and mcp.title == "Lomberk"
    tools = asyncio.run(mcp.list_tools())
    assert [t.name for t in tools] == ["execute_sql", "describe_tables", "checkpoint_status", "list_my_changes", "wait_for_approval"]
