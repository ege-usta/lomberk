"""What the MCP server tells a client about itself."""
import asyncio
from importlib.metadata import version

from rowback.api import app as rest_app
from rowback.server import build_mcp, package_version


def test_mcp_and_rest_report_the_installed_version():
    assert package_version() == version("rowback")
    assert rest_app.version == version("rowback")
    mcp = build_mcp(lambda: (None, None))
    assert mcp.version == version("rowback") and mcp.title == "Rowback"
    tools = asyncio.run(mcp.list_tools())
    assert [t.name for t in tools] == ["execute_sql"]
