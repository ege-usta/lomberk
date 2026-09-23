from mcp.server.mcpserver import MCPServer
app = MCPServer("test")

@app.tool()
def add(a: int, b: int) -> int:
    return a + b

print(app)
