import os
import sys

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from undogate.config import load_config
from undogate.executor import UndogateExecutor
from undogate.policy import PolicyEngine
from undogate.sql.classify import classify_sql

app = MCPServer("undogate")
config = load_config()

agent_dsn_env = config.database.agent_dsn_env
agent_dsn = os.environ.get(agent_dsn_env, os.environ.get("UNDOGATE_ADMIN_DSN"))

if not agent_dsn:
    print(f"Error: Database DSN must be provided via {agent_dsn_env} or UNDOGATE_ADMIN_DSN env var.", file=sys.stderr)
    sys.exit(1)

executor = UndogateExecutor(agent_dsn)
policy_engine = PolicyEngine(config)

@app.tool()
def execute_sql(sql: str = Field(description="The SQL statement to execute on the PostgreSQL database.")) -> str:
    """Executes a SQL statement with Undogate protection."""
    try:
        statements = classify_sql(sql)
        if not statements:
             return "Success (no statements executed)."
             
        results = []
        for stmt in statements:
            eval_result = policy_engine.evaluate(stmt)
            res = executor.execute(eval_result, agent_label="mcp_agent")
            
            if res.status == "applied":
                results.append(f"Success. Checkpoint: {res.public_id}. Rows affected: {res.rows_affected}.")
            elif res.status == "approval_required":
                results.append(f"APPROVAL REQUIRED. Token: {res.public_id}. Ask human to run `undogate approve {res.public_id}` in their terminal.")
            elif res.status == "denied":
                results.append(f"DENIED: {res.message}")
            else:
                results.append(f"FAILED: {res.message}")
                
        return "\n".join(results)
        
    except Exception as e:
         return f"Error executing SQL: {e}"

if __name__ == "__main__":
    app.run()
