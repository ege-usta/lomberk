import os
import sys

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from undogate.config import load_config
from undogate.executor import UndogateExecutor
from undogate.policy import PolicyEngine
from undogate.sql.classify import classify_sql
from undogate.sentinel import AISentinel

_executor_instance = None
_policy_engine_instance = None

def get_executor():
    global _executor_instance, _policy_engine_instance
    if _executor_instance is None:
        config = load_config()
        dsn = os.environ.get(config.database.agent_dsn_env)
        if not dsn:
            raise ValueError(f"Database DSN must be provided via {config.database.agent_dsn_env}")
        _executor_instance = UndogateExecutor(dsn)
        _policy_engine_instance = PolicyEngine(config)
    return _executor_instance, _policy_engine_instance

# Fail at startup if config is missing
try:
    get_executor()
except ValueError as e:
    print(f"Startup Refusal: {e}", file=sys.stderr)
    sys.exit(1)

app = MCPServer("undogate")


@app.tool()
def execute_sql(sql: str = Field(description="The SQL statement to execute on the PostgreSQL database.")) -> str:
    """Executes a SQL statement with Undogate protection."""
    try:
        try:
            executor, policy_engine = get_executor()
        except ValueError as e:
            return f"Error: {str(e)}"
            
        sentinel = AISentinel()
        safe, reason = sentinel._ast_firewall(sql)
        if not safe:
            return f"Hard Gate Denied: {reason}"

        statements = classify_sql(sql)
        if not statements:
             return "Success (no statements executed)."
             
        results = []
        for stmt in statements:
            eval_result = policy_engine.evaluate(stmt)
            res = executor.execute(eval_result, agent_label="mcp_agent")
            
            if res.status == "applied":
                msg = f"Success. Checkpoint: {res.public_id}. Rows affected: {res.rows_affected}."
                if res.data is not None:
                    import json
                    msg += f"\nData: {json.dumps(res.data, default=str)}"
                results.append(msg)
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
    try:
        app.run()
    finally:
        if _executor_instance and hasattr(_executor_instance, 'pool'):
            _executor_instance.pool.close()