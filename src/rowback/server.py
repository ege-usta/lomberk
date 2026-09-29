import json
import os
import sys
from collections.abc import Callable

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from rowback.config import load_config
from rowback.executor import ExecutionResult, RowbackExecutor
from rowback.policy import PolicyEngine
from rowback.sentinel import AISentinel
from rowback.sql.classify import classify_sql


def format_result(res: ExecutionResult) -> str:
    if res.status == "applied":
        msg = "Success." if res.public_id is None else f"Success. Checkpoint: {res.public_id}. Rows affected: {res.rows_affected}."
        if res.data is not None:
            msg += f"\nData: {json.dumps(res.data, default=str)}"
        return msg
    if res.status == "approval_required":
        return f"APPROVAL REQUIRED. Token: {res.public_id}. {res.message} A human must approve it out of band; do not retry."
    if res.status == "denied":
        return f"DENIED: {res.message}"
    return f"FAILED: {res.message}"


def run_agent_sql(executor: RowbackExecutor, policy_engine: PolicyEngine, sql: str, operation_id: str | None, principal: str) -> str:
    """Single agent entrypoint shared by the stdio and HTTP MCP transports."""
    try:
        safe, reason = AISentinel()._ast_firewall(sql)
        if not safe:
            return f"Hard Gate Denied: {reason}"
        statements = classify_sql(sql)
        if not statements:
            return "Success (no statements executed)."
        results = []
        for stmt in statements:
            res = executor.execute(policy_engine.evaluate(stmt), agent_label=principal, principal=principal, operation_id=operation_id)
            results.append(format_result(res))
        return "\n".join(results)
    except Exception as e:  # noqa: BLE001 - a tool must answer the agent, never crash the session
        return f"Error executing SQL: {e}"


def build_mcp(get_deps: Callable[[], tuple[RowbackExecutor, PolicyEngine]], principal: str = "mcp_agent") -> MCPServer:
    app = MCPServer("rowback")

    @app.tool()
    def execute_sql(
        sql: str = Field(description="One PostgreSQL statement. Writes must be schema-qualified and have a WHERE clause."),
        operation_id: str | None = Field(default=None, description="Optional idempotency key (client-generated UUID). Retries with the same operation_id are safely idempotent."),
    ) -> str:
        """Executes a SQL statement with Rowback protection. Large or sensitive writes are held for human approval; every applied write can be undone."""
        executor, policy_engine = get_deps()
        return run_agent_sql(executor, policy_engine, sql, operation_id, principal)

    return app


def build_executor() -> tuple[RowbackExecutor, PolicyEngine]:
    config = load_config()
    dsn = os.environ.get(config.database.agent_dsn_env)
    admin_dsn = os.environ.get(config.database.admin_dsn_env)
    if not dsn or not admin_dsn:
        raise ValueError(f"Database DSNs must be provided via {config.database.agent_dsn_env} and {config.database.admin_dsn_env}")
    executor = RowbackExecutor(
        admin_dsn, dsn,
        max_rows_without_approval=config.limits.max_rows_without_approval,
        approval_timeout_minutes=config.agent.approval_timeout_minutes,
        protected_tables=config.protected_tables,
        statement_timeout_ms=config.limits.statement_timeout_ms,
    )
    return executor, PolicyEngine(config)


def main() -> None:
    try:
        deps = build_executor()
    except ValueError as e:
        print(f"Startup Refusal: {e}", file=sys.stderr)
        sys.exit(1)
    build_mcp(lambda: deps).run()


if __name__ == "__main__":
    main()
