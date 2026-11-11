import json
import os
import sys
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version

from mcp.server.mcpserver import MCPServer
from pydantic import Field

from lomberk.config import load_config
from lomberk.executor import ExecutionResult, LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.sentinel import AISentinel
from lomberk.sql.classify import classify_sql
from lomberk.startup import check_config, check_db_roles, new_executor, resolve_plan


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


def run_agent_sql(executor: LomberkExecutor, policy_engine: PolicyEngine, sql: str, operation_id: str | None, principal: str) -> str:
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
    except Exception as e:
        return f"Error executing SQL: {e}"


def package_version() -> str:
    """The installed Lomberk version, reported to MCP clients and the REST API."""
    try:
        return version("lomberk")
    except PackageNotFoundError:  # running from a source tree that was never installed
        return "0+unknown"


def build_mcp(get_deps: Callable[[], tuple[LomberkExecutor, PolicyEngine]], principal: str = "mcp_agent") -> MCPServer:
    app = MCPServer("lomberk", title="Lomberk", website_url="https://ege-usta.github.io/lomberk/", version=package_version())

    @app.tool()
    def execute_sql(
        sql: str = Field(description="One PostgreSQL statement. Writes must be schema-qualified and have a WHERE clause."),
        operation_id: str | None = Field(default=None, description="Optional idempotency key (client-generated UUID). Retries with the same operation_id are safely idempotent."),
    ) -> str:
        """Executes a SQL statement with Lomberk protection. Large or sensitive writes are held for human approval; every applied write can be undone."""
        executor, policy_engine = get_deps()
        return run_agent_sql(executor, policy_engine, sql, operation_id, principal)

    return app


def build_executor() -> tuple[LomberkExecutor, PolicyEngine]:
    """The same refusals as the HTTP gateway: a valid license for Pro features, two distinct non-superuser roles."""
    config = load_config()
    dsn = os.environ.get(config.database.agent_dsn_env)
    admin_dsn = os.environ.get(config.database.admin_dsn_env)
    if not dsn or not admin_dsn:
        raise ValueError(f"Startup Refusal: Database DSNs must be provided via {config.database.agent_dsn_env} and {config.database.admin_dsn_env}")
    check_config(config)
    plan = resolve_plan(config)
    check_db_roles(admin_dsn, dsn)
    return new_executor(config, admin_dsn, dsn, plan), PolicyEngine(config)


def main() -> None:
    try:
        deps = build_executor()
    except Exception as e:  # LicenseError, ValueError, a DB that can't be reached: one line, not a traceback
        msg = str(e) if str(e).startswith("Startup Refusal") else f"Startup Refusal: {e}"
        print(msg, file=sys.stderr)
        sys.exit(1)
    build_mcp(lambda: deps).run()


if __name__ == "__main__":
    main()
