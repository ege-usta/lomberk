import json
import os
import sys
import time
from collections.abc import Callable
from importlib.metadata import PackageNotFoundError, version

import anyio
from mcp.server.mcpserver import Context, MCPServer
from pydantic import Field

from lomberk.config import load_config
from lomberk.executor import ExecutionResult, LomberkExecutor, _agent_message
from lomberk.policy import PolicyEngine
from lomberk.sentinel import AISentinel
from lomberk.sql.classify import classify_sql, is_secret
from lomberk.startup import check_config, check_db_roles, new_executor, resolve_plan


def format_result(res: ExecutionResult) -> str:
    if res.status == "applied":
        msg = "Success." if res.public_id is None else f"Success. Checkpoint: {res.public_id}. Rows affected: {res.rows_affected}."
        if res.data is not None:
            msg += f"\nData: {json.dumps(res.data, default=str)}"
        return msg
    if res.status == "approval_required":
        return (f"APPROVAL REQUIRED. Token: {res.public_id}. {res.message} A human must approve it out of band "
                f"(`lomberk approve {res.public_id}`); do not retry. Call wait_for_approval with this token to wait for the decision.")
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
        return f"Error executing SQL: {_agent_message(e)}"


# Statuses a held write passes through before a human's decision is final.
WAITING = ("pending", "approved", "executing")
POLL_SECONDS = 2


def describe_checkpoint(cp: dict) -> str:
    """One checkpoint as the agent should read it: what happened and what it can do next."""
    head = f"{cp['public_id']} ({cp['created_at']:%Y-%m-%d %H:%M %z}, {cp['classification']}): "
    status = cp["status"]
    if status == "pending" and cp.get("expired"):
        return head + "expired: no human approved it in time. Don't resubmit it unchanged; ask the user what they want."
    if status == "pending":
        got, need = cp["approvals"], cp["required_approvals"] or 1
        return head + (f"waiting for a human ({got} of {need} approvals)." if need > 1 else "waiting for a human to approve.")
    if status in ("approved", "executing"):
        return head + "approved, running now."
    if status == "applied":
        return head + f"applied, {cp['rows_affected'] or 0} row(s). A human can undo it with `lomberk undo {cp['public_id']}`."
    if status == "rejected":
        return head + "rejected or expired. Don't resubmit it unchanged; ask the user what they want."
    if status == "undone":
        return head + "undone by a human."
    return head + f"{status}."


def _sql_line(text: str, limit: int = 160) -> str:
    one = " ".join(text.split())
    return one if len(one) <= limit else one[:limit - 1] + "…"


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
        """Executes a SQL statement with Lomberk protection. Destructive SQL is refused, large or sensitive writes are held for human approval, and applied writes to registered tables can be undone within the plan's undo window."""
        executor, policy_engine = get_deps()
        return run_agent_sql(executor, policy_engine, sql, operation_id, principal)

    @app.tool()
    def describe_tables() -> str:
        """Lists the tables you can read and write through Lomberk, their columns, and which writes wait for a human."""
        try:
            executor, policy_engine = get_deps()
            config = policy_engine.config
            tables = executor.describe_tables()
        except Exception as e:
            return f"Error: {_agent_message(e)}"
        if not tables:
            return "No tables are registered with Lomberk yet, so you can't read or write any. Ask the user to run `lomberk register`."
        limit = config.limits.max_rows_without_approval
        lines = [f"Writes touching more than {limit} row(s) wait for a human. Writes need a WHERE clause and schema-qualified names."]
        for t in tables:
            cols = [c for c in t["columns"] or [] if not is_secret(c.split(" ", 1)[0], config.sensitive_columns)]
            hidden = t["hidden"] + len(t["columns"] or []) - len(cols)
            flags = " [protected: every write waits for a human]" if t["name"] in config.protected_tables else ""
            lines.append(f"- {t['name']} (key {t['pk']}){flags}: {', '.join(cols)}"
                         + (f"; {hidden} column(s) hidden" if hidden else ""))
        return "\n".join(lines)

    @app.tool()
    def checkpoint_status(
        token: str = Field(description="A checkpoint or approval token (cp_...) that execute_sql returned."),
    ) -> str:
        """Tells you what happened to one of your writes: waiting, applied, rejected or undone."""
        try:
            executor, _ = get_deps()
            found = executor.agent_checkpoints(principal, public_id=token, limit=1)
        except Exception as e:
            return f"Error: {_agent_message(e)}"
        return describe_checkpoint(found[0]) if found else f"No checkpoint {token} was made by this agent."

    @app.tool()
    def list_my_changes(
        limit: int = Field(default=20, ge=1, le=100, description="How many of your most recent writes to list."),
    ) -> str:
        """Lists your recent writes, newest first, with each checkpoint token and its status."""
        try:
            executor, _ = get_deps()
            found = executor.agent_checkpoints(principal, limit=limit)
        except Exception as e:
            return f"Error: {_agent_message(e)}"
        if not found:
            return "You haven't made any writes through Lomberk yet."
        return "\n".join(f"- {describe_checkpoint(cp)}\n  {_sql_line(cp['sql_text'])}" for cp in found)

    @app.tool()
    async def wait_for_approval(
        ctx: Context,
        token: str = Field(description="The approval token (cp_...) from an APPROVAL REQUIRED reply."),
        timeout_seconds: int = Field(default=50, ge=1, le=600, description=(
            "How long to wait. Many clients cancel a tool call after about 60 seconds; call again to keep waiting.")),
    ) -> str:
        """Waits for a human to approve or reject a held write, then says whether it was applied."""
        try:
            executor, _ = get_deps()
        except Exception as e:
            return f"Error: {_agent_message(e)}"
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                found = await anyio.to_thread.run_sync(lambda: executor.agent_checkpoints(principal, public_id=token, limit=1))
            except Exception as e:
                return f"Error: {_agent_message(e)}"
            if not found:
                return f"No checkpoint {token} was made by this agent."
            cp = found[0]
            if cp["status"] not in WAITING or cp.get("expired"):
                return describe_checkpoint(cp)
            left = deadline - time.monotonic()
            if left <= 0:
                return (f"Still waiting after {timeout_seconds} s: {describe_checkpoint(cp)} Call wait_for_approval again "
                        f"to keep waiting, or tell the user to run `lomberk approve {token}`.")
            await ctx.report_progress(timeout_seconds - left, timeout_seconds,
                                      f"Waiting for a human to approve {token} (`lomberk approve {token}`).")
            await anyio.sleep(min(POLL_SECONDS, left))

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
