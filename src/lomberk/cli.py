import os
import sys

import dotenv
import typer
import yaml
from rich.console import Console
from rich.table import Table

from lomberk.capture.install import install_lomberk
from lomberk.config import LomberkConfig, config_error_message, config_path
from lomberk.config import load_config as _load_config
from lomberk.executor import UNDO_WINDOW_HOURS, LicenseActivationStore, LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.sql.classify import classify_sql

dotenv.load_dotenv()

app = typer.Typer(help="Lomberk: every agent write, reversible", no_args_is_help=True)


def load_config() -> LomberkConfig:
    """The config, or a one-line error and exit 1 when it is missing or invalid (no traceback)."""
    try:
        return _load_config()
    except (ValueError, yaml.YAMLError) as e:  # ValueError includes pydantic's ValidationError for unknown keys
        console.print(f"[red]Config error: {config_error_message(e)}[/red]")
        raise typer.Exit(1) from None


def cli_actor() -> str:
    import getpass
    return f"cli:{getpass.getuser()}"
console = Console(soft_wrap=True)  # never break a token or a command someone will copy

def cli_plan(control_dsn: str) -> str:
    """The plan LOMBERK_LICENSE_KEY grants: "free", "pro" or "enterprise"."""
    try:
        from lomberk.ee.license import LicenseError, check_license
    except ImportError:  # core without the ee package
        return "free"
    try:
        return check_license(os.environ.get("LOMBERK_LICENSE_KEY"), [], LicenseActivationStore(control_dsn))
    except (LicenseError, ValueError) as e:
        console.print(f"[yellow]{e}[/yellow]")
        return "free"


def get_admin_dsn() -> str:
    config = load_config()
    dsn = os.environ.get(config.database.admin_dsn_env)
    if not dsn:
        console.print(f"[red]Error: Admin DSN env var '{config.database.admin_dsn_env}' not set.[/red]")
        sys.exit(1)
    return dsn

@app.command()
def preview(sql: str, rows_affected: int = typer.Option(None, help="Mock rows affected for policy check")):
    """Preview classification and policy decision for a SQL statement without DB connection."""
    config = load_config()
    policy = PolicyEngine(config)
    statements = classify_sql(sql)

    table = Table(title="SQL Classification Preview")
    table.add_column("Statement")
    table.add_column("Class")
    table.add_column("Tables")
    table.add_column("Decision")
    table.add_column("Reason")

    for stmt in statements:
        eval = policy.evaluate(stmt, rows_affected=rows_affected)
        table.add_row(
            stmt.sql[:50] + ("..." if len(stmt.sql) > 50 else ""),
            stmt.stmt_class.value,
            ", ".join(stmt.tables),
            eval.decision.value,
            eval.reason
        )

    console.print(table)

@app.command()
def init(
    control_role: str = typer.Option(..., help="Existing non-superuser role the gateway/CLI uses for approvals."),
    agent_role: str = typer.Option(..., help="Existing non-superuser role the AI agent's writes run as."),
    install_dsn: str = typer.Option(None, envvar="LOMBERK_INSTALL_DSN", help="DSN of a DB owner/superuser used only for installation."),
):
    """Initialize Lomberk in the database (run once, as a database owner)."""
    if not install_dsn:
        console.print("[red]Error: pass --install-dsn or set LOMBERK_INSTALL_DSN (an owner/superuser connection, not the control or agent role).[/red]")
        raise typer.Exit(1)
    console.print("Installing Lomberk schema and triggers...")
    install_lomberk(install_dsn, control_role=control_role, agent_role=agent_role)
    console.print("[green]Lomberk installed successfully![/green]")

@app.command()
def register(
    table: str = typer.Argument(..., help="Schema-qualified table, e.g. public.users"),
    agent_role: str = typer.Option(..., help="The agent role that may write to this table through Lomberk."),
    pk: str = typer.Option(None, help="Primary key column(s), comma-separated in key order (e.g. tenant_id,id). "
                           "Default: read from the table."),
    allow_triggers: bool = typer.Option(False, help="The table's own triggers only change the row itself (like updated_at) "
                                        "or tables Lomberk also protects. Undo switches them off while it restores rows."),
    install_dsn: str = typer.Option(None, envvar="LOMBERK_INSTALL_DSN", help="Owner/superuser DSN."),
):
    """Put a table under Lomberk protection (capture trigger + agent grants)."""
    import psycopg
    if not install_dsn:
        console.print("[red]Error: pass --install-dsn or set LOMBERK_INSTALL_DSN.[/red]")
        raise typer.Exit(1)
    schema, sep, name = table.partition(".")
    if not sep or not name:
        console.print("[red]Error: table must be schema-qualified, e.g. public.users[/red]")
        raise typer.Exit(1)
    from lomberk.sql.classify import is_secret
    extra = load_config().sensitive_columns
    try:
        with psycopg.connect(install_dsn, autocommit=True) as conn:
            columns = [r[0] for r in conn.execute(
                "SELECT attname FROM pg_attribute WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped",
                (f'"{schema}"."{name}"',))]
            hidden = [c for c in columns if is_secret(c, extra)]
            conn.execute("SELECT lomberk.register_table(%s, %s, %s, %s, %s, %s)", (schema, name, pk, agent_role, hidden, allow_triggers))
            unprotected = conn.execute("SELECT lomberk.unprotected_cascade_child(%s::regclass)", (f'"{schema}"."{name}"',)).fetchone()[0]
    except psycopg.Error as e:
        console.print(f"[red]Failed to register {table}: {str(e).splitlines()[0]}[/red]")
        raise typer.Exit(1) from None
    console.print(f"[green]{table} is now protected.[/green]")
    if hidden:
        console.print(f"Hidden from the agent by the database itself: {', '.join(hidden)}")
    if unprotected:
        console.print(f"[yellow]Note: deletes on {table} cascade into {unprotected}; register it too or those writes will be refused.[/yellow]")


@app.command()
def approve(token: str):
    """Approve and execute a pending SQL statement."""
    control, runtime = get_dsns()
    config = load_config()
    executor = LomberkExecutor(control, runtime, approval_timeout_minutes=config.agent.approval_timeout_minutes,
                                required_approvals=config.approvals.required, sensitive_columns=config.sensitive_columns)
    res = executor.execute_pending(token, actor=cli_actor())
    if res.status == "applied":
        console.print(f"[green]Approved and executed successfully. Rows affected: {res.rows_affected}. Undo with: lomberk undo {res.public_id}[/green]")
    elif res.status == "awaiting_approval":
        console.print(f"[yellow]{res.message}[/yellow]")
    else:
        console.print(f"[red]Failed to approve/execute: {res.message}[/red]")
        raise typer.Exit(1)

@app.command()
def show(token: str):
    """Show exactly what a checkpoint will run (review before approving)."""
    control, runtime = get_dsns()
    cp = LomberkExecutor(control, runtime).get_checkpoint(token)
    if not cp:
        console.print(f"[red]Token {token} not found.[/red]")
        raise typer.Exit(1)
    for key in ("public_id", "status", "classification", "agent_label", "principal", "created_at", "rows_affected"):
        console.print(f"[bold]{key}[/bold]: {cp[key]}")
    console.print("[bold]sql[/bold]:")
    console.print(cp["sql_text"], markup=False, highlight=False)
    p = cp.get("preview")
    if p:
        import json
        tables = ", ".join(f"{t} ({n})" for t, n in p["tables"].items())
        more = f", first {len(p['sample'])} shown" if p["truncated"] else ""
        console.print(f"[bold]would change[/bold]: {p['rows']} row(s) in {tables} (dry run when held{more})")
        for s in p["sample"]:  # agent data: never parsed as markup
            detail = json.dumps(s.get("changes") or s.get("row"), default=str)
            console.print(f"  {s['op']:<6} {s['table']} {json.dumps(s['key'])}: {detail}", markup=False, highlight=False)


@app.command()
def reject(token: str):
    """Reject a pending SQL statement, or close one left approved but never run (after a crash)."""
    control, runtime = get_dsns()
    if not LomberkExecutor(control, runtime).reject(token, actor=cli_actor()):
        console.print(f"[red]Token {token} not found or not pending.[/red]")
        raise typer.Exit(1)
    console.print(f"[green]Checkpoint {token} rejected.[/green]")

def get_dsns():
    config = load_config()
    control = os.environ.get(config.database.admin_dsn_env)
    runtime = os.environ.get(config.database.agent_dsn_env)

    if not control:
        console.print(f"[red]Error: Admin DSN env var '{config.database.admin_dsn_env}' not set.[/red]")
        raise typer.Exit(1)

    if not runtime:
        console.print(f"[red]Error: Agent DSN env var '{config.database.agent_dsn_env}' not set.[/red]")
        raise typer.Exit(1)

    return control, runtime

@app.command()
def undo(token: str):
    """Undo an applied SQL statement."""
    control, runtime = get_dsns()

    executor = LomberkExecutor(control, runtime, undo_window_hours=UNDO_WINDOW_HOURS["free"])
    res = executor.execute_undo(token, agent_label=cli_actor())
    if res.status == "expired" and os.environ.get("LOMBERK_LICENSE_KEY"):
        # Polar is asked only when the free window isn't enough, so everyday undo works offline.
        executor.undo_window_hours = UNDO_WINDOW_HOURS[cli_plan(control)]
        res = executor.execute_undo(token, agent_label=cli_actor())

    if res.status == "undone":
        console.print(f"[green]Successfully undid checkpoint {token}. Rows affected: {res.rows_affected}[/green]")
    else:
        console.print(f"[red]Failed to undo {token}: {res.message}[/red]")
        raise typer.Exit(1)

@app.command()
def serve():
    """Start the MCP server (stdio transport)."""
    # The MCP server runs via asyncio in server.py
    # We will just exec into it to replace the current process
    server_path = os.path.join(os.path.dirname(__file__), "server.py")
    os.execvp(sys.executable, [sys.executable, server_path])


@app.command()
def verify_ledger():
    """Verify the tamper-evident (SHA-256 hash-chained) checkpoint ledger."""
    import psycopg
    with psycopg.connect(get_admin_dsn()) as conn:
        checked, broken, head = conn.execute("SELECT * FROM lomberk.verify_ledger()").fetchone()
    if broken:
        console.print(f"[red]TAMPERING DETECTED: ledger chain breaks at checkpoint {broken} (after {checked} valid entries).[/red]")
        raise typer.Exit(2)
    if not checked:
        console.print("[yellow]Ledger is empty.[/yellow]")
        return
    console.print(f"[green]Ledger intact: {checked} checkpoints verified.[/green]")
    console.print(f"Head hash: {head}  (record it outside the database, e.g. in your SIEM, to detect full-chain rewrites)")


@app.command()
def doctor(config: str = typer.Option(None, help="Config file to check (default: $LOMBERK_CONFIG, else ./lomberk.yaml).")):
    """Check this deployment (config, keys, database roles, install, license) and say how to fix problems."""
    from rich.markup import escape

    from lomberk.doctor import FAIL, OK, run_checks
    results = run_checks(config or config_path())
    marks = {OK: "[green]✓[/green]", FAIL: "[red]✗[/red]"}
    for level, what, fix in results:
        console.print(f"{marks.get(level, '[yellow]![/yellow]')} {escape(what)}", highlight=False)
        if fix and level != OK:
            console.print(f"  [dim]→ {escape(fix)}[/dim]", highlight=False)
    failures = sum(level == FAIL for level, _, _ in results)
    if failures:
        console.print(f"[red]{failures} problem(s) to fix before starting the gateway.[/red]")
        raise typer.Exit(1)
    console.print("[green]Ready. Start the gateway with: lomberk serve (MCP over stdio) or lomberk api (HTTP)[/green]")


@app.command()
def api(port: int = 8000, host: str = typer.Option("127.0.0.1", help="Bind address. Put a TLS reverse proxy in front before exposing beyond localhost.")):
    """Start the HTTP gateway: REST at /v1 and remote MCP at /mcp, for agents that can't run `lomberk serve`."""
    import uvicorn
    console.print(f"[green]Starting Lomberk API on {host}:{port}...[/green]")
    console.print(f"[dim]- Agent HTTP endpoint: POST http://{host}:{port}/v1/execute[/dim]")
    uvicorn.run("lomberk.api:app", host=host, port=port)

if __name__ == "__main__":
    app()
