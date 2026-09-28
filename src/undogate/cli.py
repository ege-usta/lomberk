import dotenv; dotenv.load_dotenv()
import os
import sys

import typer
from rich.console import Console
from rich.table import Table

from undogate.capture.install import install_undogate
from undogate.config import load_config
from undogate.executor import UndogateExecutor
from undogate.policy import PolicyEngine
from undogate.sql.classify import classify_sql

app = typer.Typer(help="Undogate: Ctrl+Z for AI agents", no_args_is_help=True)


def cli_actor() -> str:
    import getpass
    return f"cli:{getpass.getuser()}"
console = Console()

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
    install_dsn: str = typer.Option(None, envvar="UNDOGATE_INSTALL_DSN", help="DSN of a DB owner/superuser used only for installation."),
):
    """Initialize Undogate in the database (run once, as a database owner)."""
    if not install_dsn:
        console.print("[red]Error: pass --install-dsn or set UNDOGATE_INSTALL_DSN (an owner/superuser connection, not the control or agent role).[/red]")
        raise typer.Exit(1)
    console.print("Installing Undogate schema and triggers...")
    install_undogate(install_dsn, control_role=control_role, agent_role=agent_role)
    console.print("[green]Undogate installed successfully![/green]")

@app.command()
def register(
    table: str = typer.Argument(..., help="Schema-qualified table, e.g. public.users"),
    agent_role: str = typer.Option(..., help="The agent role that may write to this table through Undogate."),
    pk: str = typer.Option("id", help="Single-column primary key."),
    install_dsn: str = typer.Option(None, envvar="UNDOGATE_INSTALL_DSN", help="Owner/superuser DSN."),
):
    """Put a table under Undogate protection (capture trigger + agent grants)."""
    import psycopg
    if not install_dsn:
        console.print("[red]Error: pass --install-dsn or set UNDOGATE_INSTALL_DSN.[/red]")
        raise typer.Exit(1)
    schema, sep, name = table.partition(".")
    if not sep or not name:
        console.print("[red]Error: table must be schema-qualified, e.g. public.users[/red]")
        raise typer.Exit(1)
    try:
        with psycopg.connect(install_dsn, autocommit=True) as conn:
            conn.execute("SELECT undogate.register_table(%s, %s, %s, %s)", (schema, name, pk, agent_role))
            unprotected = conn.execute("SELECT undogate.unprotected_cascade_child(%s::regclass)", (f'"{schema}"."{name}"',)).fetchone()[0]
    except psycopg.Error as e:
        console.print(f"[red]Failed to register {table}: {str(e).splitlines()[0]}[/red]")
        raise typer.Exit(1)
    console.print(f"[green]{table} is now protected.[/green]")
    if unprotected:
        console.print(f"[yellow]Note: deletes on {table} cascade into {unprotected}; register it too or those writes will be refused.[/yellow]")


@app.command()
def approve(token: str):
    """Approve and execute a pending SQL statement."""
    control, runtime = get_dsns()
    config = load_config()
    executor = UndogateExecutor(control, runtime, approval_timeout_minutes=config.agent.approval_timeout_minutes)
    res = executor.execute_pending(token, actor=cli_actor())
    if res.status == "applied":
        console.print(f"[green]Approved and executed successfully. Rows affected: {res.rows_affected}. Undo with: undogate undo {res.public_id}[/green]")
    else:
        console.print(f"[red]Failed to approve/execute: {res.message}[/red]")
        raise typer.Exit(1)

@app.command()
def reject(token: str):
    """Reject a pending SQL statement."""
    control, runtime = get_dsns()
    if not UndogateExecutor(control, runtime).reject(token, actor=cli_actor()):
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
            
    executor = UndogateExecutor(control, runtime)
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
        checked, broken, head = conn.execute("SELECT * FROM undogate.verify_ledger()").fetchone()
    if broken:
        console.print(f"[red]TAMPERING DETECTED: ledger chain breaks at checkpoint {broken} (after {checked} valid entries).[/red]")
        raise typer.Exit(2)
    if not checked:
        console.print("[yellow]Ledger is empty.[/yellow]")
        return
    console.print(f"[green]Ledger intact: {checked} checkpoints verified.[/green]")
    console.print(f"Head hash: {head}  (record it outside the database, e.g. in your SIEM, to detect full-chain rewrites)")


@app.command()
def api(port: int = 8000, host: str = typer.Option("127.0.0.1", help="Bind address. Put a TLS reverse proxy in front before exposing beyond localhost.")):
    """(Enterprise) Start the REST gateway (Slack via Socket Mode when enabled)."""
    import uvicorn
    console.print(f"[green]Starting Undogate API on {host}:{port}...[/green]")
    console.print(f"[dim]- Agent HTTP endpoint: POST http://{host}:{port}/v1/execute[/dim]")
    uvicorn.run("undogate.api:app", host=host, port=port)

if __name__ == "__main__":
    app()
