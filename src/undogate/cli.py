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
from undogate.undo import UndoEngine

app = typer.Typer(help="Undogate: Ctrl+Z for AI agents", no_args_is_help=True)
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
def init():
    """Initialize Undogate in the database."""
    dsn = get_admin_dsn()
    console.print("Installing Undogate schema and triggers...")
    install_undogate(dsn)
    console.print("[green]Undogate installed successfully![/green]")

@app.command()
def approve(token: str):
    """Approve and execute a pending SQL statement."""
    dsn = get_admin_dsn()
    executor = UndogateExecutor(dsn)
    res = executor.execute_pending(token)
    if res.status == "applied":
        console.print(f"[green]Approved and executed successfully. Rows affected: {res.rows_affected}[/green]")
    else:
        console.print(f"[red]Failed to approve/execute: {res.message}[/red]")

@app.command()
def reject(token: str):
    """Reject a pending SQL statement."""
    dsn = get_admin_dsn()
    import psycopg
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE undogate.checkpoints SET status = 'denied' WHERE public_id = %s", (token,))
            if cur.rowcount > 0:
                console.print(f"[green]Checkpoint {token} rejected.[/green]")
            else:
                console.print(f"[red]Token {token} not found.[/red]")

@app.command()
def undo(token: str):
    """Undo an applied SQL statement."""
    dsn = get_admin_dsn()
    import psycopg
    
    # Need to get internal ID from public token
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM undogate.checkpoints WHERE public_id = %s", (token,))
            row = cur.fetchone()
            if not row:
                console.print(f"[red]Token {token} not found.[/red]")
                raise typer.Exit(1)
            cp_id = row[0]
            
    engine = UndoEngine(dsn)
    success = engine.undo(cp_id)
    if success:
        console.print(f"[green]Successfully undid checkpoint {token}.[/green]")
    else:
        console.print(f"[red]Failed to undo {token}.[/red]")

@app.command()
def serve():
    """Start the MCP server (stdio transport)."""
    # The MCP server runs via asyncio in server.py
    # We will just exec into it to replace the current process
    server_path = os.path.join(os.path.dirname(__file__), "server.py")
    os.execvp(sys.executable, [sys.executable, server_path])

if __name__ == "__main__":
    app()

@app.command()
def verify_ledger():
    """Verify the cryptographic integrity of the ledger."""
    dsn = get_admin_dsn()
    import psycopg
    
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, sql_text, classification, decision, agent_label, prev_hash, hash FROM undogate.checkpoints ORDER BY id ASC")
            rows = cur.fetchall()
            
            if not rows:
                console.print("[yellow]Ledger is empty.[/yellow]")
                return
                
            console.print(f"Verifying {len(rows)} checkpoints...")
            import hashlib
            
            prev_expected = 'genesis'
            broken = False
            for r in rows:
                cp_id, sql, cls, dec, agent, prev_hash, actual_hash = r
                if prev_hash != prev_expected:
                    console.print(f"[red]Chain broken at ID {cp_id}! Expected prev_hash {prev_expected}, got {prev_hash}[/red]")
                    broken = True
                    break
                    
                # Recompute hash
                agent_str = agent if agent else ''
                data = prev_hash + sql + cls + dec + agent_str
                computed = hashlib.md5(data.encode('utf-8')).hexdigest()
                
                if computed != actual_hash:
                    console.print(f"[red]Hash mismatch at ID {cp_id}! Computed {computed}, got {actual_hash}[/red]")
                    broken = True
                    break
                    
                prev_expected = actual_hash
                
            if not broken:
                console.print("[green]Ledger integrity verified successfully! No tampering detected.[/green]")
