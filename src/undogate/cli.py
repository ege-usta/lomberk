import typer
from rich.console import Console
from rich.table import Table

from undogate.config import load_config
from undogate.policy import PolicyEngine
from undogate.sql.classify import classify_sql

app = typer.Typer(help="Undogate: Ctrl+Z for AI agents")
console = Console()

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
def init(admin_dsn_env: str = typer.Option("UNDOGATE_ADMIN_DSN", help="Env var name for admin DSN")):
    """Initialize Undogate in the database."""
    console.print("init not implemented yet.")

if __name__ == "__main__":
    app()
