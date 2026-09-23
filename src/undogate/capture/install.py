import psycopg
import os
from pathlib import Path

def install_undogate(admin_dsn: str):
    """Installs Undogate schema, tables, and functions into the database."""
    sql_dir = Path(__file__).parent / "sql"
    
    with psycopg.connect(admin_dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            # 1. Read and execute schema
            with open(sql_dir / "01_schema.sql", "r") as f:
                cur.execute(f.read())
                
            # 2. Read and execute functions
            with open(sql_dir / "02_functions.sql", "r") as f:
                cur.execute(f.read())
                
            # 3. Attach triggers to existing tables
            cur.execute("SELECT undogate.attach_triggers_to_all();")
