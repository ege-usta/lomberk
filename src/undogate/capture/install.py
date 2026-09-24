from pathlib import Path
import psycopg
from urllib.parse import urlparse

def install_undogate(admin_dsn: str, agent_role: str):
    """Installs Undogate schema, tables, and functions into the database."""
    if not agent_role:
        raise ValueError("agent_role is required")
        
    sql_dir = Path(__file__).parent / "sql"
    
    with psycopg.connect(admin_dsn) as conn:
        with conn.cursor() as cur:
            # Check if agent_role is superuser
            cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = %s", (agent_role,))
            row = cur.fetchone()
            if not row:
                raise ValueError(f"Role {agent_role} does not exist.")
            if row[0]:
                raise ValueError(f"Role {agent_role} must not be a superuser.")
                
            cur.execute("SELECT current_user")
            curr_user = cur.fetchone()[0]
            if curr_user == agent_role:
                raise ValueError("Installation cannot be performed by the agent role itself.")
        
            # 1. Read and execute schema
            with open(sql_dir / "01_schema.sql", "r") as f:
                cur.execute(f.read())
                
            # 2. Read and execute functions
            with open(sql_dir / "02_functions.sql", "r") as f:
                func_sql = f.read()
                func_sql = func_sql.replace('__AGENT_ROLE__', agent_role)
                cur.execute(func_sql)
                
            # Grant schema usage and functions
            cur.execute("SELECT undogate.grant_agent_access(%s)", (agent_role,))
            
        conn.commit()
