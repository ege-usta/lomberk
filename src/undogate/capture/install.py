from pathlib import Path
import psycopg
from psycopg import sql

def install_undogate(admin_dsn: str, control_role: str, agent_role: str):
    """Installs Undogate schema, tables, and functions into the database."""
    if not agent_role or not control_role:
        raise ValueError("control_role and agent_role are required")
        
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
            if curr_user == agent_role or curr_user == control_role:
                raise ValueError("Installation cannot be performed by the runtime or control role itself.")
        
            # Legacy cleanup: drop old function signatures to prevent upgrade collisions
            cur.execute("DROP FUNCTION IF EXISTS undogate.begin_checkpoint(TEXT, TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS undogate.approve_checkpoint(BIGINT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS undogate.claim_checkpoint(BIGINT);")
            cur.execute("DROP FUNCTION IF EXISTS undogate.fail_checkpoint(BIGINT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS undogate.finish_checkpoint(BIGINT, INTEGER);")
            cur.execute("DROP FUNCTION IF EXISTS undogate.get_pending_checkpoint(BIGINT);")
            cur.execute("DROP FUNCTION IF EXISTS undogate.attach_trigger_to_table(TEXT, TEXT);")
            
            # 1. Read and execute schema
            with open(sql_dir / "01_schema.sql", "r") as f:
                cur.execute(f.read())
                
            # 2. Read and execute functions
            with open(sql_dir / "02_functions.sql", "r") as f:
                func_sql = f.read()
                func_sql = func_sql.replace('__AGENT_ROLE__', agent_role)
                cur.execute(func_sql)
                
            # Grant schema usage and functions
            cur.execute("SELECT undogate.grant_access(%s, %s)", (control_role, agent_role))
            
        conn.commit()
