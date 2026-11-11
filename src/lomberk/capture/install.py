from pathlib import Path

import psycopg
from psycopg import sql


def install_lomberk(admin_dsn: str, control_role: str, agent_role: str):
    """Installs Lomberk schema, tables, and functions into the database."""
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
            cur.execute("DROP FUNCTION IF EXISTS lomberk.begin_checkpoint(TEXT, TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.begin_checkpoint(TEXT, TEXT, TEXT, TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.requeue_checkpoint(TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.approve_checkpoint(BIGINT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.claim_checkpoint(BIGINT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.claim_checkpoint(UUID);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.fail_checkpoint(BIGINT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.finish_checkpoint(BIGINT, INTEGER);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.get_pending_checkpoint(BIGINT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.attach_trigger_to_table(TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.execute_undo_dml(TEXT, TEXT, CHAR, TEXT, TEXT, JSONB, JSONB);"); cur.execute("DROP FUNCTION IF EXISTS lomberk.execute_undo_dml(TEXT, TEXT, CHAR, JSONB, JSONB);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.lock_table_for_undo(TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.register_table(TEXT, TEXT, TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS lomberk.register_table(TEXT, TEXT, TEXT, TEXT, TEXT[]);")

            # 1. Read and execute schema
            with open(sql_dir / "01_schema.sql") as f:
                cur.execute(f.read())

            # 2. Read and execute functions
            with open(sql_dir / "02_functions.sql") as f:
                func_sql = f.read()
                func_sql = func_sql.replace('__AGENT_ROLE__', agent_role.replace("'", "''"))
                cur.execute(func_sql)

            # Grant schema usage and functions
            cur.execute(sql.SQL("REVOKE ALL ON lomberk.checkpoints FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE ALL ON lomberk.row_changes FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE ALL ON lomberk.undo_operations FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION lomberk.claim_checkpoint(UUID) FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION lomberk.finish_checkpoint(UUID, INTEGER) FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA lomberk FROM {}").format(sql.Identifier(control_role)))
            cur.execute("SELECT lomberk.grant_access(%s, %s)", (control_role, agent_role))
            # Upgrade: older installs granted the control role EXECUTE on register_table
            # (a SECURITY DEFINER function that runs as the installer). Take it back.
            cur.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION lomberk.register_table(TEXT, TEXT, TEXT, TEXT, TEXT[], BOOLEAN) FROM {}").format(sql.Identifier(control_role)))

        conn.commit()
