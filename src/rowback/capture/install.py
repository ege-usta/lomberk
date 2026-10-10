from pathlib import Path

import psycopg
from psycopg import sql


def install_rowback(admin_dsn: str, control_role: str, agent_role: str):
    """Installs Rowback schema, tables, and functions into the database."""
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
            cur.execute("DROP FUNCTION IF EXISTS rowback.begin_checkpoint(TEXT, TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.approve_checkpoint(BIGINT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.claim_checkpoint(BIGINT);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.claim_checkpoint(UUID);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.fail_checkpoint(BIGINT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.finish_checkpoint(BIGINT, INTEGER);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.get_pending_checkpoint(BIGINT);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.attach_trigger_to_table(TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.execute_undo_dml(TEXT, TEXT, CHAR, TEXT, TEXT, JSONB, JSONB);"); cur.execute("DROP FUNCTION IF EXISTS rowback.execute_undo_dml(TEXT, TEXT, CHAR, JSONB, JSONB);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.lock_table_for_undo(TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.register_table(TEXT, TEXT, TEXT, TEXT);")
            cur.execute("DROP FUNCTION IF EXISTS rowback.register_table(TEXT, TEXT, TEXT, TEXT, TEXT[]);")

            # 1. Read and execute schema
            with open(sql_dir / "01_schema.sql") as f:
                cur.execute(f.read())

            # 2. Read and execute functions
            with open(sql_dir / "02_functions.sql") as f:
                func_sql = f.read()
                func_sql = func_sql.replace('__AGENT_ROLE__', agent_role.replace("'", "''"))
                cur.execute(func_sql)

            # Grant schema usage and functions
            cur.execute(sql.SQL("REVOKE ALL ON rowback.checkpoints FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE ALL ON rowback.row_changes FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE ALL ON rowback.undo_operations FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION rowback.claim_checkpoint(UUID) FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION rowback.finish_checkpoint(UUID, INTEGER) FROM {}").format(sql.Identifier(control_role)))
            cur.execute(sql.SQL("REVOKE USAGE, SELECT ON ALL SEQUENCES IN SCHEMA rowback FROM {}").format(sql.Identifier(control_role)))
            cur.execute("SELECT rowback.grant_access(%s, %s)", (control_role, agent_role))
            # Upgrade: older installs granted the control role EXECUTE on register_table
            # (a SECURITY DEFINER function that runs as the installer). Take it back.
            cur.execute(sql.SQL("REVOKE EXECUTE ON FUNCTION rowback.register_table(TEXT, TEXT, TEXT, TEXT, TEXT[], BOOLEAN) FROM {}").format(sql.Identifier(control_role)))

        conn.commit()
