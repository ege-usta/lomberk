import json

import pglast
import psycopg
from psycopg import sql
from psycopg_pool import ConnectionPool
from pydantic import BaseModel

from undogate.ddl.handlers import handle_drop_column, handle_drop_table, handle_truncate
from undogate.models import PolicyDecision, StatementEvaluation


class ExecutionResult(BaseModel):
    checkpoint_id: int | None = None
    public_id: str | None = None
    rows_affected: int = 0
    data: list[dict] | None = None
    status: str
    message: str

class UndogateExecutor:

    def execute_undo(self, public_id: str, agent_label: str = "UNDOGATE_SYSTEM") -> ExecutionResult:
        import psycopg
        import json
        
        # We must use control_dsn, but executor uses whatever self.dsn is. 
        # API should initialize UndogateExecutor with control_dsn for this.
        
        try:
            with psycopg.connect(self.dsn, autocommit=False) as conn:
                with conn.transaction(), conn.cursor() as cur:
                    # 1. Lock the source checkpoint
                    try:
                        cur.execute("SELECT id, status, sql_text FROM undogate.checkpoints WHERE public_id = %s FOR UPDATE NOWAIT", (public_id,))
                    except psycopg.errors.LockNotAvailable:
                        return ExecutionResult(status="busy", message="Checkpoint is busy.", public_id=public_id, rows_affected=0)
                        
                    row = cur.fetchone()
                    if not row:
                        return ExecutionResult(status="denied", message="Checkpoint not found.", public_id=public_id, rows_affected=0)
                    
                    cp_id, status, sql_text = row
                    
                    if status == "undone":
                        return ExecutionResult(status="already_undone", message="Checkpoint already undone.", public_id=public_id, rows_affected=0)
                    
                    if status != "applied":
                        return ExecutionResult(status="denied", message=f"Cannot undo checkpoint in state: {status}", public_id=public_id, rows_affected=0)
                        
                    # Fetch changes in LIFO order
                    cur.execute("SELECT id, table_schema, table_name, op, pk, old_row, new_row FROM undogate.row_changes WHERE checkpoint_id = %s ORDER BY seq DESC", (cp_id,))
                    changes = cur.fetchall()
                    
                    if not changes:
                        # Nothing to undo
                        pass
                        
                    tables_involved = set()
                    for c in changes:
                        tables_involved.add((c[1], c[2]))
                        
                    # Validate tables (no FKs, no extra triggers, no rules)
                    for schema, table in tables_involved:
                        # Lock table against DDL
                        try:
                            cur.execute("SELECT undogate.lock_table_for_undo(%s, %s)", (schema, table))
                        except psycopg.errors.LockNotAvailable:
                            return ExecutionResult(status="busy", message=f"Table {schema}.{table} is locked by another transaction.", public_id=public_id, rows_affected=0)
                            
                        # Check FKs
                        cur.execute("""
                            SELECT COUNT(*) FROM pg_constraint c
                            JOIN pg_class t1 ON c.conrelid = t1.oid
                            JOIN pg_namespace n1 ON t1.relnamespace = n1.oid
                            LEFT JOIN pg_class t2 ON c.confrelid = t2.oid
                            LEFT JOIN pg_namespace n2 ON t2.relnamespace = n2.oid
                            WHERE contype = 'f' AND (
                                (n1.nspname = %s AND t1.relname = %s) OR 
                                (n2.nspname = %s AND t2.relname = %s)
                            )
                        """, (schema, table, schema, table))
                        if cur.fetchone()[0] > 0:
                            return ExecutionResult(status="failed", message=f"Table {schema}.{table} has foreign keys, which is unsupported for undo.", public_id=public_id, rows_affected=0)
                            
                        # Check Triggers
                        cur.execute("""
                            SELECT COUNT(*) FROM pg_trigger t
                            JOIN pg_class c ON t.tgrelid = c.oid
                            JOIN pg_namespace n ON c.relnamespace = n.oid
                            WHERE n.nspname = %s AND c.relname = %s AND t.tgisinternal = false AND t.tgname != 'undogate_capture'
                        """, (schema, table))
                        if cur.fetchone()[0] > 0:
                            return ExecutionResult(status="failed", message=f"Table {schema}.{table} has unsupported application triggers.", public_id=public_id, rows_affected=0)
                            
                        # Check Rules
                        cur.execute("""
                            SELECT COUNT(*) FROM pg_rewrite r
                            JOIN pg_class c ON r.ev_class = c.oid
                            JOIN pg_namespace n ON c.relnamespace = n.oid
                            WHERE n.nspname = %s AND c.relname = %s AND r.rulename != '_RETURN'
                        """, (schema, table))
                        if cur.fetchone()[0] > 0:
                            return ExecutionResult(status="failed", message=f"Table {schema}.{table} has unsupported rules.", public_id=public_id, rows_affected=0)
                            
                    # Start undo context
                    cur.execute("SELECT * FROM undogate.begin_checkpoint(%s, 'WRITE_DML', %s)", (f"UNDO {public_id}", agent_label))
                    undo_cp_row = cur.fetchone()
                    undo_cp_id, undo_public_id = undo_cp_row[0], undo_cp_row[1]
                    
                    cur.execute("SELECT undogate.approve_checkpoint(%s, 'ALLOW')", (undo_public_id,))
                    token = cur.fetchone()[0]
                    
                    cur.execute("SELECT undogate.claim_checkpoint(%s)", (token,))
                    
                    # Create undo_operation record
                    cur.execute("INSERT INTO undogate.undo_operations (source_checkpoint_id, undo_checkpoint_id) VALUES (%s, %s)", (cp_id, undo_cp_id))
                    
                    # Apply reverse operations
                    for c_id, schema, table, op, pk_json, old_row, new_row in changes:
                        pk_col = list(pk_json.keys())[0]
                        pk_val = str(pk_json[pk_col])
                        
                        try:
                            cur.execute("SELECT undogate.execute_undo_dml(%s, %s, %s, %s, %s, %s, %s)", 
                                (schema, table, op, pk_col, pk_val, json.dumps(old_row) if old_row else None, json.dumps(new_row) if new_row else None))
                        except psycopg.errors.LockNotAvailable:
                            return ExecutionResult(status="busy", message=f"Row {pk_val} in {schema}.{table} is locked.", public_id=public_id, rows_affected=0)
                        except psycopg.errors.UniqueViolation:
                            return ExecutionResult(status="failed", message=f"Row {pk_val} already exists in {schema}.{table}. Conflict.", public_id=public_id, rows_affected=0)
                        except Exception as e:
                            # Catch the raise exceptions from PL/pgSQL
                            return ExecutionResult(status="failed", message=str(e), public_id=public_id, rows_affected=0)
                            
                    # Update status
                    cur.execute("UPDATE undogate.checkpoints SET status = 'undone' WHERE id = %s", (cp_id,))
                    cur.execute("SELECT undogate.finish_checkpoint(%s, %s)", (token, 1))
                    
                    # Transaction context manager will commit
                    return ExecutionResult(status="undone", message="Undo successful.", public_id=public_id, rows_affected=1)
                    
        except psycopg.OperationalError:
            return ExecutionResult(status="outcome_unknown", message="Network failure.", public_id=public_id, rows_affected=0)
        except Exception as e:
            # Revert everything implicitly since we're in a 'with conn:' context but we caught it
            return ExecutionResult(status="failed", message=str(e), public_id=public_id, rows_affected=0)

    def _mask_and_sanitize_rows(self, columns, rows):
        import re
        def sanitize_payload(val_str: str) -> str:
            val_str = re.sub(r'(?i)<\|.*?\|>', '[SANITIZED_TOKEN]', val_str)
            val_str = re.sub(r'(?i)<!--.*?-->', '[SANITIZED_COMMENT]', val_str)
            val_str = re.sub(r'(?i)system:\s*override', '[SANITIZED_OVERRIDE]', val_str)
            return val_str

        SENSITIVE_COLUMNS = {"password", "ssn", "credit_card", "secret", "token", "hash"}
        fetched_data = []
        for row in rows:
            row_dict = dict(zip(columns, row))
            for col in columns:
                if any(sens in col.lower() for sens in SENSITIVE_COLUMNS) and row_dict[col]:
                    val_str = str(row_dict[col])
                    if len(val_str) > 4:
                        row_dict[col] = "***MASKED***" + val_str[-4:]
                    else:
                        row_dict[col] = "***MASKED***"
                elif isinstance(row_dict[col], str):
                    row_dict[col] = sanitize_payload(row_dict[col])
            fetched_data.append(row_dict)
        return fetched_data

    def __init__(self, dsn: str, runtime_dsn: str):
        if not dsn or not runtime_dsn:
            raise ValueError("Both dsn and runtime_dsn are required")
        self.dsn = dsn
        self.runtime_dsn = runtime_dsn

    def create_pending_checkpoint(self, sql: str, stmt_class: str, decision: str, agent_label: str) -> str:
        import psycopg
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM undogate.begin_checkpoint(%s, %s, %s)",
                    (sql, stmt_class, agent_label)
                )
                row = cur.fetchone()
                cp_id = row[0]
                public_id = row[1]
                # Transaction context manager will commit
                return public_id


    def execute(self, eval_result, agent_label: str = "agent"):
        if not self.dsn or not self.runtime_dsn:
            raise ValueError("Both dsn and runtime_dsn are required for execution.")
            
        from undogate.sentinel import AISentinel
        from undogate.policy import PolicyDecision
        
        
        safe, reason = AISentinel()._ast_firewall(eval_result.statement.sql)
        if not safe:
            return ExecutionResult(status="denied", message=f"Hard Gate Denied: {reason}")
            
        if eval_result.decision == PolicyDecision.DENY:
            return ExecutionResult(status="denied", message=eval_result.reason)
            
        if eval_result.decision == PolicyDecision.REQUIRE_APPROVAL:
            public_id = self.create_pending_checkpoint(
                sql=eval_result.statement.sql,
                stmt_class=eval_result.statement.stmt_class.value,
                decision=eval_result.decision.value,
                agent_label=agent_label
            )
            return ExecutionResult(checkpoint_id=-1, public_id=public_id, status="approval_required", message="Policy requires explicit approval.")
            
        # READ ONLY PATH
        if eval_result.statement.stmt_class.value == "READ":
            import psycopg
            error_msg = None
            fetched_data = None
            try:
                with psycopg.connect(self.runtime_dsn, autocommit=False) as conn:
                    with conn.transaction():
                        with conn.transaction(), conn.cursor() as cur:
                            from undogate.sql.classify import check_sensitive_columns
                            import pglast
                            ast = pglast.parse_sql(eval_result.statement.sql)
                            sens_cols = check_sensitive_columns(ast)
                            if sens_cols:
                                raise Exception(f"Access denied: Query contains sensitive columns {sens_cols}")
                            
                            cur.execute("SET LOCAL statement_timeout = '5s'")
                            cur.execute("SET TRANSACTION READ ONLY")
                            cur.execute(eval_result.statement.sql)
                            if cur.description:
                                columns = [desc[0] for desc in cur.description]
                                rows = cur.fetchmany(100)
                                fetched_data = self._mask_and_sanitize_rows(columns, rows)
            except Exception as e:
                error_msg = str(e)
                
            if error_msg:
                return ExecutionResult(status="failed", message=error_msg)
            return ExecutionResult(status="applied", message="Success", data=fetched_data)
            
        return self._execute_internal(eval_result.statement.sql, eval_result.statement.stmt_class.value, eval_result.decision.value, agent_label)

    def _execute_dml(self, cp_id: int, public_id: str, exec_token: str, sql_to_execute: str):
        import psycopg
        from psycopg import sql
        
        
        error_msg = None
        fetched_data = None
        rows_affected = 0
        execution_completed = False
        try:
            with psycopg.connect(self.runtime_dsn, autocommit=False) as runtime_conn:
                with runtime_conn.transaction():
                    with runtime_conn.cursor() as cur:
                        cur.execute("SET LOCAL statement_timeout = '5s'")
                        cur.execute("SELECT undogate.claim_checkpoint(%s)", (exec_token,))
                        cur.execute("SELECT set_config('undogate.checkpoint_id', %s, true)", (str(cp_id),))
                        cur.execute("SELECT set_config('undogate.capability_token', %s, true)", (str(exec_token),))
                        cur.execute("SELECT set_config('undogate.seq', '0', true)")
                        
                        from undogate.sql.classify import extract_tables_from_ast, check_sensitive_columns
                        import pglast
                        ast = pglast.parse_sql(sql_to_execute)
                        tables = extract_tables_from_ast(ast)
                        
                        sens_cols = check_sensitive_columns(ast)
                        if sens_cols:
                            raise Exception(f"Access denied: Query contains sensitive columns {sens_cols}")
                        
                        for schema, table in tables:
                            if schema in ('undogate', 'undogate_trash', 'information_schema', 'pg_catalog'):
                                raise Exception(f"Direct DML on system schema {schema} is forbidden.")
                            cur.execute(sql.SQL("LOCK TABLE {}.{} IN ROW EXCLUSIVE MODE;").format(sql.Identifier(schema), sql.Identifier(table)))
                            
                            cur.execute("""
                                SELECT 
                                    c.oid AS table_oid, 
                                    r.table_oid AS reg_oid, 
                                    r.pk_column, 
                                    t.tgenabled, 
                                    t.tgtype, 
                                    t.tgattr, 
                                    t.tgqual, 
                                    t.tgfoid, 
                                    p.oid AS expected_foid,
                                    a.attname AS pk_exists,
                                    (
                                        SELECT a2.attname
                                        FROM pg_index i 
                                        JOIN pg_attribute a2 ON a2.attrelid = i.indrelid AND a2.attnum = i.indkey[0]
                                        WHERE i.indrelid = c.oid AND i.indisprimary AND i.indnatts = 1
                                    ) AS actual_pk_column
                                FROM pg_class c 
                                JOIN pg_namespace n ON n.oid = c.relnamespace
                                LEFT JOIN undogate.registered_tables r ON r.schema_name = n.nspname AND r.table_name = c.relname
                                LEFT JOIN pg_trigger t ON t.tgrelid = c.oid AND t.tgname = 'undogate_capture'
                                LEFT JOIN pg_proc p ON p.proname = 'capture_row_change' AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'undogate') AND p.pronargs = 0
                                LEFT JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = r.pk_column AND a.attnum > 0 AND NOT a.attisdropped
                                WHERE n.nspname = %s AND c.relname = %s AND c.relkind = 'r'
                            """, (schema, table))
                            row2 = cur.fetchone()
                            
                            if not row2: raise Exception(f"Table {schema}.{table} does not exist.")
                            
                            (c_oid, r_table_oid, pk_column, tgenabled, tgtype, tgattr, tgqual, tgfoid, expected_foid, pk_exists, actual_pk_column) = row2
                            
                            if r_table_oid is None:
                                raise Exception(f"Table {schema}.{table} is not registered for mutation.")
                            if c_oid != r_table_oid:
                                raise Exception(f"Registration mismatch for {schema}.{table}: OID has changed.")
                            
                            if pk_exists is None:
                                raise Exception(f"Primary key column '{pk_column}' does not exist on table {schema}.{table}.")
                                
                            if actual_pk_column is None:
                                raise Exception(f"Table {schema}.{table} must have exactly one single-column primary key.")
                            if actual_pk_column != pk_column:
                                raise Exception(f"Registered primary key '{pk_column}' does not match actual primary key '{actual_pk_column}' on table {schema}.{table}.")
                            
                            if tgenabled is None:
                                raise Exception(f"Trigger missing on {schema}.{table}.")
                            tge = tgenabled.decode('utf-8') if isinstance(tgenabled, bytes) else str(tgenabled)
                            if tge not in ('O', 'A'):
                                raise Exception(f"Trigger disabled or replica-only on {schema}.{table}.")
                            
                            if tgfoid != expected_foid or expected_foid is None:
                                raise Exception(f"Trigger function OID mismatch for {schema}.{table}. Suspected spoofing.")
                            
                            if tgtype != 29:
                                raise Exception(f"Trigger type mismatch on {schema}.{table}. Expected AFTER EACH ROW INSERT/UPDATE/DELETE.")
                                
                            if tgqual is not None:
                                raise Exception(f"Trigger condition (WHEN) is not allowed on {schema}.{table}.")
                                
                            if tgattr and str(tgattr) != '' and str(tgattr) != 'b\'\'':
                                raise Exception(f"Trigger column restrictions (UPDATE OF) are not allowed on {schema}.{table}.")
                            
                        cur.execute(sql_to_execute)
                        if cur.description:
                            columns = [desc[0] for desc in cur.description]
                            rows = cur.fetchmany(100)
                            fetched_data = self._mask_and_sanitize_rows(columns, rows)
                                
                        rows_affected = max(cur.rowcount, 0)
                        cur.execute("SELECT undogate.finish_checkpoint(%s, %s)", (exec_token, rows_affected))
                        execution_completed = True
        except Exception as e:
            error_msg = str(e)
            
        if error_msg:
            if execution_completed:
                return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="outcome_unknown", message="Network failure during commit. Checkpoint state is unknown.")
            
            try:
                with psycopg.connect(self.dsn, autocommit=True) as fail_conn:
                    with fail_conn.cursor() as fail_cur:
                        fail_cur.execute("SELECT undogate.fail_checkpoint(%s)", (public_id,))
            except Exception:
                pass 
                
            from undogate.audit import emit_audit_event
            emit_audit_event(cp_id, public_id, sql_to_execute, "mcp_agent", "failed", rows=0)
            safe_error_msg = error_msg if "exec_token" not in error_msg else "An error occurred during execution."
            return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="failed", message=safe_error_msg)

        from undogate.audit import emit_audit_event
        emit_audit_event(cp_id, public_id, sql_to_execute, "mcp_agent", "applied", [], rows_affected)
        return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, rows_affected=rows_affected, status="applied", message="Success", data=fetched_data)

    def _execute_internal(self, sql_to_execute: str, classification: str, decision: str, agent_label: str):
        import psycopg
        try:
        
            with psycopg.connect(self.dsn, autocommit=False) as conn:
                with conn.transaction(), conn.cursor() as cur:
                    cur.execute(
                        "SELECT * FROM undogate.begin_checkpoint(%s, %s, %s)",
                        (sql_to_execute, classification, agent_label)
                    )
                    row = cur.fetchone()
                    cp_id = row[0]
                    public_id = row[1]
                
                    cur.execute("SELECT undogate.approve_checkpoint(%s, 'ALLOW')", (public_id,))
                    exec_token = cur.fetchone()[0]
                    # Transaction context manager will commit

            return self._execute_dml(cp_id, public_id, exec_token, sql_to_execute)

        except psycopg.OperationalError:
            return ExecutionResult(status="outcome_unknown", message="Network failure.")
    def execute_pending(self, public_id: str):
        import psycopg
        try:
        
        
            with psycopg.connect(self.dsn, autocommit=False) as conn:
                with conn.transaction(), conn.cursor() as cur:
                    cur.execute("SELECT id, sql_text, status FROM undogate.get_pending_checkpoint(%s)", (public_id,))
                    row = cur.fetchone()
                    if not row:
                        return ExecutionResult(status="failed", message="Token not found.")
                    cp_id, sql_to_execute, status = row
                    if status != "pending":
                        return ExecutionResult(status="failed", message=f"Checkpoint status is {status}, not pending.")

                    from undogate.sentinel import AISentinel
                    safe, reason = AISentinel()._ast_firewall(sql_to_execute)
                    if not safe:
                        cur.execute("SELECT undogate.reject_checkpoint(%s)", (public_id,))
                        # Transaction context manager will commit
                        return ExecutionResult(status="denied", message=f"Hard Gate Denied: {reason}")

                    cur.execute("SELECT undogate.approve_checkpoint(%s, 'ALLOW')", (public_id,))
                    exec_token = cur.fetchone()[0]
                    # Transaction context manager will commit

            return self._execute_dml(cp_id, public_id, exec_token, sql_to_execute)

        except psycopg.OperationalError as e:
            return ExecutionResult(status="outcome_unknown", message=str(e))
    def check_status(self, public_id: str) -> str:
        import psycopg
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT undogate.check_checkpoint_status(%s)", (public_id,))
                    return cur.fetchone()[0]
        except psycopg.OperationalError as e:
            print("check_status Error:", repr(e))
            return "outcome_unknown"

