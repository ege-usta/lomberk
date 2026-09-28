import json

import pglast
import psycopg
from psycopg import sql
from psycopg_pool import ConnectionPool
from pydantic import BaseModel

from undogate.audit import audit
from undogate.models import PolicyDecision, StatementEvaluation


class ExecutionResult(BaseModel):
    checkpoint_id: int | None = None
    public_id: str | None = None
    operation_id: str | None = None
    rows_affected: int = 0
    data: list[dict] | None = None
    status: str
    message: str
    error_code: str | None = None

class HoldForApproval(Exception):
    """Auto-approved write must be rolled back and sent to a human instead."""


class UndogateExecutor:
    # ponytail: a fresh connection per step (~5 ms each, ~18 ms p50 per captured write
    # on localhost) keeps outcome-unknown handling exact. Add psycopg_pool when the DB
    # is remote/TLS and latency matters; pooled conns must be discarded after errors.

    def _resolve_duplicate(self, principal: str, operation_id: str, sql_to_execute: str):
        import psycopg
        with psycopg.connect(self.dsn) as check_conn, check_conn.cursor() as check_cur:
            check_cur.execute("SELECT id, public_id, status, rows_affected, sql_text FROM undogate.checkpoints WHERE principal = %s AND operation_id = %s", (principal, operation_id))
            existing = check_cur.fetchone()
            if existing:
                if existing[4] != sql_to_execute:
                    return ExecutionResult(checkpoint_id=existing[0], public_id=existing[1], operation_id=operation_id, status="failed", error_code="conflict", message=f"Conflict: operation_id {operation_id} was already used with a different SQL payload.")
                return ExecutionResult(checkpoint_id=existing[0], public_id=existing[1], operation_id=operation_id, status="approval_required" if existing[2] == "pending" else existing[2], rows_affected=existing[3] or 0, message="Idempotent replay")
        raise RuntimeError(f"UniqueViolation occurred but no existing record found for {principal}:{operation_id}")

    def execute_undo(self, public_id: str, agent_label: str = "UNDOGATE_SYSTEM") -> ExecutionResult:
        res = self._execute_undo(public_id, agent_label)
        audit("undone" if res.status == "undone" else "undo_failed", actor=agent_label, public_id=public_id,
              status=res.status, rows_affected=res.rows_affected, message=res.message)
        return res

    def get_checkpoint(self, public_id: str) -> dict | None:
        with psycopg.connect(self.dsn) as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(
                "SELECT public_id, status, classification, decision, agent_label, principal, sql_text, "
                "rows_affected, created_at FROM undogate.checkpoints WHERE public_id = %s", (public_id,))
            return cur.fetchone()

    def reject(self, public_id: str, actor: str) -> bool:
        """Reject a pending checkpoint. Returns False if it is not pending."""
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                conn.execute("SELECT undogate.reject_checkpoint(%s)", (public_id,))
        except psycopg.errors.RaiseException:
            return False
        audit("rejected", actor=actor, public_id=public_id)
        return True

    def _execute_undo(self, public_id: str, agent_label: str) -> ExecutionResult:
        
        try:
            with psycopg.connect(self.dsn, autocommit=False) as conn:
                try:
                    with conn.transaction(), conn.cursor() as cur:
                        cur.execute("SELECT undogate.execute_undo(%s, %s)", (public_id, agent_label))
                        result = cur.fetchone()[0]
                        return ExecutionResult(
                            status='undone', 
                            public_id=public_id, 
                            rows_affected=result['rows_affected'], message='Undo successful.'
                        )
                except psycopg.errors.LockNotAvailable:
                    return ExecutionResult(status="busy", message="Checkpoint is busy.", public_id=public_id, rows_affected=0)
                except psycopg.errors.UniqueViolation as e:
                    return ExecutionResult(status="conflict", message="Unique constraint violation during undo.", public_id=public_id, rows_affected=0)
                except psycopg.errors.DeadlockDetected as e:
                    return ExecutionResult(status="busy", message="Deadlock detected.", public_id=public_id, rows_affected=0)
                except psycopg.errors.QueryCanceled as e:
                    return ExecutionResult(status="busy", message="Statement timeout.", public_id=public_id, rows_affected=0)
                except psycopg.errors.RaiseException as e:
                    error_msg = str(e)
                    if "Checkpoint not found" in error_msg or "Cannot undo checkpoint in state" in error_msg:
                        return ExecutionResult(operation_id=None, status="denied", message=error_msg.split('\n')[0], public_id=public_id, rows_affected=0)
                    elif "already undone" in error_msg:
                        return ExecutionResult(status="already_undone", message="Checkpoint already undone.", public_id=public_id, rows_affected=0)
                    elif "Unsupported schema" in error_msg or "identity drifted" in error_msg or "missing, disabled" in error_msg:
                        return ExecutionResult(operation_id=None, status="failed", message=error_msg.split('\n')[0], public_id=public_id, rows_affected=0)
                    elif "Conflict" in error_msg:
                        return ExecutionResult(status="conflict", message=error_msg.split('\n')[0], public_id=public_id, rows_affected=0)
                    else:
                        return ExecutionResult(operation_id=None, status="failed", message=error_msg.split('\n')[0], public_id=public_id, rows_affected=0)
                except psycopg.OperationalError as e:
                    raise e
                except psycopg.Error as e:
                    # Other postgres errors (foreign key violation, check constraint violation, etc)
                    if e.sqlstate and e.sqlstate.startswith('08'):
                        raise psycopg.OperationalError(str(e)) # Let it bubble up for outcome_unknown
                    return ExecutionResult(operation_id=None, status="failed", message=str(e).split('\n')[0], public_id=public_id, rows_affected=0)
        except psycopg.OperationalError as e:
            return ExecutionResult(operation_id=None, status="unknown", message=str(e), public_id=public_id)

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
                    row_dict[col] = "***MASKED***"
                elif isinstance(row_dict[col], str):
                    row_dict[col] = sanitize_payload(row_dict[col])
            fetched_data.append(row_dict)
        return fetched_data

    def __init__(self, dsn: str, runtime_dsn: str, max_rows_without_approval: int | None = None, approval_timeout_minutes: int | None = None, protected_tables: list[str] | None = None, statement_timeout_ms: int = 5000):
        if not dsn or not runtime_dsn:
            raise ValueError("Both dsn and runtime_dsn are required")
        self.dsn = dsn
        self.runtime_dsn = runtime_dsn
        # None disables the check (library/test use); servers pass config.limits values.
        self.max_rows_without_approval = max_rows_without_approval
        self.approval_timeout_minutes = approval_timeout_minutes
        self.protected_tables = set(protected_tables or ())
        self.statement_timeout_ms = int(statement_timeout_ms)

    def create_pending_checkpoint(self, sql: str, stmt_class: str, decision: str, agent_label: str, principal: str = "system", operation_id: str | None = None) -> str:
        import psycopg
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM undogate.begin_checkpoint(%s, %s, %s, %s, %s)",
                    (sql, stmt_class, agent_label, principal, operation_id)
                )
                row = cur.fetchone()
                cp_id = row[0]
                public_id = row[1]
                # Transaction context manager will commit
                return public_id


    def execute(self, eval_result, agent_label: str = "agent", principal: str = "system", operation_id: str | None = None):
        if not self.dsn or not self.runtime_dsn:
            raise ValueError("Both dsn and runtime_dsn are required for execution.")
            
        from undogate.sentinel import AISentinel
        from undogate.policy import PolicyDecision
        
        
        safe, reason = AISentinel()._ast_firewall(eval_result.statement.sql)
        if not safe:
            audit("denied", actor=principal, sql=eval_result.statement.sql, reason=reason)
            return ExecutionResult(operation_id=operation_id, status="denied", message=f"Hard Gate Denied: {reason}")
            
        if eval_result.decision == PolicyDecision.DENY:
            audit("denied", actor=principal, sql=eval_result.statement.sql, reason=eval_result.reason)
            return ExecutionResult(operation_id=operation_id, status="denied", message=eval_result.reason)
            
        if eval_result.decision == PolicyDecision.REQUIRE_APPROVAL:
            import psycopg
            try:
                public_id = self.create_pending_checkpoint(
                    sql=eval_result.statement.sql,
                    stmt_class=eval_result.statement.stmt_class.value,
                    decision=eval_result.decision.value,
                    agent_label=agent_label,
                    principal=principal,
                    operation_id=operation_id
                )
                audit("held", actor=principal, public_id=public_id, sql=eval_result.statement.sql, reason=eval_result.reason)
                return ExecutionResult(checkpoint_id=-1, public_id=public_id, operation_id=operation_id, status="approval_required", message=f"Policy requires explicit approval: {eval_result.reason}")
            except psycopg.errors.UniqueViolation as e:
                if e.diag.constraint_name == 'idx_checkpoints_idempotency':
                    return self._resolve_duplicate(principal, operation_id, eval_result.statement.sql)
                raise
            
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
                            
                            cur.execute("SELECT set_config('statement_timeout', %s, true)", (f"{self.statement_timeout_ms}ms",))
                            cur.execute("SET TRANSACTION READ ONLY")
                            cur.execute(eval_result.statement.sql)
                            if cur.description:
                                columns = [desc[0] for desc in cur.description]
                                rows = cur.fetchmany(100)
                                fetched_data = self._mask_and_sanitize_rows(columns, rows)
            except Exception as e:
                error_msg = str(e)
                
            if error_msg:
                return ExecutionResult(operation_id=operation_id, status="failed", message=error_msg)
            return ExecutionResult(status="applied", message="Success", data=fetched_data)
            
        return self._execute_internal(eval_result.statement.sql, eval_result.statement.stmt_class.value, eval_result.decision.value, agent_label, principal, operation_id)

    def _execute_dml(self, cp_id: int, public_id: str, exec_token: str, sql_to_execute: str, enforce_row_limit: bool = False, actor: str = "system"):
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
                        cur.execute("SELECT set_config('statement_timeout', %s, true)", (f"{self.statement_timeout_ms}ms",))
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

                            cur.execute("SELECT undogate.unprotected_cascade_child(%s)", (c_oid,))
                            unprotected = cur.fetchone()[0]
                            if unprotected:
                                raise Exception(f"Write on {schema}.{table} could cascade into {unprotected}, which is not registered with Undogate; its rows could not be undone.")
                            
                        if enforce_row_limit and self.protected_tables:
                            # FK cascades can reach a protected table the SQL never names.
                            cur.execute("""
                                WITH RECURSIVE reach(oid) AS (
                                    SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                                    WHERE (n.nspname, c.relname) IN (SELECT * FROM unnest(%s::text[], %s::text[]))
                                    UNION
                                    SELECT k.conrelid FROM pg_constraint k JOIN reach r ON k.confrelid = r.oid
                                    WHERE k.contype = 'f' AND (k.confdeltype IN ('c', 'n', 'd') OR k.confupdtype IN ('c', 'n', 'd'))
                                )
                                SELECT n.nspname || '.' || c.relname FROM reach JOIN pg_class c ON c.oid = reach.oid
                                JOIN pg_namespace n ON n.oid = c.relnamespace
                            """, ([s for s, _ in tables], [t for _, t in tables]))
                            hit = sorted({r[0] for r in cur.fetchall()} & self.protected_tables)
                            if hit:
                                raise HoldForApproval(f"Write can cascade into protected table(s) {', '.join(hit)}.")

                        cur.execute(sql_to_execute)
                        if cur.description:
                            columns = [desc[0] for desc in cur.description]
                            rows = cur.fetchmany(100)
                            fetched_data = self._mask_and_sanitize_rows(columns, rows)
                                
                        rows_affected = max(cur.rowcount, 0)
                        limit = self.max_rows_without_approval
                        if enforce_row_limit and limit is not None:
                            # Count what the capture trigger recorded, not the outer command tag:
                            # includes FK cascades and anything nested in the statement.
                            cur.execute("SELECT current_setting('undogate.seq')::bigint")
                            changed = max(rows_affected, cur.fetchone()[0])
                            if changed > limit:
                                # Leaving the with-block via exception rolls the write back.
                                raise HoldForApproval(f"Rows changed ({changed}) exceeds limit ({limit}).")
                        cur.execute("SELECT undogate.finish_checkpoint(%s, %s)", (exec_token, rows_affected))
                        execution_completed = True
        except HoldForApproval as e:
            try:
                with psycopg.connect(self.dsn, autocommit=True) as rq_conn, rq_conn.cursor() as rq_cur:
                    rq_cur.execute("SELECT undogate.requeue_checkpoint(%s)", (public_id,))
            except psycopg.Error:
                return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="unknown", message=f"{e} Write was rolled back but the checkpoint could not be re-queued.")
            audit("held", actor=actor, public_id=public_id, sql=sql_to_execute, reason=str(e))
            return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="approval_required", message=f"{e} Write was rolled back and requires explicit approval.")
        except Exception as e:
            error_msg = str(e)
            
        if error_msg:
            if execution_completed:
                return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="unknown", message="Network failure during commit. Checkpoint state is unknown.")
            
            try:
                with psycopg.connect(self.dsn, autocommit=True) as fail_conn:
                    with fail_conn.cursor() as fail_cur:
                        fail_cur.execute("SELECT undogate.fail_checkpoint(%s)", (public_id,))
            except Exception:
                pass 
                
            audit("failed", actor=actor, public_id=public_id, sql=sql_to_execute, error=error_msg)
            safe_error_msg = error_msg if "exec_token" not in error_msg else "An error occurred during execution."
            return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="failed", message=safe_error_msg)

        audit("applied", actor=actor, public_id=public_id, sql=sql_to_execute, rows_affected=rows_affected)
        return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, rows_affected=rows_affected, status="applied", message="Success", data=fetched_data)

    def _execute_internal(self, sql_to_execute: str, classification: str, decision: str, agent_label: str, principal: str = "system", operation_id: str | None = None):
        import psycopg
        try:
            with psycopg.connect(self.dsn, autocommit=False) as conn:
                try:
                    with conn.transaction(), conn.cursor() as cur:
                        cur.execute(
                            "SELECT * FROM undogate.begin_checkpoint(%s, %s, %s, %s, %s)",
                            (sql_to_execute, classification, agent_label, principal, operation_id)
                        )
                        row = cur.fetchone()
                        cp_id = row[0]
                        public_id = row[1]
                    
                        cur.execute("SELECT undogate.approve_checkpoint(%s, 'ALLOW')", (public_id,))
                        exec_token = cur.fetchone()[0]
                except psycopg.errors.UniqueViolation as e:
                    if e.diag.constraint_name == 'idx_checkpoints_idempotency':
                        return self._resolve_duplicate(principal, operation_id, sql_to_execute)
                    raise

            return self._execute_dml(cp_id, public_id, exec_token, sql_to_execute, enforce_row_limit=True, actor=principal)

        except psycopg.OperationalError as e:
            if operation_id:
                return ExecutionResult(operation_id=operation_id, status="unknown", message="Network lost during checkpoint creation. Retry with same operation_id.")
            return ExecutionResult(operation_id=operation_id, status="failed", message=f"Pre-execution connection error: {e}")
    def execute_pending(self, public_id: str, actor: str = "unknown_approver"):
        import psycopg
        try:
        
        
            with psycopg.connect(self.dsn, autocommit=False) as conn:
                with conn.transaction(), conn.cursor() as cur:
                    cur.execute("SELECT id, sql_text, status FROM undogate.get_pending_checkpoint(%s)", (public_id,))
                    row = cur.fetchone()
                    if not row:
                        return ExecutionResult(operation_id=None, status="failed", message="Token not found.")
                    cp_id, sql_to_execute, status = row
                    if status != "pending":
                        return ExecutionResult(operation_id=None, status="failed", message=f"Checkpoint status is {status}, not pending.")

                    if self.approval_timeout_minutes is not None:
                        cur.execute("SELECT created_at < now() - make_interval(mins => %s) FROM undogate.checkpoints WHERE id = %s", (self.approval_timeout_minutes, cp_id))
                        if cur.fetchone()[0]:
                            cur.execute("SELECT undogate.reject_checkpoint(%s)", (public_id,))
                            audit("expired", actor=actor, public_id=public_id, sql=sql_to_execute)
                            return ExecutionResult(operation_id=None, status="denied", message=f"Checkpoint expired: pending longer than {self.approval_timeout_minutes} minutes. Ask the agent to resubmit.")

                    from undogate.sentinel import AISentinel
                    safe, reason = AISentinel()._ast_firewall(sql_to_execute)
                    if not safe:
                        cur.execute("SELECT undogate.reject_checkpoint(%s)", (public_id,))
                        audit("rejected", actor="hard_gate", public_id=public_id, sql=sql_to_execute, reason=reason)
                        # Transaction context manager will commit
                        return ExecutionResult(operation_id=None, status="denied", message=f"Hard Gate Denied: {reason}")

                    cur.execute("SELECT undogate.approve_checkpoint(%s, 'ALLOW')", (public_id,))
                    exec_token = cur.fetchone()[0]
                    # Transaction context manager will commit

            audit("approved", actor=actor, public_id=public_id, sql=sql_to_execute)
            return self._execute_dml(cp_id, public_id, exec_token, sql_to_execute, actor=actor)

        except psycopg.OperationalError as e:
            return ExecutionResult(operation_id=None, status="unknown", message=str(e))
    def check_status(self, public_id: str) -> str:
        import psycopg
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT undogate.check_checkpoint_status(%s)", (public_id,))
                    return cur.fetchone()[0]
        except psycopg.OperationalError:
            # Never print: stdout is the MCP JSON-RPC channel.
            return "unknown"

