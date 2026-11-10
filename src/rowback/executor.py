
import json
import logging

import psycopg
from psycopg import sql
from pydantic import BaseModel

from rowback.audit import audit
from rowback.sentinel import BIDI_CONTROLS

logger = logging.getLogger("rowback.executor")


class LicenseActivationStore:
    """This database's activation of the license key (rowback.license_activation), for ee/license.py."""

    def __init__(self, dsn: str):
        self.dsn = dsn

    def load(self) -> tuple[str, str | None]:
        try:
            with psycopg.connect(self.dsn) as conn:
                return conn.execute("SELECT label, activation_id FROM rowback.license_activation").fetchone()
        except psycopg.errors.UndefinedTable as e:
            raise ValueError("Startup Refusal: the Rowback schema is older than this gateway. "
                             "Run `rowback install` again to upgrade it.") from e

    def save(self, activation_id: str) -> None:
        with psycopg.connect(self.dsn) as conn:
            conn.execute("UPDATE rowback.license_activation SET activation_id = %s", (activation_id,))


class ExecutionResult(BaseModel):
    checkpoint_id: int | None = None
    public_id: str | None = None
    operation_id: str | None = None
    rows_affected: int = 0
    data: list[dict] | None = None
    status: str
    message: str
    error_code: str | None = None

def _agent_message(e: Exception) -> str:
    """The part of an error the agent may see. Never PostgreSQL's DETAIL: for NOT NULL and
    CHECK violations it prints the whole failing row, secret columns included."""
    if isinstance(e, psycopg.errors.InsufficientPrivilege):
        return (f"{e.diag.message_primary}. Some columns are hidden from agents; "
                "name the columns you need instead of *.")
    if isinstance(e, psycopg.Error):
        return e.diag.message_primary or str(e).split("\n")[0]
    return str(e)


MASK = "***MASKED***"


def _mask_json(value, secret):
    """JSON (dicts/lists, or text that parses as JSON) with every secret-looking key masked."""
    if isinstance(value, dict):
        return {k: (MASK if secret(k) and v not in (None, "") else _mask_json(v, secret)) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_json(v, secret) for v in value]
    if isinstance(value, str) and value[:1] in ("{", "["):
        import json
        try:
            parsed = json.loads(value)
        except ValueError:
            return value
        masked = _mask_json(parsed, secret)
        return value if masked == parsed else json.dumps(masked)
    return value


class HoldForApproval(Exception):
    """Write must be rolled back and sent to a human instead. `preview` is what it changed
    before the rollback; `policy` marks a hold the policy asked for up front."""

    def __init__(self, message: str, preview: dict | None = None, policy: bool = False):
        super().__init__(message)
        self.preview = preview
        self.policy = policy


# How far back each plan can undo, in hours. None = no limit.
UNDO_WINDOW_HOURS = {"free": 24, "pro": 30 * 24, "enterprise": None}


def undo_window_message(hours: int) -> str:
    span = f"{hours // 24} days" if hours % 24 == 0 and hours > 24 else f"{hours} hours"
    return (f"This checkpoint is older than the {span} undo window of this Rowback plan. "
            "Rowback Pro undoes up to 30 days back, Enterprise without a limit: see https://github.com/ege-usta/rowback#pricing")


PREVIEW_ROWS = 20
PREVIEW_CHARS = 200  # per value shown to an approver
# What a query hands back to an agent. The gateway reads at most one row past RESULT_ROWS (a
# server-side cursor), and cuts any value and the whole result to sizes an agent's context can hold.
RESULT_ROWS = 100
RESULT_VALUE_CHARS = 4_000
RESULT_TOTAL_CHARS = 100_000


def _cut(v, limit: int = RESULT_VALUE_CHARS):
    """A value no longer than `limit` characters; JSON that is too long becomes its cut text."""
    if isinstance(v, (dict, list)):
        text = json.dumps(v, default=str)
        if len(text) <= limit:
            return v
        v = text
    if isinstance(v, str) and len(v) > limit:
        return f"{v[:limit]}… ({len(v) - limit} more characters; use substr() or a narrower query to read the rest)"
    return v


# Tables an ON DELETE/UPDATE cascade from %(t)s can reach that have triggers of their own and were not
# registered --allow-triggers: undo would refuse to restore their rows.
CASCADE_TRIGGER_SQL = """
    WITH RECURSIVE reach(oid) AS (
        SELECT %(t)s::oid
        UNION
        SELECT k.conrelid FROM pg_constraint k JOIN reach r ON k.confrelid = r.oid
        WHERE k.contype = 'f' AND (k.confdeltype IN ('c', 'n', 'd') OR k.confupdtype IN ('c', 'n', 'd'))
    )
    SELECT n.nspname || '.' || c.relname FROM reach r
    JOIN pg_class c ON c.oid = r.oid JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE r.oid <> %(t)s
      AND EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = r.oid AND NOT g.tgisinternal AND g.tgname <> 'rowback_capture')
      AND NOT coalesce((SELECT allow_triggers FROM rowback.registered_tables WHERE table_oid = r.oid), false)
    ORDER BY 1 LIMIT 1
"""


class RowbackExecutor:
    # ponytail: a fresh connection per step (~5 ms each, ~18 ms p50 per captured write
    # on localhost) keeps outcome-unknown handling exact. Add psycopg_pool when the DB
    # is remote/TLS and latency matters; pooled conns must be discarded after errors.

    def _resolve_duplicate(self, principal: str, operation_id: str, sql_to_execute: str):
        import psycopg
        with psycopg.connect(self.dsn) as check_conn, check_conn.cursor() as check_cur:
            check_cur.execute("SELECT id, public_id, status, rows_affected, sql_text FROM rowback.checkpoints WHERE principal = %s AND operation_id = %s", (principal, operation_id))
            existing = check_cur.fetchone()
            if existing:
                if existing[4] != sql_to_execute:
                    return ExecutionResult(checkpoint_id=existing[0], public_id=existing[1], operation_id=operation_id, status="failed", error_code="conflict", message=f"Conflict: operation_id {operation_id} was already used with a different SQL payload.")
                return ExecutionResult(checkpoint_id=existing[0], public_id=existing[1], operation_id=operation_id, status="approval_required" if existing[2] == "pending" else existing[2], rows_affected=existing[3] or 0, message="Idempotent replay")
        raise RuntimeError(f"UniqueViolation occurred but no existing record found for {principal}:{operation_id}")

    def execute_undo(self, public_id: str, agent_label: str = "ROWBACK_SYSTEM") -> ExecutionResult:
        res = self._execute_undo(public_id, agent_label)
        audit("undone" if res.status == "undone" else "undo_failed", actor=agent_label, public_id=public_id,
              status=res.status, rows_affected=res.rows_affected, message=res.message)
        return res

    def get_checkpoint(self, public_id: str) -> dict | None:
        with psycopg.connect(self.dsn) as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(
                "SELECT c.public_id, c.status, c.classification, c.decision, c.agent_label, c.principal, c.sql_text, "
                "c.rows_affected, c.created_at, p.preview FROM rowback.checkpoints c "
                "LEFT JOIN rowback.previews p USING (public_id) WHERE c.public_id = %s", (public_id,))
            cp = cur.fetchone()
            if cp and cp["status"] == "pending":
                # Tell an approver, before they decide, if this write could not be undone — they
                # see only the SQL otherwise. Best-effort: any introspection error adds no warning.
                cp["undo_warning"] = self._undo_warning(conn, cp["sql_text"])
            return cp

    def _undo_warning(self, conn, sql_text: str) -> str | None:
        """Name any target table whose own schema makes this write impossible to undo: its own
        triggers (without --allow-triggers), rewrite rules, or inheritance — the same conditions
        rowback.execute_undo refuses on. Read-only and defensive; returns None on any error."""
        try:
            import pglast

            from rowback.sql.classify import extract_tables_from_ast
            tables = extract_tables_from_ast(pglast.parse_sql(sql_text))
            blocked = []
            with conn.cursor() as cur:
                for schema, table in tables:
                    cur.execute(
                        "SELECT "
                        "EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal AND t.tgname <> 'rowback_capture') "
                        "  AND NOT coalesce((SELECT allow_triggers FROM rowback.registered_tables WHERE table_oid = c.oid), false), "
                        "EXISTS(SELECT 1 FROM pg_rewrite WHERE ev_class = c.oid AND rulename <> '_RETURN'), "
                        "rowback.inheritance_problem(c.oid) "
                        "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                        "WHERE n.nspname = %s AND c.relname = %s AND c.relkind IN ('r', 'p')",
                        (schema, table))
                    row = cur.fetchone()
                    if not row:
                        continue
                    trig, rules, inh = row
                    cur.execute("SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                                "WHERE n.nspname = %s AND c.relname = %s", (schema, table))
                    cur.execute(CASCADE_TRIGGER_SQL, {"t": cur.fetchone()[0]})
                    cascade = cur.fetchone()
                    if cascade:
                        blocked.append(f"{schema}.{table} cascades into {cascade[0]}, which has its own triggers")
                    if inh:  # first: for a partitioned table it names the exact partition and reason
                        blocked.append(inh)
                    elif trig:
                        blocked.append(f"{schema}.{table} has its own triggers (register it with --allow-triggers to make this undoable)")
                    elif rules:
                        blocked.append(f"{schema}.{table} has rewrite rules")
            if blocked:
                return "This write cannot be undone once approved: " + "; ".join(blocked)
        except Exception:
            return None
        return None

    def list_checkpoints(self, since=None, limit: int | None = None) -> list[dict]:
        """Newest first, with who approved each one. limit None = all (for exports)."""
        with psycopg.connect(self.dsn) as conn, conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(
                "SELECT c.public_id, c.created_at, c.status, c.classification, c.agent_label, c.principal, "
                "c.sql_text, c.rows_affected, c.chain_seq, c.hash, "
                "coalesce(array_agg(a.actor ORDER BY a.approved_at) FILTER (WHERE a.actor IS NOT NULL), '{}') AS approved_by, "
                "(SELECT p.preview FROM rowback.previews p WHERE p.public_id = c.public_id) AS preview "
                "FROM rowback.checkpoints c LEFT JOIN rowback.approvals a USING (public_id) "
                "WHERE %(since)s::timestamptz IS NULL OR c.created_at >= %(since)s "
                "GROUP BY c.id ORDER BY c.id DESC LIMIT %(limit)s",
                {"since": since, "limit": limit})
            return cur.fetchall()

    def reject(self, public_id: str, actor: str) -> bool:
        """Reject a pending checkpoint. Returns False if it is not pending."""
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                conn.execute("SELECT rowback.reject_checkpoint(%s)", (public_id,))
        except psycopg.errors.RaiseException:
            return False
        audit("rejected", actor=actor, public_id=public_id)
        return True

    def _execute_undo(self, public_id: str, agent_label: str) -> ExecutionResult:

        try:
            with psycopg.connect(self.dsn, autocommit=False) as conn:
                try:
                    with conn.transaction(), conn.cursor() as cur:
                        if self.undo_window_hours is not None:
                            # Age counts from when the write ran: the last approval, else when it was made.
                            cur.execute(
                                "SELECT now() - coalesce((SELECT max(a.approved_at) FROM rowback.approvals a "
                                "WHERE a.public_id = c.public_id), c.created_at) > make_interval(hours => %s) "
                                "FROM rowback.checkpoints c WHERE c.public_id = %s",
                                (self.undo_window_hours, public_id))
                            row = cur.fetchone()
                            if row and row[0]:
                                return ExecutionResult(status="expired", message=undo_window_message(self.undo_window_hours),
                                                       public_id=public_id, rows_affected=0)
                        cur.execute("SELECT rowback.execute_undo(%s, %s)", (public_id, agent_label))
                        result = cur.fetchone()[0]
                        return ExecutionResult(
                            status='undone',
                            public_id=public_id,
                            rows_affected=result['rows_affected'], message='Undo successful.'
                        )
                except psycopg.errors.LockNotAvailable:
                    return ExecutionResult(status="busy", message="Checkpoint is busy.", public_id=public_id, rows_affected=0)
                except psycopg.errors.UniqueViolation:
                    return ExecutionResult(status="conflict", message="Unique constraint violation during undo.", public_id=public_id, rows_affected=0)
                except psycopg.errors.DeadlockDetected:
                    return ExecutionResult(status="busy", message="Deadlock detected.", public_id=public_id, rows_affected=0)
                except psycopg.errors.QueryCanceled:
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
                        raise psycopg.OperationalError(str(e)) from e # Let it bubble up for outcome_unknown
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

        from rowback.sql.classify import is_secret

        def secret(name) -> bool:
            return is_secret(name, self.sensitive_columns)
        fetched_data = []
        for row in rows:
            row_dict = dict(zip(columns, row, strict=True))
            for col in columns:
                if secret(col) and row_dict[col]:
                    row_dict[col] = MASK
                    continue
                row_dict[col] = _cut(_mask_json(row_dict[col], secret))
                if isinstance(row_dict[col], str):
                    row_dict[col] = sanitize_payload(row_dict[col])
            fetched_data.append(row_dict)
        return fetched_data

    def __init__(self, dsn: str, runtime_dsn: str, max_rows_without_approval: int | None = None, approval_timeout_minutes: int | None = None, protected_tables: list[str] | None = None, statement_timeout_ms: int = 5000, required_approvals: int = 1, sensitive_columns: list[str] | None = None, preview_writes: bool = False, undo_window_hours: int | None = None):
        if not dsn or not runtime_dsn:
            raise ValueError("Both dsn and runtime_dsn are required")
        self.dsn = dsn
        self.runtime_dsn = runtime_dsn
        # None disables the check (library/test use); servers pass config.limits values.
        self.max_rows_without_approval = max_rows_without_approval
        self.approval_timeout_minutes = approval_timeout_minutes
        self.protected_tables = set(protected_tables or ())
        self.statement_timeout_ms = int(statement_timeout_ms)
        self.required_approvals = int(required_approvals)  # distinct people per held write
        self.sensitive_columns = tuple(sensitive_columns or ())  # config names treated like `password`
        self.preview_writes = preview_writes  # dry-run held writes for an approval preview (config.approvals.preview)
        self.undo_window_hours = undo_window_hours  # None = no limit (library/test use); servers pass the plan's window

    def create_pending_checkpoint(self, sql: str, stmt_class: str, decision: str, agent_label: str, principal: str = "system", operation_id: str | None = None) -> str:
        import psycopg
        with psycopg.connect(self.dsn, autocommit=True) as conn:
            with conn.transaction(), conn.cursor() as cur:
                cur.execute(
                    "SELECT * FROM rowback.begin_checkpoint(%s, %s, %s, %s, %s)",
                    (sql, stmt_class, agent_label, principal, operation_id)
                )
                row = cur.fetchone()
                public_id = row[1]
                # Transaction context manager will commit
                return public_id


    def execute(self, eval_result, agent_label: str = "agent", principal: str = "system", operation_id: str | None = None):
        if not self.dsn or not self.runtime_dsn:
            raise ValueError("Both dsn and runtime_dsn are required for execution.")

        from rowback.policy import PolicyDecision
        from rowback.sentinel import AISentinel


        safe, reason = AISentinel()._ast_firewall(eval_result.statement.sql)
        if not safe:
            audit("denied", actor=principal, sql=eval_result.statement.sql, reason=reason)
            return ExecutionResult(operation_id=operation_id, status="denied", message=f"Hard Gate Denied: {reason}")

        if eval_result.decision == PolicyDecision.DENY:
            audit("denied", actor=principal, sql=eval_result.statement.sql, reason=eval_result.reason)
            return ExecutionResult(operation_id=operation_id, status="denied", message=eval_result.reason)

        if eval_result.decision == PolicyDecision.REQUIRE_APPROVAL and self.preview_writes \
                and eval_result.statement.stmt_class.value == "WRITE_DML":
            # Dry run: execute, record what changed, roll back, then queue for a person.
            return self._execute_internal(eval_result.statement.sql, eval_result.statement.stmt_class.value,
                                          eval_result.decision.value, agent_label, principal, operation_id,
                                          hold_reason=f"Policy requires explicit approval: {eval_result.reason}")

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
            message = "Success"
            try:
                with psycopg.connect(self.runtime_dsn, autocommit=False) as conn:
                    with conn.transaction():
                        with conn.transaction(), conn.cursor() as cur:
                            import pglast

                            from rowback.sql.classify import check_sensitive_columns
                            ast = pglast.parse_sql(eval_result.statement.sql)
                            sens_cols = check_sensitive_columns(ast, self.sensitive_columns)
                            if sens_cols:
                                # A reach for a secret is what an operator reviews later: keep it.
                                audit("denied", actor=principal, sql=eval_result.statement.sql, reason=f"sensitive columns {sens_cols}")
                                raise Exception(f"Access denied: Query contains sensitive columns {sens_cols}")

                            cur.execute("SELECT set_config('statement_timeout', %s, true)", (f"{self.statement_timeout_ms}ms",))
                            cur.execute("SET TRANSACTION READ ONLY")
                            # A SELECT runs through a server-side cursor, so a query over millions of
                            # rows sends the gateway only the page it returns. EXPLAIN and SHOW can't.
                            is_select = type(ast[0].stmt).__name__ == "SelectStmt"
                            with conn.cursor(name="rowback_read") if is_select else conn.cursor() as rc:
                                rc.execute(eval_result.statement.sql)
                                if rc.description:
                                    columns = [desc[0] for desc in rc.description]
                                    rows = rc.fetchmany(RESULT_ROWS + 1)
                                    more = len(rows) > RESULT_ROWS
                                    fetched_data, used = [], 0
                                    for row in self._mask_and_sanitize_rows(columns, rows[:RESULT_ROWS]):
                                        used += len(json.dumps(row, default=str))
                                        if fetched_data and used > RESULT_TOTAL_CHARS:
                                            more = True
                                            break
                                        fetched_data.append(row)
                                    if more:
                                        message = (f"Success: showing the first {len(fetched_data)} rows; more exist. "
                                                   "Narrow the query (WHERE, LIMIT, fewer columns) to see the rest.")
            except Exception as e:
                error_msg = _agent_message(e)

            if error_msg:
                return ExecutionResult(operation_id=operation_id, status="failed", message=error_msg)
            return ExecutionResult(status="applied", message=message, data=fetched_data)

        return self._execute_internal(eval_result.statement.sql, eval_result.statement.stmt_class.value, eval_result.decision.value, agent_label, principal, operation_id)

    def _preview(self, cur, exec_token) -> dict:
        """What the in-flight write changed, masked like agent results. Updates list only the
        columns that changed; inserts and deletes list the row."""
        from rowback.sql.classify import is_secret

        def secret(name) -> bool:
            return is_secret(name, self.sensitive_columns)

        def shown(v):
            # Agent-written data reaches a person here: no direction overrides that reorder what
            # they read, and no value long enough to push the rest of the preview out of view.
            if isinstance(v, str):
                v = "".join(f"\\u{ord(ch):04x}" if ch in BIDI_CONTROLS else ch for ch in v)
                if len(v) > PREVIEW_CHARS:
                    v = f"{v[:PREVIEW_CHARS]}… ({len(v) - PREVIEW_CHARS} more characters)"
                return v
            if isinstance(v, dict):
                return {shown(k): shown(x) for k, x in v.items()}
            if isinstance(v, list):
                return [shown(x) for x in v]
            return v

        def clean(row):
            row = row or {}  # NULL when the role may SELECT none of the columns
            return {shown(k): shown(MASK if secret(k) and v not in (None, "") else _mask_json(v, secret)) for k, v in row.items()}

        cur.execute("SELECT rowback.preview_changes(%s, %s)", (exec_token, PREVIEW_ROWS))
        p = cur.fetchone()[0]
        sample = []
        for item in p["sample"]:
            before, after = clean(item["before"]), clean(item["after"])
            entry = {"table": item["table"], "op": {"I": "insert", "U": "update", "D": "delete"}[item["op"]],
                     "key": clean(item["key"])}
            if entry["op"] == "update":
                entry["changes"] = {k: [before.get(k), after.get(k)] for k in after if before.get(k) != after.get(k)}
            else:
                entry["row"] = before if entry["op"] == "delete" else after
            sample.append(entry)
        return {"rows": p["rows"], "tables": p["tables"], "sample": sample, "truncated": p["rows"] > len(sample),
                "digest": p["digest"]}

    def _execute_dml(self, cp_id: int, public_id: str, exec_token: str, sql_to_execute: str, enforce_row_limit: bool = False,
                     actor: str = "system", hold_reason: str | None = None, expect: dict | None = None):
        import psycopg


        error_msg = None
        fetched_data = None
        rows_affected = 0
        execution_completed = False
        try:
            with psycopg.connect(self.runtime_dsn, autocommit=False) as runtime_conn:
                with runtime_conn.transaction():
                    with runtime_conn.cursor() as cur:
                        cur.execute("SELECT set_config('statement_timeout', %s, true)", (f"{self.statement_timeout_ms}ms",))
                        cur.execute("SELECT rowback.claim_checkpoint(%s)", (exec_token,))
                        cur.execute("SELECT set_config('rowback.checkpoint_id', %s, true)", (str(cp_id),))
                        cur.execute("SELECT set_config('rowback.capability_token', %s, true)", (str(exec_token),))
                        cur.execute("SELECT set_config('rowback.seq', '0', true)")

                        import pglast

                        from rowback.sql.classify import (
                            check_sensitive_columns,
                            extract_tables_from_ast,
                        )
                        ast = pglast.parse_sql(sql_to_execute)
                        tables = extract_tables_from_ast(ast)

                        sens_cols = check_sensitive_columns(ast, self.sensitive_columns)
                        if sens_cols:
                            raise Exception(f"Access denied: Query contains sensitive columns {sens_cols}")

                        for schema, table in tables:
                            if schema in ('rowback', 'rowback_trash', 'information_schema', 'pg_catalog'):
                                raise Exception(f"Direct DML on system schema {schema} is forbidden.")
                            # Before LOCK, which needs privileges only registered tables have: say why plainly.
                            cur.execute("SELECT EXISTS (SELECT 1 FROM rowback.registered_tables WHERE schema_name = %s AND table_name = %s)",
                                        (schema, table))
                            if not cur.fetchone()[0]:
                                raise Exception(f"Table {schema}.{table} is not registered for mutation. "
                                                "For a partition, write through its partitioned table.")
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
                                    array_to_string(rowback.primary_key_columns(c.oid), ',') AS actual_pk_column
                                FROM pg_class c
                                JOIN pg_namespace n ON n.oid = c.relnamespace
                                LEFT JOIN rowback.registered_tables r ON r.schema_name = n.nspname AND r.table_name = c.relname
                                LEFT JOIN pg_trigger t ON t.tgrelid = c.oid AND t.tgname = 'rowback_capture'
                                LEFT JOIN pg_proc p ON p.proname = 'capture_row_change' AND p.pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'rowback') AND p.pronargs = 0
                                WHERE n.nspname = %s AND c.relname = %s AND c.relkind IN ('r', 'p')
                            """, (schema, table))
                            row2 = cur.fetchone()

                            if not row2: raise Exception(f"Table {schema}.{table} does not exist.")

                            (c_oid, r_table_oid, pk_column, tgenabled, tgtype, tgattr, tgqual, tgfoid, expected_foid, actual_pk_column) = row2

                            if r_table_oid is None:
                                raise Exception(f"Table {schema}.{table} is not registered for mutation.")
                            if c_oid != r_table_oid:
                                raise Exception(f"Registration mismatch for {schema}.{table}: OID has changed.")

                            if actual_pk_column is None:
                                raise Exception(f"Table {schema}.{table} has no primary key; undo needs one to find rows again.")
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
                            # Rows reached through inheritance children or rewrite rules never pass
                            # the capture trigger, so they could not be undone: refuse before writing.
                            # Partitioned tables pass when their whole tree is captured (inheritance_problem).
                            cur.execute(
                                "SELECT rowback.inheritance_problem(%(t)s), "
                                "EXISTS (SELECT 1 FROM pg_rewrite WHERE ev_class = %(t)s AND rulename <> '_RETURN'), "
                                "EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = %(t)s AND NOT tgisinternal AND tgname <> 'rowback_capture') "
                                "AND NOT coalesce((SELECT allow_triggers FROM rowback.registered_tables WHERE table_oid = %(t)s), false)",
                                {"t": c_oid})
                            in_inheritance, has_rules, has_user_triggers = cur.fetchone()
                            # Undo refuses every table it must restore that has triggers of its own,
                            # and that includes tables a cascade reaches: find them before writing.
                            cur.execute(CASCADE_TRIGGER_SQL, {"t": c_oid})
                            cascade_trigger = cur.fetchone()
                            if in_inheritance:
                                raise Exception(f"Table {schema}.{table}: {in_inheritance}.")
                            if has_rules:
                                raise Exception(f"Table {schema}.{table} has rewrite rules, which move writes past capture.")
                            if cascade_trigger and enforce_row_limit and not has_user_triggers:
                                raise HoldForApproval(((hold_reason + " ") if hold_reason else "")
                                                      + f"A write on {schema}.{table} can cascade into {cascade_trigger[0]}, which has "
                                                      "its own triggers, so it couldn't be undone. If they only change the row itself, "
                                                      "register that table with --allow-triggers.",
                                                      policy=bool(hold_reason and hold_reason.startswith("Policy requires")))
                            if has_user_triggers and enforce_row_limit:
                                # Undo refuses tables with their own triggers unless registered with
                                # --allow-triggers, so this write could not be undone.
                                # Held before it runs: a dry run would fire triggers a rollback might not take back.
                                raise HoldForApproval(((hold_reason + " ") if hold_reason else "")
                                                      + f"Table {schema}.{table} has its own triggers, so this write can't be undone. "
                                                      "If they only change the row itself (like updated_at), register it with --allow-triggers.",
                                                      policy=bool(hold_reason and hold_reason.startswith("Policy requires")))

                            if tgattr and str(tgattr) != '' and str(tgattr) != 'b\'\'':
                                raise Exception(f"Trigger column restrictions (UPDATE OF) are not allowed on {schema}.{table}.")

                            cur.execute("SELECT rowback.unprotected_cascade_child(%s)", (c_oid,))
                            unprotected = cur.fetchone()[0]
                            if unprotected:
                                raise Exception(f"Write on {schema}.{table} could cascade into {unprotected}, which is not registered with Rowback; its rows could not be undone.")

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
                                # Held after it runs (and is rolled back), so the preview shows the cascade.
                                hold_reason = hold_reason or f"Write can cascade into protected table(s) {', '.join(hit)}."

                        cur.execute(sql_to_execute)
                        if cur.description:
                            columns = [desc[0] for desc in cur.description]
                            rows = cur.fetchmany(100)
                            fetched_data = self._mask_and_sanitize_rows(columns, rows)

                        rows_affected = max(cur.rowcount, 0)
                        if expect and expect.get("digest"):
                            # The person approved the rows the preview showed. If the data or the
                            # clock moved since (`WHERE ... OR now() > ...`), refuse; rollback below.
                            cur.execute("SELECT rowback.preview_changes(%s, 0)", (exec_token,))
                            now = cur.fetchone()[0]
                            if now["digest"] != expect["digest"]:
                                raise Exception(f"This write now changes {now['rows']} row(s), not the {expect['rows']} previewed "
                                                "when it was held (the data or the time changed). Nothing was changed; "
                                                "ask the agent to send it again.")
                        limit = self.max_rows_without_approval
                        if enforce_row_limit and limit is not None:
                            # Count what the capture trigger recorded, not the outer command tag:
                            # includes FK cascades and anything nested in the statement.
                            cur.execute("SELECT current_setting('rowback.seq')::bigint")
                            changed = max(rows_affected, cur.fetchone()[0])
                            if changed > limit and not hold_reason:
                                hold_reason = f"Rows changed ({changed}) exceeds limit ({limit})."
                        if hold_reason:
                            # Leaving the with-block via exception rolls the write back.
                            preview = self._preview(cur, exec_token) if self.preview_writes else None
                            raise HoldForApproval(hold_reason, preview, policy=hold_reason.startswith("Policy requires"))
                        cur.execute("SELECT rowback.finish_checkpoint(%s, %s)", (exec_token, rows_affected))
                        execution_completed = True
        except HoldForApproval as e:
            try:
                # One transaction: an approver never sees the held write without its preview.
                with psycopg.connect(self.dsn) as rq_conn, rq_conn.transaction(), rq_conn.cursor() as rq_cur:
                    rq_cur.execute("SELECT rowback.requeue_checkpoint(%s)", (public_id,))
                    if e.preview is not None:
                        rq_cur.execute("INSERT INTO rowback.previews (public_id, preview) VALUES (%s, %s) "
                                       "ON CONFLICT (public_id) DO UPDATE SET preview = EXCLUDED.preview, created_at = now()",
                                       (public_id, psycopg.types.json.Jsonb(e.preview)))
            except psycopg.Error:
                return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="unknown", message=f"{e} Write was rolled back but the checkpoint could not be re-queued.")
            audit("held", actor=actor, public_id=public_id, sql=sql_to_execute, reason=str(e))
            message = str(e) if e.policy else f"{e} Write was rolled back and requires explicit approval."
            return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="approval_required", message=message)
        except Exception as e:
            error_msg = _agent_message(e)

        if error_msg:
            if execution_completed:
                return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="unknown", message="Network failure during commit. Checkpoint state is unknown.")

            try:
                with psycopg.connect(self.dsn, autocommit=True) as fail_conn:
                    with fail_conn.cursor() as fail_cur:
                        fail_cur.execute("SELECT rowback.fail_checkpoint(%s)", (public_id,))
            except Exception as e:
                # The write itself failed; only the bookkeeping did too. Surface it so an operator can close the checkpoint.
                logger.error("Could not mark checkpoint %s as failed: %s", public_id, type(e).__name__)

            audit("failed", actor=actor, public_id=public_id, sql=sql_to_execute, error=error_msg)
            safe_error_msg = error_msg if "exec_token" not in error_msg else "An error occurred during execution."
            return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="failed", message=safe_error_msg)

        audit("applied", actor=actor, public_id=public_id, sql=sql_to_execute, rows_affected=rows_affected)
        return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, rows_affected=rows_affected, status="applied", message="Success", data=fetched_data)

    def _execute_internal(self, sql_to_execute: str, classification: str, decision: str, agent_label: str, principal: str = "system",
                          operation_id: str | None = None, hold_reason: str | None = None):
        import psycopg
        try:
            with psycopg.connect(self.dsn, autocommit=False) as conn:
                try:
                    with conn.transaction(), conn.cursor() as cur:
                        cur.execute(
                            "SELECT * FROM rowback.begin_checkpoint(%s, %s, %s, %s, %s)",
                            (sql_to_execute, classification, agent_label, principal, operation_id)
                        )
                        row = cur.fetchone()
                        cp_id = row[0]
                        public_id = row[1]

                        cur.execute("SELECT rowback.approve_checkpoint(%s, 'ALLOW')", (public_id,))
                        exec_token = cur.fetchone()[0]
                except psycopg.errors.UniqueViolation as e:
                    if e.diag.constraint_name == 'idx_checkpoints_idempotency':
                        return self._resolve_duplicate(principal, operation_id, sql_to_execute)
                    raise

            return self._execute_dml(cp_id, public_id, exec_token, sql_to_execute, enforce_row_limit=True, actor=principal,
                                     hold_reason=hold_reason)

        except psycopg.OperationalError as e:
            if operation_id:
                return ExecutionResult(operation_id=operation_id, status="unknown", message="Network lost during checkpoint creation. Retry with same operation_id.")
            return ExecutionResult(operation_id=operation_id, status="failed", message=f"Pre-execution connection error: {e}")
    def execute_pending(self, public_id: str, actor: str = "unknown_approver"):
        import psycopg
        try:


            with psycopg.connect(self.dsn, autocommit=False) as conn:
                with conn.transaction(), conn.cursor() as cur:
                    cur.execute("SELECT id, sql_text, status FROM rowback.get_pending_checkpoint(%s)", (public_id,))
                    row = cur.fetchone()
                    if not row:
                        return ExecutionResult(operation_id=None, status="failed", message="Token not found.")
                    cp_id, sql_to_execute, status = row
                    if status != "pending":
                        return ExecutionResult(operation_id=None, status="failed", message=f"Checkpoint status is {status}, not pending.")

                    if self.approval_timeout_minutes is not None:
                        cur.execute("SELECT created_at < now() - make_interval(mins => %s) FROM rowback.checkpoints WHERE id = %s", (self.approval_timeout_minutes, cp_id))
                        if cur.fetchone()[0]:
                            cur.execute("SELECT rowback.reject_checkpoint(%s)", (public_id,))
                            audit("expired", actor=actor, public_id=public_id, sql=sql_to_execute)
                            return ExecutionResult(operation_id=None, status="denied", message=f"Checkpoint expired: pending longer than {self.approval_timeout_minutes} minutes. Ask the agent to resubmit.")

                    from rowback.sentinel import AISentinel
                    safe, reason = AISentinel()._ast_firewall(sql_to_execute)
                    if not safe:
                        cur.execute("SELECT rowback.reject_checkpoint(%s)", (public_id,))
                        audit("rejected", actor="hard_gate", public_id=public_id, sql=sql_to_execute, reason=reason)
                        # Transaction context manager will commit
                        return ExecutionResult(operation_id=None, status="denied", message=f"Hard Gate Denied: {reason}")

                    cur.execute("SELECT rowback.record_approval(%s, %s)", (public_id, actor))
                    approvals = cur.fetchone()[0]
                    if self.required_approvals > 1 and approvals < self.required_approvals:
                        audit("approval_recorded", actor=actor, public_id=public_id, approvals=approvals, required=self.required_approvals)
                        note = ("" if actor.startswith(("oidc:", "slack:")) else
                                " Admin-key and CLI approvals are recorded but don't count toward the two-person rule; approve with SSO or Slack.")
                        return ExecutionResult(operation_id=None, status="awaiting_approval", public_id=public_id,
                                               message=f"{approvals} of {self.required_approvals} approvals.{note}")

                    cur.execute("SELECT rowback.approve_checkpoint(%s, 'ALLOW')", (public_id,))
                    exec_token = cur.fetchone()[0]
                    cur.execute("SELECT preview FROM rowback.previews WHERE public_id = %s", (public_id,))
                    stored = cur.fetchone()
                    # Transaction context manager will commit

            audit("approved", actor=actor, public_id=public_id, sql=sql_to_execute)
            return self._execute_dml(cp_id, public_id, exec_token, sql_to_execute, actor=actor,
                                     expect=stored[0] if stored else None)

        except psycopg.OperationalError as e:
            return ExecutionResult(operation_id=None, status="unknown", message=str(e))
    def check_status(self, public_id: str) -> str:
        import psycopg
        try:
            with psycopg.connect(self.dsn, autocommit=True) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT rowback.check_checkpoint_status(%s)", (public_id,))
                    return cur.fetchone()[0]
        except psycopg.OperationalError:
            # Never print: stdout is the MCP JSON-RPC channel.
            return "unknown"

