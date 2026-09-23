import json

import pglast
import psycopg
from pydantic import BaseModel

from undogate.ddl.handlers import handle_drop_column, handle_drop_table, handle_truncate
from undogate.models import PolicyDecision, StatementEvaluation


class ExecutionResult(BaseModel):
    checkpoint_id: int | None = None
    public_id: str | None = None
    rows_affected: int = 0
    status: str
    message: str

class UndogateExecutor:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def create_pending_checkpoint(self, sql: str, stmt_class: str, decision: str, agent_label: str) -> str:
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT undogate.begin_checkpoint(%s, %s, %s, %s)",
                    (sql, stmt_class, decision, agent_label)
                )
                cp_id = cur.fetchone()[0]
                cur.execute("SELECT public_id FROM undogate.checkpoints WHERE id = %s", (cp_id,))
                return cur.fetchone()[0]

    def execute_pending(self, public_id: str) -> ExecutionResult:
        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, sql_text, status FROM undogate.checkpoints WHERE public_id = %s", (public_id,))
                row = cur.fetchone()
                if not row:
                    return ExecutionResult(status="failed", message="Token not found.")
                
                cp_id, sql_to_execute, status = row
                if status != "pending":
                    return ExecutionResult(status="failed", message=f"Checkpoint status is {status}, not pending.")

                # Proceed with execution just like a normal ALLOW, but we already have a checkpoint.
                return self._execute_internal(conn, cur, cp_id, public_id, sql_to_execute)

    def execute(self, eval_result: StatementEvaluation, agent_label: str = "agent") -> ExecutionResult:
        if eval_result.decision == PolicyDecision.DENY:
            return ExecutionResult(status="denied", message=eval_result.reason)
            
        if eval_result.decision == PolicyDecision.REQUIRE_APPROVAL:
            public_id = self.create_pending_checkpoint(
                eval_result.statement.sql, 
                eval_result.statement.stmt_class.value, 
                eval_result.decision.value, 
                agent_label
            )
            
            # Trigger Enterprise Notification
            from undogate.slack import SlackNotifier
            SlackNotifier().send_approval_request(
                token=public_id, 
                sql=eval_result.statement.sql, 
                agent=agent_label, 
                reason=eval_result.reason
            )
            
            return ExecutionResult(
                status="approval_required", 
                public_id=public_id,
                message=f"{eval_result.reason}. Use 'undogate approve {public_id}'"
            )

        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                # Begin new checkpoint
                cur.execute(
                    "SELECT undogate.begin_checkpoint(%s, %s, %s, %s)",
                    (eval_result.statement.sql, eval_result.statement.stmt_class.value, eval_result.decision.value, agent_label)
                )
                cp_id = cur.fetchone()[0]
                cur.execute("SELECT public_id FROM undogate.checkpoints WHERE id = %s", (cp_id,))
                public_id = cur.fetchone()[0]
                
                return self._execute_internal(conn, cur, cp_id, public_id, eval_result.statement.sql)
                
    def _execute_internal(self, conn, cur, cp_id, public_id, sql_to_execute) -> ExecutionResult:
        try:
            # Set the local configuration for the transaction so triggers know the cp_id
            cur.execute("SELECT set_config('undogate.checkpoint_id', %s, true)", (str(cp_id),))
            cur.execute("SELECT set_config('undogate.seq', '0', true)")
            
            ddl_undo_plan = []
            skip_execution = False

            # We must parse again to find DDL reversible objects if any
            ast = pglast.parse_sql(sql_to_execute)
            for stmt_dict in ast:
                stmt = stmt_dict.stmt
                stmt_type = type(stmt).__name__
                
                if stmt_type == "DropStmt":
                    schema = "public"
                    table_name = stmt.objects[0][0].sval
                    if len(stmt.objects[0]) > 1:
                        schema = stmt.objects[0][0].sval
                        table_name = stmt.objects[0][1].sval
                        
                    plan = handle_drop_table(cur, schema, table_name, public_id)
                    ddl_undo_plan.append(plan)
                    skip_execution = True 
                    
                elif stmt_type == "TruncateStmt":
                    table_name = stmt.relations[0].relname
                    schema = stmt.relations[0].schemaname or "public"
                    plan = handle_truncate(cur, schema, table_name, public_id)
                    ddl_undo_plan.append(plan)
                    
                elif stmt_type == "AlterTableStmt":
                    table_name = stmt.relation.relname
                    schema = stmt.relation.schemaname or "public"
                    for cmd in stmt.cmds:
                        if type(cmd).__name__ == "AlterTableCmd" and cmd.subtype == pglast.enums.AlterTableType.AT_DropColumn:
                            col_name = cmd.name
                            plan = handle_drop_column(cur, schema, table_name, col_name, public_id)
                            ddl_undo_plan.append(plan)

            if ddl_undo_plan:
                cur.execute("UPDATE undogate.checkpoints SET ddl_undo_plan = %s WHERE id = %s", (json.dumps(ddl_undo_plan), cp_id))

            if not skip_execution:
                cur.execute(sql_to_execute)
                
            rows_affected = max(cur.rowcount, 0)
            
            # Finish checkpoint
            cur.execute("SELECT undogate.finish_checkpoint(%s, %s)", (cp_id, rows_affected))
            
            conn.commit()
            
            # Audit Stream
            from undogate.audit import emit_audit_event
            emit_audit_event(cp_id, public_id, sql_to_execute, "mcp_agent", "applied", ddl_undo_plan, rows_affected)
            
            return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, rows_affected=rows_affected, status="applied", message="Success")
            
        except Exception as e:
            conn.rollback()
            # Mark checkpoint as failed
            with psycopg.connect(self.dsn, autocommit=True) as fail_conn:
                with fail_conn.cursor() as fail_cur:
                    fail_cur.execute("UPDATE undogate.checkpoints SET status = 'failed' WHERE id = %s", (cp_id,))
            
            # Audit Stream
            from undogate.audit import emit_audit_event
            emit_audit_event(cp_id, public_id, sql_to_execute, "mcp_agent", "failed", rows=0)
                    
            return ExecutionResult(checkpoint_id=cp_id, public_id=public_id, status="failed", message=str(e))
