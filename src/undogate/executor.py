import json

import pglast
import psycopg
from pydantic import BaseModel

from undogate.ddl.handlers import handle_drop_column, handle_drop_table, handle_truncate
from undogate.models import PolicyDecision, StatementClass, StatementEvaluation


class ExecutionResult(BaseModel):
    checkpoint_id: int | None = None
    rows_affected: int = 0
    status: str
    message: str

class UndogateExecutor:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def execute(self, eval_result: StatementEvaluation, agent_label: str = "agent") -> ExecutionResult:
        if eval_result.decision == PolicyDecision.DENY:
            return ExecutionResult(status="denied", message=eval_result.reason)
            
        if eval_result.decision == PolicyDecision.REQUIRE_APPROVAL:
            return ExecutionResult(status="approval_required", message=eval_result.reason)

        with psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                try:
                    # Begin checkpoint
                    cur.execute(
                        "SELECT undogate.begin_checkpoint(%s, %s, %s, %s)",
                        (eval_result.statement.sql, eval_result.statement.stmt_class.value, eval_result.decision.value, agent_label)
                    )
                    cp_id = cur.fetchone()[0]
                    
                    # Fetch public_id
                    cur.execute("SELECT public_id FROM undogate.checkpoints WHERE id = %s", (cp_id,))
                    public_id = cur.fetchone()[0]

                    ddl_undo_plan = []
                    sql_to_execute = eval_result.statement.sql
                    skip_execution = False

                    # Handle DDL before executing
                    if eval_result.statement.stmt_class == StatementClass.DDL_REVERSIBLE:
                        ast = pglast.parse_sql(eval_result.statement.sql)
                        for stmt_dict in ast:
                            stmt = stmt_dict.stmt
                            stmt_type = type(stmt).__name__
                            
                            if stmt_type == "DropStmt":
                                # Assuming single table drop for MVP
                                table_name = stmt.objects[0][0].sval
                                schema = "public"
                                if len(stmt.objects[0]) > 1:
                                    schema = stmt.objects[0][0].sval
                                    table_name = stmt.objects[0][1].sval
                                    
                                plan = handle_drop_table(cur, schema, table_name, public_id)
                                ddl_undo_plan.append(plan)
                                skip_execution = True # Handled by rename, do not run DROP
                                
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

                    # Execute actual SQL
                    if not skip_execution:
                        cur.execute(sql_to_execute)
                        
                    rows_affected = max(cur.rowcount, 0)
                    
                    # Finish checkpoint
                    cur.execute("SELECT undogate.finish_checkpoint(%s, %s)", (cp_id, rows_affected))
                    
                    conn.commit()
                    return ExecutionResult(checkpoint_id=cp_id, rows_affected=rows_affected, status="applied", message="Success")
                    
                except Exception as e:
                    conn.rollback()
                    return ExecutionResult(status="failed", message=str(e))
