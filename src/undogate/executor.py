import psycopg
from pydantic import BaseModel
from typing import Optional

from undogate.models import StatementEvaluation, PolicyDecision

class ExecutionResult(BaseModel):
    checkpoint_id: Optional[int] = None
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
                    
                    # Execute actual SQL
                    cur.execute(eval_result.statement.sql)
                    rows_affected = cur.rowcount if cur.rowcount >= 0 else 0
                    
                    # Finish checkpoint
                    cur.execute("SELECT undogate.finish_checkpoint(%s, %s)", (cp_id, rows_affected))
                    
                    conn.commit()
                    return ExecutionResult(checkpoint_id=cp_id, rows_affected=rows_affected, status="applied", message="Success")
                    
                except Exception as e:
                    conn.rollback()
                    return ExecutionResult(status="failed", message=str(e))
