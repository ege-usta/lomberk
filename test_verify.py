import psycopg
from testcontainers.community.postgres import PostgresContainer
import os
import sys

with PostgresContainer("postgres:16-alpine") as postgres:
    dsn = postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
    os.environ["UNDOGATE_ADMIN_DSN"] = dsn
    
    from undogate.capture.install import install_undogate
    from undogate.executor import UndogateExecutor
    from undogate.models import StatementClass, ClassifiedStatement, PolicyDecision, StatementEvaluation
    
    install_undogate(dsn)
    executor = UndogateExecutor(dsn)
    
    stmt = ClassifiedStatement(sql="SELECT 1;", stmt_class=StatementClass.READ, tables=[])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")
    executor.execute(eval)
    
    # Run the CLI verify command
    from undogate.cli import verify_ledger
    verify_ledger()
