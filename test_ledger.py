import psycopg
from testcontainers.community.postgres import PostgresContainer
from undogate.capture.install import install_undogate
from undogate.executor import UndogateExecutor
from undogate.models import StatementClass, ClassifiedStatement, PolicyDecision, StatementEvaluation

with PostgresContainer("postgres:16-alpine") as postgres:
    dsn = postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
    install_undogate(dsn)
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE test_ledger (id INT);")
            
    executor = UndogateExecutor(dsn)
    
    # 1st checkpoint
    stmt = ClassifiedStatement(sql="INSERT INTO test_ledger VALUES (1);", stmt_class=StatementClass.WRITE_DML, tables=["test_ledger"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")
    res1 = executor.execute(eval)
    
    # 2nd checkpoint
    stmt2 = ClassifiedStatement(sql="INSERT INTO test_ledger VALUES (2);", stmt_class=StatementClass.WRITE_DML, tables=["test_ledger"])
    eval2 = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")
    res2 = executor.execute(eval2)

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, prev_hash, hash FROM undogate.checkpoints ORDER BY id ASC")
            for row in cur.fetchall():
                print(row)
