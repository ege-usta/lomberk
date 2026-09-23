from undogate.executor import UndogateExecutor
from undogate.models import StatementClass, ClassifiedStatement, PolicyDecision, StatementEvaluation
import psycopg
from testcontainers.community.postgres import PostgresContainer
from undogate.capture.install import install_undogate

with PostgresContainer("postgres:16-alpine") as postgres:
    dsn = postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
    install_undogate(dsn)
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("CREATE TABLE public.test_ddl (id SERIAL PRIMARY KEY, data TEXT);")
            
    executor = UndogateExecutor(dsn)
    stmt = ClassifiedStatement(sql="DROP TABLE public.test_ddl;", stmt_class=StatementClass.DDL_REVERSIBLE, tables=["public.test_ddl"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")
    res = executor.execute(eval)
    print(res)
