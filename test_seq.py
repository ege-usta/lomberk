import psycopg
from testcontainers.postgres import PostgresContainer
from undogate.capture.install import install_undogate
from undogate.executor import UndogateExecutor
from undogate.models import StatementClass, ClassifiedStatement, PolicyDecision, StatementEvaluation

with PostgresContainer("postgres:16-alpine") as postgres:
    dsn = postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
    install_undogate(dsn)
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE public.test_users (id SERIAL PRIMARY KEY, name TEXT);
                CREATE TABLE public.test_orders (id SERIAL PRIMARY KEY, user_id INT REFERENCES public.test_users(id) ON DELETE CASCADE);
            """)
            cur.execute("SELECT undogate.attach_trigger_to_table('public', 'test_users');")
            cur.execute("SELECT undogate.attach_trigger_to_table('public', 'test_orders');")
            cur.execute("INSERT INTO public.test_users (name) VALUES ('Dave') RETURNING id")
            user_id = cur.fetchone()[0]
            cur.execute("INSERT INTO public.test_orders (user_id) VALUES (%s)", (user_id,))
            
    executor = UndogateExecutor(dsn)
    stmt = ClassifiedStatement(sql=f"DELETE FROM public.test_users WHERE id = {user_id}", stmt_class=StatementClass.WRITE_DML, tables=["public.test_users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    res = executor.execute(eval)
    
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT seq, table_name, op FROM undogate.row_changes ORDER BY seq ASC")
            for row in cur.fetchall():
                print(row)
