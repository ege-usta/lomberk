import psycopg
import pytest
from testcontainers.postgres import PostgresContainer

from undogate.capture.install import install_undogate
from undogate.executor import UndogateExecutor
from undogate.models import (
    ClassifiedStatement,
    PolicyDecision,
    StatementClass,
    StatementEvaluation,
)
from undogate.undo import UndoEngine


@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer("postgres:16-alpine") as postgres:
        yield postgres

@pytest.fixture(scope="module")
def dsn(postgres):
    return postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")

@pytest.fixture(scope="module")
def setup_db(dsn):
    # Install undogate
    install_undogate(dsn)
    
    # Create test schema and table
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                CREATE TABLE public.test_users (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    age INT
                );
            """)
        # Attach trigger
        cur.execute("SELECT undogate.attach_trigger_to_table('public', 'test_users');")

def test_insert_undo(dsn, setup_db):
    executor = UndogateExecutor(dsn)
    undo_engine = UndoEngine(dsn)
    
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_users (name, age) VALUES ('Alice', 30)", stmt_class=StatementClass.WRITE_DML, tables=["public.test_users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    
    # 1. Execute
    res = executor.execute(eval)
    assert res.status == "applied"
    assert res.rows_affected == 1
    cp_id = res.checkpoint_id
    
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.test_users WHERE name = 'Alice'")
            assert cur.fetchone()[0] == 1
            
            # Check row_changes
            cur.execute("SELECT op, new_row FROM undogate.row_changes WHERE checkpoint_id = %s", (cp_id,))
            changes = cur.fetchall()
            assert len(changes) == 1
            assert changes[0][0] == 'I'
            assert changes[0][1]['name'] == 'Alice'

    # 2. Undo
    undo_engine.undo(cp_id)
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_users WHERE name = 'Alice'")
        assert cur.fetchone()[0] == 0
            
def test_update_undo(dsn, setup_db):
    executor = UndogateExecutor(dsn)
    undo_engine = UndoEngine(dsn)
    
    # Insert manually
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO public.test_users (name, age) VALUES ('Bob', 40)")
            
    # Update via executor
    stmt = ClassifiedStatement(sql="UPDATE public.test_users SET age = 41 WHERE name = 'Bob'", stmt_class=StatementClass.WRITE_DML, tables=["public.test_users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    
    res = executor.execute(eval)
    cp_id = res.checkpoint_id
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT age FROM public.test_users WHERE name = 'Bob'")
        assert cur.fetchone()[0] == 41
            
    # Undo
    undo_engine.undo(cp_id)
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT age FROM public.test_users WHERE name = 'Bob'")
        assert cur.fetchone()[0] == 40
            
def test_delete_undo(dsn, setup_db):
    executor = UndogateExecutor(dsn)
    undo_engine = UndoEngine(dsn)
    
    # Insert manually
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO public.test_users (name, age) VALUES ('Charlie', 50)")
            
    # Delete via executor
    stmt = ClassifiedStatement(sql="DELETE FROM public.test_users WHERE name = 'Charlie'", stmt_class=StatementClass.WRITE_DML, tables=["public.test_users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    
    res = executor.execute(eval)
    cp_id = res.checkpoint_id
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_users WHERE name = 'Charlie'")
        assert cur.fetchone()[0] == 0
            
    # Undo
    undo_engine.undo(cp_id)
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_users WHERE name = 'Charlie'")
        assert cur.fetchone()[0] == 1

def test_cascade_delete_undo(dsn, setup_db):
    executor = UndogateExecutor(dsn)
    undo_engine = UndoEngine(dsn)
    
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE public.test_orders (
                    id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES public.test_users(id) ON DELETE CASCADE,
                    total INT
                );
            """)
            cur.execute("SELECT undogate.attach_trigger_to_table('public', 'test_orders');")
            
            # Insert User and Order
            cur.execute("INSERT INTO public.test_users (name, age) VALUES ('Dave', 60) RETURNING id")
            user_id = cur.fetchone()[0]
            cur.execute("INSERT INTO public.test_orders (user_id, total) VALUES (%s, 100)", (user_id,))
            
    # Delete User via executor (should cascade to order)
    stmt = ClassifiedStatement(sql=f"DELETE FROM public.test_users WHERE id = {user_id}", stmt_class=StatementClass.WRITE_DML, tables=["public.test_users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    
    res = executor.execute(eval)
    cp_id = res.checkpoint_id
    
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.test_users WHERE id = %s", (user_id,))
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT count(*) FROM public.test_orders WHERE user_id = %s", (user_id,))
            assert cur.fetchone()[0] == 0
            
    # Undo
    undo_engine.undo(cp_id)
    
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM public.test_users WHERE id = %s", (user_id,))
            assert cur.fetchone()[0] == 1
            cur.execute("SELECT count(*) FROM public.test_orders WHERE user_id = %s", (user_id,))
            assert cur.fetchone()[0] == 1
