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


@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer("postgres:16-alpine") as postgres:
        yield postgres

@pytest.fixture(scope="module")
def dsn(postgres):
    return postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")

@pytest.fixture(scope="module")
def runtime_dsn(dsn):
    # Parse dsn to replace username with mcp_agent
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"mcp_agent:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn, runtime_dsn):
    # Admin creates runtime role
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("DROP ROLE IF EXISTS undogate_control")
        cur.execute("CREATE ROLE undogate_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    
    install_undogate(dsn, control_role="undogate_control", agent_role="mcp_agent")

    # Create test schema and table as Admin
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                CREATE TABLE public.test_users (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    age INT
                );
            """)
        cur.execute("SELECT undogate.register_table('public', 'test_users', 'id', 'mcp_agent');")

def assert_runtime_role(dsn):
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT current_user, session_user")
        curr, sess = cur.fetchone()
        assert curr == 'mcp_agent'
        assert sess == 'mcp_agent'
        cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = 'mcp_agent'")
        assert cur.fetchone()[0] is False

def test_insert_undo(dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    assert_runtime_role(runtime_dsn)
    executor = UndogateExecutor(dsn, runtime_dsn)
        
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_users (name, age) VALUES ('Alice', 30)", stmt_class=StatementClass.WRITE_DML, tables=["public.test_users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    
    # 1. Execute
    res = executor.execute(eval)
    assert res.status == "applied", res.message
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
    res_undo = executor.execute_undo(res.public_id)
    assert res_undo.status == 'undone'
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_users WHERE name = 'Alice'")
        assert cur.fetchone()[0] == 0
            
def test_update_undo(dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(dsn, runtime_dsn)
        
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
    res_undo = executor.execute_undo(res.public_id)
    assert res_undo.status == 'undone'
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT age FROM public.test_users WHERE name = 'Bob'")
        assert cur.fetchone()[0] == 40
            
def test_delete_undo(dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(dsn, runtime_dsn)
        
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
    res_undo = executor.execute_undo(res.public_id)
    assert res_undo.status == 'undone'
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_users WHERE name = 'Charlie'")
        assert cur.fetchone()[0] == 1

def test_cascade_delete_undo(dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(dsn, runtime_dsn)
        
    with psycopg.connect(dsn, autocommit=True) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE public.test_orders (
                    id SERIAL PRIMARY KEY,
                    user_id INT REFERENCES public.test_users(id) ON DELETE CASCADE,
                    total INT
                );
            """)
            cur.execute("SELECT undogate.register_table('public', 'test_orders', 'id', 'mcp_agent');")
            
            # Insert User and Order
            cur.execute("INSERT INTO public.test_users (name, age) VALUES ('Dave', 60) RETURNING id")
            user_id = cur.fetchone()[0]
            cur.execute("INSERT INTO public.test_orders (user_id, total) VALUES (%s, 100)", (user_id,))
            
    # Delete User via executor (should cascade to order)
    stmt = ClassifiedStatement(sql=f"DELETE FROM public.test_users WHERE id = {user_id}", stmt_class=StatementClass.WRITE_DML, tables=["public.test_users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    
    res = executor.execute(eval)
    
    # Undo
    res_undo = executor.execute_undo(res.public_id)
    assert res_undo.status == 'failed'
    assert 'Foreign keys not allowed' in res_undo.message

def test_concurrent_undo(dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    import threading
    executor = UndogateExecutor(dsn, runtime_dsn)
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS public.test_chain (id SERIAL PRIMARY KEY, name TEXT, age INT);")
        cur.execute("SELECT undogate.register_table('public', 'test_chain', 'id', 'mcp_agent');")
        
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_chain (name, age) VALUES ('Racer', 99)", stmt_class=StatementClass.WRITE_DML, tables=["public.test_chain"])
    res = executor.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test"))
    
    results = []
    def do_undo():
        res_undo = executor.execute_undo(res.public_id)
        results.append(f"{res_undo.status}:{res_undo.message}")
        
    t1 = threading.Thread(target=do_undo)
    t2 = threading.Thread(target=do_undo)
    t1.start(); t2.start()
    t1.join(); t2.join()
    
    undone_count = sum(1 for r in results if r.startswith('undone'))
    failed_busy_count = sum(1 for r in results if r.startswith('failed') or r.startswith('busy'))
    assert undone_count == 1, results
    assert failed_busy_count == 1, results

def test_undo_privilege_boundary(dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(dsn, runtime_dsn)
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS public.test_chain (id SERIAL PRIMARY KEY, name TEXT, age INT);")
        cur.execute("SELECT undogate.register_table('public', 'test_chain', 'id', 'mcp_agent');")
        
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_chain (name, age) VALUES ('Hacker', 100)", stmt_class=StatementClass.WRITE_DML, tables=["public.test_chain"])
    res = executor.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test"))
    
    hacker_executor = UndogateExecutor(runtime_dsn, runtime_dsn)
    res_undo = hacker_executor.execute_undo(res.public_id)
    
    assert res_undo.status == "failed"
    assert "permission denied" in res_undo.message.lower()

def test_undo_chaining_lifo(dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(dsn, runtime_dsn)
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS public.test_chain (id SERIAL PRIMARY KEY, name TEXT, age INT);")
        cur.execute("SELECT undogate.register_table('public', 'test_chain', 'id', 'mcp_agent');")
        
    stmt = ClassifiedStatement(
        sql='''
DO $$ 
BEGIN
    INSERT INTO public.test_chain (id, name, age) VALUES (991, 'A', 1);
    INSERT INTO public.test_chain (id, name, age) VALUES (992, 'B', 2);
    UPDATE public.test_chain SET age=3 WHERE id=991;
END $$;
''',
        stmt_class=StatementClass.WRITE_DML,
        tables=["public.test_chain"],
        is_multistatement=True
    )
    res = executor.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test"))
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT name, age FROM public.test_chain WHERE id IN (991, 992) ORDER BY id")
        rows = cur.fetchall()
        assert rows == [('A', 3), ('B', 2)]
        
    res_undo = executor.execute_undo(res.public_id)
    assert res_undo.status == "undone", res_undo.message
