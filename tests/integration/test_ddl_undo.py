import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

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
    install_undogate(dsn)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                CREATE TABLE public.test_ddl (
                    id SERIAL PRIMARY KEY,
                    data TEXT
                );
                INSERT INTO public.test_ddl (data) VALUES ('A'), ('B');
            """)

def test_drop_table_undo(dsn, setup_db):
    executor = UndogateExecutor(dsn)
    undo_engine = UndoEngine(dsn)
    
    stmt = ClassifiedStatement(sql="DROP TABLE public.test_ddl;", stmt_class=StatementClass.DDL_REVERSIBLE, tables=["public.test_ddl"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.REQUIRE_APPROVAL, reason="Test")
    # In executor, if decision is REQUIRE_APPROVAL it blocks. But for tests we force ALLOW.
    eval.decision = PolicyDecision.ALLOW
    
    res = executor.execute(eval)
    cp_id = res.checkpoint_id
    
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            # Table should not exist in public
            cur.execute("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'test_ddl'")
            assert cur.fetchone()[0] == 0
            
    undo_engine.undo(cp_id)
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_ddl")
        assert cur.fetchone()[0] == 2

def test_truncate_undo(dsn, setup_db):
    executor = UndogateExecutor(dsn)
    undo_engine = UndoEngine(dsn)
    
    stmt = ClassifiedStatement(sql="TRUNCATE public.test_ddl;", stmt_class=StatementClass.DDL_REVERSIBLE, tables=["public.test_ddl"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")
    
    res = executor.execute(eval)
    cp_id = res.checkpoint_id
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_ddl")
        assert cur.fetchone()[0] == 0
            
    undo_engine.undo(cp_id)
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM public.test_ddl")
        assert cur.fetchone()[0] == 2

def test_drop_column_undo(dsn, setup_db):
    executor = UndogateExecutor(dsn)
    undo_engine = UndoEngine(dsn)
    
    # Add a column first
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("ALTER TABLE public.test_ddl ADD COLUMN extra INT DEFAULT 42;")
            
    stmt = ClassifiedStatement(sql="ALTER TABLE public.test_ddl DROP COLUMN extra;", stmt_class=StatementClass.DDL_REVERSIBLE, tables=["public.test_ddl"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")
    
    res = executor.execute(eval)
    cp_id = res.checkpoint_id
    
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            # Column should not exist
            cur.execute("SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'test_ddl' AND column_name = 'extra'")
            assert cur.fetchone()[0] == 0
            
    undo_engine.undo(cp_id)
    
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            # Column should be back
            cur.execute("SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'test_ddl' AND column_name = 'extra'")
            assert cur.fetchone()[0] == 1
            
            # Data should be back
            cur.execute("SELECT count(*) FROM public.test_ddl WHERE extra = 42")
            assert cur.fetchone()[0] == 2
