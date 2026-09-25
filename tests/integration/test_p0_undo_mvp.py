import pytest
import psycopg
import threading
import time
from testcontainers.community.postgres import PostgresContainer
from undogate.capture.install import install_undogate
from undogate.executor import UndogateExecutor
from undogate.models import ClassifiedStatement, StatementClass
from undogate.policy import StatementEvaluation, PolicyDecision

@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer("postgres:16-alpine") as postgres:
        yield postgres

@pytest.fixture(scope="module")
def dsn(postgres):
    return postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")

@pytest.fixture(scope="module")
def runtime_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"mcp_agent:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def control_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"undogate_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn, control_dsn, runtime_dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE ROLE undogate_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    install_undogate(dsn, control_role="undogate_control", agent_role="mcp_agent")
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_undo (my_pk INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT undogate.register_table('public', 'test_undo', 'my_pk', 'mcp_agent');")

def test_undo_basic_operations(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    # INSERT
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_undo (my_pk, val) VALUES (1, 'initial');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    res_ins = executor.execute(eval_result)
    assert res_ins.status == "applied"
    
    # UPDATE
    stmt = ClassifiedStatement(sql="UPDATE public.test_undo SET val = 'updated' WHERE my_pk = 1;", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    res_upd = executor.execute(eval_result)
    assert res_upd.status == "applied"
    
    # DELETE
    stmt = ClassifiedStatement(sql="DELETE FROM public.test_undo WHERE my_pk = 1;", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    res_del = executor.execute(eval_result)
    assert res_del.status == "applied"

    # Now Undo DELETE
    res_undo_del = executor.execute_undo(res_del.public_id)
    assert res_undo_del.status == "undone", res_undo_del.message
    
    # Verify row is back
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT val FROM public.test_undo WHERE my_pk = 1")
        assert cur.fetchone()[0] == 'updated'
        
    # Undo UPDATE
    res_undo_upd = executor.execute_undo(res_upd.public_id)
    assert res_undo_upd.status == "undone", res_undo_upd.message
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT val FROM public.test_undo WHERE my_pk = 1")
        assert cur.fetchone()[0] == 'initial'
        
    # Undo INSERT
    res_undo_ins = executor.execute_undo(res_ins.public_id)
    assert res_undo_ins.status == "undone"
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.test_undo WHERE my_pk = 1")
        assert cur.fetchone()[0] == 0

def test_undo_conflict_rollback(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    # Insert 2 rows in one checkpoint
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_undo (my_pk, val) VALUES (2, 'a'), (3, 'b');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    res = executor.execute(eval_result)
    assert res.status == "applied"
    
    # Human modifies row 3 out of band
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("UPDATE public.test_undo SET val = 'human' WHERE my_pk = 3")
        
    # Undo should fail (Conflict) because row 3 doesn't match post-image
    res_undo = executor.execute_undo(res.public_id)
    assert res_undo.status == "conflict"
    assert "Conflict" in res_undo.message
    
    # Rollback must be complete: row 2 should STILL exist
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.test_undo WHERE my_pk IN (2, 3)")
        assert cur.fetchone()[0] == 2
        
        # Original checkpoint should remain 'applied'
        cur.execute("SELECT status FROM undogate.checkpoints WHERE public_id = %s", (res.public_id,))
        assert cur.fetchone()[0] == 'applied'
def test_undo_unsupported_schema(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        # FK
        cur.execute("CREATE TABLE public.test_fk_parent (id INT PRIMARY KEY);")
        cur.execute("CREATE TABLE public.test_fk_child (id INT PRIMARY KEY, parent_id INT REFERENCES public.test_fk_parent(id));")
        cur.execute("SELECT undogate.register_table('public', 'test_fk_child', 'id', 'mcp_agent');")
        cur.execute("INSERT INTO public.test_fk_parent VALUES (1);")
        
        # Rule
        cur.execute("CREATE TABLE public.test_rule (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT undogate.register_table('public', 'test_rule', 'id', 'mcp_agent');")
        cur.execute("CREATE RULE test_rule_insert AS ON INSERT TO public.test_rule DO ALSO NOTIFY some_event;")
        
        # Inheritance
        cur.execute("CREATE TABLE public.test_parent (id INT PRIMARY KEY, val TEXT);")
        cur.execute("CREATE TABLE public.test_child (child_val TEXT) INHERITS (public.test_parent);")
        cur.execute("SELECT undogate.register_table('public', 'test_child', 'id', 'mcp_agent');")

        # Trigger
        cur.execute("CREATE TABLE public.test_trigger (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT undogate.register_table('public', 'test_trigger', 'id', 'mcp_agent');")
        cur.execute("CREATE FUNCTION public.dummy_trig() RETURNS trigger AS $$ BEGIN RETURN NEW; END; $$ LANGUAGE plpgsql;")
        cur.execute("CREATE TRIGGER some_trig BEFORE INSERT ON public.test_trigger FOR EACH ROW EXECUTE FUNCTION public.dummy_trig();")

    # Execute valid DMLs
    stmt1 = ClassifiedStatement(sql="INSERT INTO public.test_fk_child VALUES (1, 1);", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_fk = executor.execute(StatementEvaluation(statement=stmt1, decision=PolicyDecision.ALLOW, reason=""))
    
    stmt2 = ClassifiedStatement(sql="INSERT INTO public.test_rule VALUES (1, 'val');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_rule = executor.execute(StatementEvaluation(statement=stmt2, decision=PolicyDecision.ALLOW, reason=""))
    
    stmt3 = ClassifiedStatement(sql="INSERT INTO public.test_trigger VALUES (1, 'val');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_trig = executor.execute(StatementEvaluation(statement=stmt3, decision=PolicyDecision.ALLOW, reason=""))

    # Undo should fail for all
    undo_fk = executor.execute_undo(res_fk.public_id)
    assert undo_fk.status == "failed"
    assert "Foreign keys" in undo_fk.message

    undo_rule = executor.execute_undo(res_rule.public_id)
    assert undo_rule.status == "failed"
    assert "Rules" in undo_rule.message

    undo_trig = executor.execute_undo(res_trig.public_id)
    assert undo_trig.status == "failed"
    assert "Triggers" in undo_trig.message
def test_undo_commit_loss(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)

    # Insert
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_undo (my_pk, val) VALUES (4, 'loss');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    res = executor.execute(eval_result)
    assert res.status == "applied"
    
    import psycopg
    original_exit = psycopg.Transaction.__exit__
    
    def mocked_exit(self, exc_type, exc_val, exc_tb):
        original_exit(self, exc_type, exc_val, exc_tb)
        raise psycopg.OperationalError("Simulated network loss after commit")
        
    monkeypatch.setattr(psycopg.Transaction, "__exit__", mocked_exit)

    # Undo should hit exception
    res_undo = executor.execute_undo(res.public_id)
    assert res_undo.status == "outcome_unknown", res_undo.message
    
    # Check the real status
    monkeypatch.setattr(psycopg.Transaction, "__exit__", original_exit)
    assert executor.check_status(res.public_id) == "undone"
    
    # Subsequent calls should return already_undone
    res_undo2 = executor.execute_undo(res.public_id)
    assert res_undo2.status == "already_undone"

def test_undo_pk_drift_same_oid(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    from undogate.executor import UndogateExecutor
    executor = UndogateExecutor(control_dsn, runtime_dsn)

    # INSERT
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_undo (my_pk, val) VALUES (99, 'initial');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    res_ins = executor.execute(eval_result)
    assert res_ins.status == "applied"
    
    # Drop PK constraint, insert second row with same values
    import psycopg
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("ALTER TABLE public.test_undo DROP CONSTRAINT test_undo_pkey;")
        cur.execute("INSERT INTO public.test_undo (my_pk, val) VALUES (99, 'initial');")
        
    # Try to undo
    res_undo = executor.execute_undo(res_ins.public_id)
    assert res_undo.status == "failed"
    assert "has no primary key" in res_undo.message or "Security Violation" in res_undo.message

def test_undo_schema_drift_dropped_column(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_drop_col (id INT PRIMARY KEY, val TEXT, secret TEXT);")
        cur.execute("SELECT undogate.register_table('public', 'test_drop_col', 'id', 'mcp_agent');")
        
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_drop_col VALUES (1, 'val', 'sec');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_ins = executor.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason=""))
    
    stmt2 = ClassifiedStatement(sql="DELETE FROM public.test_drop_col WHERE id = 1;", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_del = executor.execute(StatementEvaluation(statement=stmt2, decision=PolicyDecision.ALLOW, reason=""))
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("ALTER TABLE public.test_drop_col DROP COLUMN secret;")
        
    undo_del = executor.execute_undo(res_del.public_id)
    assert undo_del.status == "failed"
    assert "Schema drift" in undo_del.message

def test_undo_when_false_trigger(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_when (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT undogate.register_table('public', 'test_when', 'id', 'mcp_agent');")
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_when VALUES (1, 'val');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_ins = executor.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason=""))
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        # Replace trigger with WHEN false
        cur.execute("DROP TRIGGER undogate_capture ON public.test_when;")
        cur.execute("CREATE TRIGGER undogate_capture AFTER INSERT OR UPDATE OR DELETE ON public.test_when FOR EACH ROW WHEN (false) EXECUTE FUNCTION undogate.capture_row_change();")
        
    undo = executor.execute_undo(res_ins.public_id)
    assert undo.status == "failed"
    assert "Capture trigger missing" in undo.message

def test_undo_generated_column(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_gen (id INT PRIMARY KEY, val TEXT, gen TEXT GENERATED ALWAYS AS (val) STORED);")
        cur.execute("SELECT undogate.register_table('public', 'test_gen', 'id', 'mcp_agent');")
        
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_gen (id, val) VALUES (1, 'val');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_ins = executor.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason=""))
    
    undo = executor.execute_undo(res_ins.public_id)
    assert undo.status == "failed"
    assert "Generated/Identity columns not allowed" in undo.message

def test_undo_schema_drift_alter_type(control_dsn, runtime_dsn, dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_alter_type (id INT PRIMARY KEY, val NUMERIC(10,2));")
        cur.execute("SELECT undogate.register_table('public', 'test_alter_type', 'id', 'mcp_agent');")
        
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_alter_type VALUES (1, 10.50);", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_ins = executor.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason=""))
    
    stmt2 = ClassifiedStatement(sql="DELETE FROM public.test_alter_type WHERE id = 1;", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    res_del = executor.execute(StatementEvaluation(statement=stmt2, decision=PolicyDecision.ALLOW, reason=""))
    
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("ALTER TABLE public.test_alter_type ALTER COLUMN val TYPE NUMERIC(5,0);")
        
    undo_del = executor.execute_undo(res_del.public_id)
    assert undo_del.status == "failed"
    assert "Schema drift detected" in undo_del.message
