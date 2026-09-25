import pytest
import psycopg
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
def setup_db(dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE ROLE undogate_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    install_undogate(dsn, control_role="undogate_control", agent_role="mcp_agent")

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_fail (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT undogate.register_table('public', 'test_fail', 'id', 'mcp_agent');")

def test_p0_connection_open_failure(dsn, control_dsn, runtime_dsn, setup_db, monkeypatch):
    # DML_WRITE with a broken runtime_dsn
    from urllib.parse import urlparse, urlunparse
    p = urlparse(runtime_dsn)
    broken_dsn = urlunparse((p.scheme, f"{p.username}:{p.password}@{p.hostname}:9999", p.path, p.params, p.query, p.fragment))
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(dsn, broken_dsn)
    
    sql = "INSERT INTO public.test_fail (id, val) VALUES (1, 'fail');"
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    
    res = executor.execute(eval_result, agent_label="test")
    assert res.status == "failed"
    assert "Connection refused" in res.message or "could not connect" in res.message
    
    # Ledger must say failed
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT status FROM undogate.checkpoints WHERE public_id = %s", (res.public_id,))
        assert cur.fetchone()[0] == 'failed'
        
    # Table must be empty
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.test_fail WHERE id = 1")
        assert cur.fetchone()[0] == 0

def test_p0_execution_rollback(dsn, control_dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    # DML that fails after partial execution (e.g. division by zero in multi-row insert)
    # This proves atomicity (first row is rolled back when second row fails)
    sql = "INSERT INTO public.test_fail (id, val) VALUES (2, 'fail'), (3, (1/0)::text);"
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    
    res = executor.execute(eval_result, agent_label="test")
    assert res.status == "failed"
    assert "division by zero" in res.message
    
    # Data is not inserted
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.test_fail WHERE id IN (2, 3)")
        assert cur.fetchone()[0] == 0
    
    # Ledger must say failed
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT status FROM undogate.checkpoints WHERE public_id = %s", (res.public_id,))
        assert cur.fetchone()[0] == 'failed'

def test_p0_commit_network_loss(dsn, control_dsn, runtime_dsn, setup_db, monkeypatch):

    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    # We mock Transaction.__exit__ to raise an error during commit, ONLY for runtime_dsn
    original_exit = psycopg.Transaction.__exit__
    def mock_exit(self_tx, exc_type, exc_val, exc_tb):
        if self_tx.connection.info.user == 'mcp_agent':
            raise psycopg.OperationalError("Simulated network drop during commit")
        return original_exit(self_tx, exc_type, exc_val, exc_tb)
        
    monkeypatch.setattr(psycopg.Transaction, "__exit__", mock_exit)
    
    sql = "INSERT INTO public.test_fail (id, val) VALUES (3, 'unknown');"
    from undogate.models import ClassifiedStatement, StatementClass
    from undogate.policy import StatementEvaluation, PolicyDecision
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    
    res = executor.execute(eval_result, agent_label="test")
    
    assert res.status == "outcome_unknown"
    assert "Network failure" in res.message
    
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT status FROM undogate.checkpoints WHERE public_id = %s", (res.public_id,))
        assert cur.fetchone()[0] == 'approved'

def test_p0_status_check(dsn, control_dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    # 1. Test not found
    assert executor.check_status("cp_invalid123") == "not_found"
    
    # 2. Test execution success state (applied)
    sql = "INSERT INTO public.test_fail (id, val) VALUES (10, 'success');"
    from undogate.models import ClassifiedStatement, StatementClass
    from undogate.policy import StatementEvaluation, PolicyDecision
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    
    res = executor.execute(eval_result, agent_label="test")
    assert res.status == "applied"
    
    assert executor.check_status(res.public_id) == "applied"

    # 3. Test execution executing state via lock
    # We will manually set a checkpoint to executing and hold a ROW EXCLUSIVE lock on it, 
    # to simulate another backend actively running it.
    
    with psycopg.connect(dsn, autocommit=False) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM undogate.begin_checkpoint('SELECT 1', 'WRITE_DML', 'test')")
        row = cur.fetchone()
        cp_id, pub_id = row[0], row[1]
        
        # Approve it
        cur.execute("SELECT undogate.approve_checkpoint(%s, 'ALLOW')", (pub_id,))
        token = cur.fetchone()[0]
        conn.commit()
        
        # Claim it (sets it to executing and locks the row if we don't commit)
        cur.execute("SELECT undogate.claim_checkpoint(%s)", (token,))
        
        # Now, in a separate connection, check_status should see it as 'executing' 
        # because it will hit LockNotAvailable
        assert executor.check_status(pub_id) == "busy"
        
        # If we commit, it becomes 'executing' but unlocked, so check_status can read it
        conn.commit()
        assert executor.check_status(pub_id) == "executing"

def test_p0_commit_network_loss_after_commit(dsn, control_dsn, runtime_dsn, setup_db, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    executor = UndogateExecutor(control_dsn, runtime_dsn)
    
    # We patch Transaction.__exit__ to call original_exit successfully,
    # and THEN raise OperationalError to simulate the connection dropping 
    # while waiting for the server's ReadyForQuery message after COMMIT.
    import psycopg
    original_exit = psycopg.Transaction.__exit__
    
    def mocked_exit(self, exc_type, exc_val, exc_tb):
        original_exit(self, exc_type, exc_val, exc_tb)
        raise psycopg.OperationalError("Simulated network loss after commit")
        
    monkeypatch.setattr(psycopg.Transaction, "__exit__", mocked_exit)
    
    sql = "INSERT INTO public.test_fail (id, val) VALUES (4, 'commit_loss_after');"
    from undogate.models import ClassifiedStatement, StatementClass
    from undogate.policy import StatementEvaluation, PolicyDecision
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")
    
    res = executor.execute(eval_result, agent_label="test")
    # Even though execution technically completed on DB side, 
    # psycopg raised OperationalError which means executor sees it as outcome_unknown!
    assert res.status == "outcome_unknown"
    
    # We can check the true status with check_status which will return 'applied'
    # since it actually committed!
    assert executor.check_status(res.public_id) == "applied"
    
    # Verify data is actually inserted
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.test_fail WHERE id = 4")
        assert cur.fetchone()[0] == 1
        
        # Verify capture record exists
        cur.execute("SELECT COUNT(*) FROM undogate.row_changes WHERE table_schema = 'public' AND table_name = 'test_fail'")
        # Might be more than 1 depending on other tests, just assert > 0 for this test or fetch by transaction id if we had it.
        assert cur.fetchone()[0] > 0
