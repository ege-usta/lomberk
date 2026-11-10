import json
import os
import urllib.error

import psycopg
import pytest
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer

from lomberk.api import app
from lomberk.capture.install import install_lomberk
from lomberk.executor import LomberkExecutor
from lomberk.models import ClassifiedStatement, PolicyDecision, StatementClass, StatementEvaluation


@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as postgres:
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
def setup_db(dsn, runtime_dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
        cur.execute("DROP ROLE IF EXISTS lomberk_control")
        cur.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")

    install_lomberk(dsn, control_role='lomberk_control', agent_role='mcp_agent')
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE IF NOT EXISTS public.users (id SERIAL PRIMARY KEY, data TEXT, role TEXT, password TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS public.dangerous_function ()")
        cur.execute("INSERT INTO public.users (data) VALUES ('test_admin'); SELECT lomberk.register_table('public', 'users', 'id', 'mcp_agent')")
        cur.execute("REVOKE SELECT, UPDATE ON public.users FROM mcp_agent")
        cur.execute("GRANT SELECT (id, data, role), UPDATE (id, data, role) ON public.users TO mcp_agent")

def test_llm_safe_boolean_mock(monkeypatch):
    from lomberk.sentinel import AISentinel

    payloads = [
        {"safe": "false", "reason": "string false"},
        {"safe": 1, "reason": "int 1"},
        {"safe": None, "reason": "null"},
        {"reason": "missing safe"},
        "invalid_json"
    ]

    for p in payloads:
        class MockResponse:
            def read(self):
                return json.dumps({"choices": [{"message": {"content": json.dumps(p) if isinstance(p, dict) else p}}]}).encode()
            def __enter__(self): return self
            def __exit__(self, *args): pass

        def mock_urlopen(*args, **kwargs):
            return MockResponse()

        monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)

        sentinel = AISentinel()
        sentinel.api_key = "test"
        safe, reason = sentinel.evaluate_intent("SELECT 1", [])
        assert safe is False
        assert "Invalid boolean format" in reason or "Unexpected error" in reason or "Network/API failure" in reason

def test_timeout_mock(monkeypatch):
    from lomberk.sentinel import AISentinel
    def mock_timeout(*args, **kwargs):
        raise urllib.error.URLError("Timeout")
    monkeypatch.setattr("urllib.request.urlopen", mock_timeout)

    sentinel = AISentinel()
    sentinel.api_key = "test"
    safe, reason = sentinel.evaluate_intent("SELECT 1", [])
    assert safe is False
    assert "Network/API failure" in reason


def test_api_valid_approval_flow(monkeypatch, dsn, runtime_dsn, setup_db):
    monkeypatch.setenv("LOMBERK_AGENT_DSN", runtime_dsn)
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    admin_dsn = urlunparse((parsed.scheme, f"lomberk_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))
    monkeypatch.setenv("LOMBERK_ADMIN_DSN", admin_dsn)
    monkeypatch.setenv("LOMBERK_API_KEY", "agent")
    monkeypatch.setenv("LOMBERK_ADMIN_KEY", "admin")

    # Mock config
    import lomberk.config
    original_load = lomberk.config.load_config
    def mock_load(*a, **kw):
        cfg = original_load(*a, **kw)
        cfg.limits.max_rows_without_approval = 0
        cfg.protected_tables = ["public.users"]
        return cfg
    monkeypatch.setattr(lomberk.config, "load_config", mock_load)

    import lomberk.api
    lomberk.api._executor_instance = None
    lomberk.api._policy_engine_instance = None

    with TestClient(app) as client:
        # Step 1: Agent tries valid DML write
        resp = client.post("/v1/execute", json={"sql": "UPDATE public.users SET data = 'updated' WHERE id = 1;"}, headers={"X-API-Key": "agent"})
        assert resp.status_code == 200
        res_data = resp.json()["results"][0]
        assert res_data["status"] == "approval_required"

        token = res_data["checkpoint_id"]

        # Step 2: Target row should remain unchanged
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT data FROM public.users WHERE id = 1")
            assert cur.fetchone()[0] == "test_admin"

        # Step 3: Admin approves
        approve_resp = client.post(f"/v1/checkpoints/{token}/approve", headers={"X-API-Key": "admin"})
        print(approve_resp.json())
        print(approve_resp.json())
        assert approve_resp.status_code == 200
        assert approve_resp.json()["status"] == "approved"
        assert approve_resp.json()["rows_affected"] == 1

        # Step 4: Target row should be updated
        with psycopg.connect(dsn) as conn, conn.cursor() as cur:
            cur.execute("SELECT data FROM public.users WHERE id = 1")
            assert cur.fetchone()[0] == "updated"





def test_p0_quoted_identifier_injection(dsn, runtime_dsn, setup_db):
    import psycopg
    executor = LomberkExecutor(dsn, runtime_dsn)

    # 1. Canary check: Ensure the injected SQL was NOT executed.
    # If `SELECT 1; --` was executed, it would just return. But if we put an INSERT into a canary table, we could check it.
    # However, since `execute` fails at `LOCK TABLE public."users; SELECT 1; --"`, it never reaches execution.
    # Let's verify the error message explicitly points to the locked table, proving it was parsed as a single literal.

    stmt = ClassifiedStatement(sql='UPDATE public."users; SELECT 1; --" SET data=\'x\' WHERE id=1', stmt_class=StatementClass.WRITE_DML, tables=[])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")

    res = executor.execute(eval)
    assert res.status == "failed"
    assert 'relation "public.users; SELECT 1; --" does not exist' in res.message or "not registered" in res.message

    # 2. Valid dotted/quoted identifier check
    # Let's create a valid table with a quoted name and register it
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute('CREATE TABLE IF NOT EXISTS public."Valid.Table" (id SERIAL PRIMARY KEY, data TEXT)')
        cur.execute("SELECT lomberk.register_table('public', 'Valid.Table', 'id', 'mcp_agent')")
        cur.execute('INSERT INTO public."Valid.Table" (data) VALUES (\'test\')')

    stmt_valid = ClassifiedStatement(sql='UPDATE public."Valid.Table" SET data=\'y\' WHERE id=1', stmt_class=StatementClass.WRITE_DML, tables=[])
    eval_valid = StatementEvaluation(statement=stmt_valid, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")
    res_valid = executor.execute(eval_valid)

    assert res_valid.status == "applied", res_valid.message

def test_p0_sensitive_alias_leak(dsn, runtime_dsn, setup_db):
    import psycopg
    executor = LomberkExecutor(dsn, runtime_dsn)

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("UPDATE public.users SET password = 'real-synthetic-secret' WHERE id = 1")

    stmt = ClassifiedStatement(sql='SELECT password AS safe_val FROM public.users', stmt_class=StatementClass.READ, tables=["public.users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")

    res = executor.execute(eval)
    assert res.status == "failed"
    assert "Access denied: Query contains sensitive columns" in res.message


def test_p0_sensitive_returning_leak(dsn, runtime_dsn, setup_db):
    import psycopg
    executor = LomberkExecutor(dsn, runtime_dsn)

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("UPDATE public.users SET data = 'old', password = 'synthetic-secret' WHERE id = 1")

    stmt = ClassifiedStatement(sql='UPDATE public.users SET data=\'x\' WHERE id=1 RETURNING password', stmt_class=StatementClass.WRITE_DML, tables=["public.users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")

    res = executor.execute(eval)
    assert res.status == "failed"
    assert "Access denied: Query contains sensitive columns" in res.message or "permission denied" in res.message

    # Verify DB state didn't change!
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT data, password FROM public.users WHERE id = 1")
        row = cur.fetchone()
        assert row[0] == 'old'
        assert row[1] == 'synthetic-secret'

def test_p0_whole_row_wildcard_leak(dsn, runtime_dsn, setup_db):
    executor = LomberkExecutor(dsn, runtime_dsn)

    stmt = ClassifiedStatement(sql='SELECT * FROM public.users', stmt_class=StatementClass.READ, tables=["public.users"])
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Test")

    res = executor.execute(eval)
    assert res.status == "failed"
    assert "Access denied" in res.message or "permission denied" in res.message

def test_p0_runtime_missing_context(dsn, runtime_dsn, setup_db):
    import psycopg
    import pytest
    with psycopg.connect(runtime_dsn, autocommit=True) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.RaiseException, match="Lomberk Security Violation"):
            cur.execute("INSERT INTO public.users (data) VALUES ('bypass')")

def test_p0_forged_context_rejected(dsn, runtime_dsn, setup_db):
    import psycopg
    import pytest
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM lomberk.begin_checkpoint('SELECT 1', 'WRITE_DML', 'mcp_agent', 'system', gen_random_uuid()::text)")
        cp_id = cur.fetchone()[0]

    with psycopg.connect(runtime_dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT set_config('lomberk.checkpoint_id', %s, true)", (str(cp_id),))
        with pytest.raises(psycopg.errors.RaiseException, match="Invalid checkpoint context|Security Violation"):
            cur.execute("INSERT INTO public.users (data) VALUES ('forged')")

def test_p0_approval_claim_fail_rejected(dsn, runtime_dsn, setup_db):
    import psycopg
    import pytest

    # Control plane creates a pending checkpoint
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM lomberk.begin_checkpoint('SELECT 1', 'WRITE_DML', 'mcp_agent', 'system', gen_random_uuid()::text)")
        row = cur.fetchone()
        _cp_id = row[0]
        public_id = row[1]

    # Agent tries to approve/claim/fail using public_id
    with psycopg.connect(runtime_dsn, autocommit=True) as conn, conn.cursor() as cur:
        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            cur.execute("SELECT lomberk.approve_checkpoint(%s, 'ALLOW')", (public_id,))

        with pytest.raises(psycopg.errors.InsufficientPrivilege, match="permission denied"):
            cur.execute("SELECT lomberk.fail_checkpoint(%s)", (public_id,))

        with pytest.raises(psycopg.errors.InvalidTextRepresentation):
            # public_id is not a UUID, so claim_checkpoint(UUID) will fail parsing, but even if it passed, it would fail
            cur.execute("SELECT lomberk.claim_checkpoint(%s)", (public_id,))

def test_p0_capability_spoofing(dsn, runtime_dsn, setup_db):
    import psycopg
    import pytest
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM lomberk.begin_checkpoint('SELECT 1', 'WRITE_DML', 'mcp_agent', 'system', gen_random_uuid()::text)")
        public_id = cur.fetchone()[1]
        cur.execute("SELECT lomberk.approve_checkpoint(%s, 'ALLOW')", (public_id,))
        _token = cur.fetchone()[0]

    with psycopg.connect(runtime_dsn, autocommit=True) as conn, conn.cursor() as cur:
        # Agent has some OTHER capability token or invalid uuid
        invalid_token = '00000000-0000-0000-0000-000000000000'
        with pytest.raises(psycopg.errors.RaiseException, match="Checkpoint not found or not in approved state"):
            cur.execute("SELECT lomberk.claim_checkpoint(%s)", (invalid_token,))

def test_p0_token_stealing_different_backend(dsn, runtime_dsn, setup_db):
    import psycopg
    import pytest

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM lomberk.begin_checkpoint('INSERT INTO public.users(data) VALUES (''x'')', 'WRITE_DML', 'mcp_agent', 'system', gen_random_uuid()::text)")
        row = cur.fetchone()
        cp_id = row[0]
        public_id = row[1]

        cur.execute("SELECT lomberk.approve_checkpoint(%s, 'ALLOW')", (public_id,))
        token = cur.fetchone()[0]

    # The real executor claims it
    real_conn = psycopg.connect(runtime_dsn, autocommit=False)
    real_conn.autocommit = False
    cur = real_conn.cursor()
    cur.execute("BEGIN")
    cur.execute("SELECT lomberk.claim_checkpoint(%s)", (str(token),))

    # Now in a DIFFERENT connection (attacker), try to use the stolen token
    with psycopg.connect(runtime_dsn, autocommit=False) as attacker_conn:
        with attacker_conn.transaction():
            with attacker_conn.cursor() as attacker_cur:
                # Agent sets GUC with the stolen token
                attacker_cur.execute("SELECT set_config('lomberk.checkpoint_id', %s, true)", (str(cp_id),))
                attacker_cur.execute("SELECT set_config('lomberk.capability_token', %s, true)", (str(token),))
                attacker_cur.execute("SELECT set_config('lomberk.seq', '0', true)")

                # The state is 'executing', but txid_current() doesn't match!
                with pytest.raises(psycopg.errors.RaiseException, match="Checkpoint is not in executing state"):
                    attacker_cur.execute("INSERT INTO public.users(data) VALUES ('stolen')")

    real_conn.rollback()
    real_conn.close()

def test_p0_valid_claim_dml_finish(dsn, runtime_dsn, setup_db):
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM lomberk.begin_checkpoint('INSERT INTO public.users(data) VALUES (''valid'')', 'WRITE_DML', 'mcp_agent', 'system', gen_random_uuid()::text)")
        row = cur.fetchone()
        cp_id = row[0]
        public_id = row[1]

        cur.execute("SELECT lomberk.approve_checkpoint(%s, 'ALLOW')", (public_id,))
        token = cur.fetchone()[0]

    with psycopg.connect(runtime_dsn, autocommit=False) as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("SELECT lomberk.claim_checkpoint(%s)", (str(token),))

                cur.execute("SELECT set_config('lomberk.checkpoint_id', %s, true)", (str(cp_id),))
                cur.execute("SELECT set_config('lomberk.capability_token', %s, true)", (str(token),))
                cur.execute("SELECT set_config('lomberk.seq', '0', true)")

                cur.execute("INSERT INTO public.users(data) VALUES ('valid')")

                cur.execute("SELECT lomberk.finish_checkpoint(%s, 1)", (str(token),))

    # Verify success
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM public.users WHERE data = 'valid'")
        assert cur.fetchone()[0] == 1
        cur.execute("SELECT status FROM lomberk.checkpoints WHERE public_id = %s", (public_id,))
        assert cur.fetchone()[0] == 'applied'
