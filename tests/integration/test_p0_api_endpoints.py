import os

import psycopg
import pytest
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer

from lomberk.api import app, get_executor
from lomberk.capture.install import install_lomberk
from lomberk.executor import LomberkExecutor


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
def control_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"lomberk_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    install_lomberk(dsn, control_role="lomberk_control", agent_role="mcp_agent")

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_api (id INT PRIMARY KEY, val TEXT);")
        cur.execute("SELECT lomberk.register_table('public', 'test_api', 'id', 'mcp_agent');")

@pytest.fixture(scope="module")
def client(control_dsn, runtime_dsn, setup_db):
    import os
    os.environ["LOMBERK_AGENT_DSN"] = runtime_dsn
    os.environ["LOMBERK_ADMIN_DSN"] = control_dsn
    os.environ["LOMBERK_API_KEY"] = "test-api-key"
    os.environ["LOMBERK_ADMIN_KEY"] = "test-admin-key"

    executor = LomberkExecutor(control_dsn, runtime_dsn)

    app.dependency_overrides[get_executor] = lambda: executor
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

def test_api_unauthorized(client):
    res = client.get("/v1/checkpoints/pending")
    assert res.status_code == 401

def test_api_list_pending(client):
    res = client.get("/v1/checkpoints/pending", headers={"X-API-Key": "test-admin-key"})
    assert res.status_code == 200
    assert isinstance(res.json(), list)

def test_api_status_not_found(client):
    res = client.get("/v1/checkpoints/cp_invalid/status", headers={"X-API-Key": "test-admin-key"})
    assert res.status_code == 404

def test_api_status_applied(client, control_dsn, runtime_dsn):
    # Execute a statement successfully and verify its status via API
    executor = LomberkExecutor(control_dsn, runtime_dsn)

    from lomberk.models import ClassifiedStatement, StatementClass
    from lomberk.policy import PolicyDecision, StatementEvaluation
    stmt = ClassifiedStatement(sql="INSERT INTO public.test_api (id, val) VALUES (10, 'ok');", stmt_class=StatementClass.WRITE_DML, tables=[], is_multistatement=False)
    eval_result = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="")

    # We must patch AST sentinel just for the executor instance if we can
    import lomberk.sentinel
    original_firewall = lomberk.sentinel.AISentinel._ast_firewall
    lomberk.sentinel.AISentinel._ast_firewall = lambda self, sql: (True, "")
    try:
        res = executor.execute(eval_result, agent_label="test")
        assert res.status == "applied"
    finally:
        lomberk.sentinel.AISentinel._ast_firewall = original_firewall

    api_res = client.get(f"/v1/checkpoints/{res.public_id}/status", headers={"X-API-Key": "test-admin-key"})
    assert api_res.status_code == 200
    assert api_res.json()["status"] == "applied"


def test_api_approve_outcome_unknown(client, control_dsn, runtime_dsn, monkeypatch):
    import psycopg
    _executor = LomberkExecutor(control_dsn, runtime_dsn)

    # We create a pending checkpoint first
    with psycopg.connect(control_dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM lomberk.begin_checkpoint('INSERT INTO test_api VALUES(99, ''val'')', 'WRITE_DML', 'test', 'system', gen_random_uuid()::text)")
        row = cur.fetchone()
        assert row is not None
        _cp_id, pub_id = row[0], row[1]

    original_exit = psycopg.Transaction.__exit__
    def mocked_exit(self, exc_type, exc_val, exc_tb):
        original_exit(self, exc_type, exc_val, exc_tb)
        raise psycopg.OperationalError("Simulated network loss after commit")

    monkeypatch.setattr(psycopg.Transaction, "__exit__", mocked_exit)

    # Also patch AST
    monkeypatch.setattr("lomberk.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))

    # Hit the approve endpoint
    api_res = client.post(f"/v1/checkpoints/{pub_id}/approve", json={"decision": "ALLOW"}, headers={"X-API-Key": "test-admin-key"})

    monkeypatch.undo()
    # Should get 502 with outcome_unknown
    print(api_res.text)
    assert api_res.status_code == 502
    assert api_res.json()["status"] == "unknown"


def test_api_lists_checkpoints_to_find_one_to_undo(client, control_dsn, runtime_dsn, monkeypatch):
    from typer.testing import CliRunner

    from lomberk.cli import app as cli_app
    executor = LomberkExecutor(control_dsn, runtime_dsn)
    held = executor.create_pending_checkpoint("UPDATE public.test_api SET val = '[red]x[/red]' WHERE id = 10", "WRITE_DML",
                                             "REQUIRE_APPROVAL", "agent_x")
    assert client.get("/v1/checkpoints").status_code == 401
    assert client.get("/v1/checkpoints?status=nonsense", headers={"X-API-Key": "test-admin-key"}).status_code == 422
    applied = client.get("/v1/checkpoints?status=applied", headers={"X-API-Key": "test-admin-key"}).json()
    assert applied and {c["status"] for c in applied} == {"applied"}
    assert {"public_id", "sql", "rows_affected", "approved_by"} <= set(applied[0])
    newest = client.get("/v1/checkpoints?limit=1", headers={"X-API-Key": "test-admin-key"}).json()
    assert [c["public_id"] for c in newest] == [held]

    monkeypatch.setenv("LOMBERK_ADMIN_DSN", control_dsn)
    monkeypatch.setenv("LOMBERK_AGENT_DSN", runtime_dsn)
    r = CliRunner().invoke(cli_app, ["log", "--status", "pending"])
    assert r.exit_code == 0, r.output
    assert held in r.output and "[red]x[/red]" in r.output and "lomberk undo" in r.output  # agent SQL printed as-is
    assert "No undone checkpoints." in CliRunner().invoke(cli_app, ["log", "--status", "undone"]).output
