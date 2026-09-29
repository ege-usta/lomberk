"""Two-person rule: a held write runs only after N distinct people approve it."""
import threading

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback
from rowback.executor import RowbackExecutor


@pytest.fixture(scope="module")
def dsn():
    with PostgresContainer("postgres:16-alpine") as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_rowback(url, control_role="rowback_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE TABLE public.acct (id INT PRIMARY KEY, val INT)")
            conn.execute("INSERT INTO public.acct VALUES (1, 0)")
            conn.execute("SELECT rowback.register_table('public', 'acct', 'id', 'mcp_agent')")
        yield url


def _roles(dsn):
    host = dsn.split("@", 1)[1]
    return f"postgresql://rowback_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


def _executor(dsn, required):
    control, runtime = _roles(dsn)
    return RowbackExecutor(control, runtime, required_approvals=required)


def _pending(dsn, sql="UPDATE public.acct SET val = val + 1 WHERE id = 1"):
    control, _ = _roles(dsn)
    return RowbackExecutor(control, "unused").create_pending_checkpoint(sql, "DML_WRITE", "REQUIRE_APPROVAL", "agent")


def _val(dsn):
    with psycopg.connect(dsn) as conn:
        return conn.execute("SELECT val FROM public.acct WHERE id = 1").fetchone()[0]


def test_second_distinct_person_is_required(dsn):
    ex, pid, before = _executor(dsn, 2), _pending(dsn), _val(dsn)

    first = ex.execute_pending(pid, actor="oidc:alice@co.com")
    again = ex.execute_pending(pid, actor="oidc:alice@co.com")  # same person twice counts once
    assert (first.status, again.status) == ("awaiting_approval", "awaiting_approval")
    assert _val(dsn) == before and ex.check_status(pid) == "pending"

    done = ex.execute_pending(pid, actor="oidc:bob@co.com")
    assert done.status == "applied" and _val(dsn) == before + 1
    with psycopg.connect(dsn) as conn:
        actors = {r[0] for r in conn.execute("SELECT actor FROM rowback.approvals WHERE public_id = %s", (pid,))}
    assert actors == {"oidc:alice@co.com", "oidc:bob@co.com"}


def test_single_approval_is_recorded_by_default(dsn):
    ex, pid = _executor(dsn, 1), _pending(dsn)
    assert ex.execute_pending(pid, actor="cli:carol").status == "applied"
    with psycopg.connect(dsn) as conn:
        assert conn.execute("SELECT actor FROM rowback.approvals WHERE public_id = %s", (pid,)).fetchall() == [("cli:carol",)]


def test_one_reject_vetoes(dsn):
    ex, pid, before = _executor(dsn, 2), _pending(dsn), _val(dsn)
    assert ex.execute_pending(pid, actor="oidc:alice@co.com").status == "awaiting_approval"
    assert ex.reject(pid, actor="oidc:dave@co.com")
    assert ex.execute_pending(pid, actor="oidc:bob@co.com").status == "failed"
    assert _val(dsn) == before


def test_approvals_are_append_only(dsn):
    ex, pid = _executor(dsn, 2), _pending(dsn)
    ex.execute_pending(pid, actor="oidc:alice@co.com")
    with psycopg.connect(dsn, autocommit=True) as conn:
        for stmt in ("UPDATE rowback.approvals SET actor = 'oidc:bob@co.com'", "DELETE FROM rowback.approvals"):
            with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
                conn.execute(stmt)


def test_control_role_cannot_forge_approval_rows(dsn):
    control, _ = _roles(dsn)
    with psycopg.connect(control, autocommit=True) as conn, pytest.raises(psycopg.errors.InsufficientPrivilege):
        conn.execute("INSERT INTO rowback.approvals (public_id, actor) VALUES ('cp_x', 'oidc:ghost')")


def test_concurrent_second_approvals_apply_once(dsn):
    ex, pid, before = _executor(dsn, 2), _pending(dsn), _val(dsn)
    ex.execute_pending(pid, actor="oidc:alice@co.com")
    barrier, results = threading.Barrier(4), []

    def approve(who):
        barrier.wait(timeout=5)
        results.append(_executor(dsn, 2).execute_pending(pid, actor=who).status)

    threads = [threading.Thread(target=approve, args=(f"oidc:p{i}@co.com",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert results.count("applied") == 1 and _val(dsn) == before + 1


def test_api_shared_admin_key_counts_as_one_person(dsn, monkeypatch):
    from fastapi.testclient import TestClient

    from rowback.api import app, get_executor
    control, runtime = _roles(dsn)
    for k, v in {"ROWBACK_AGENT_DSN": runtime, "ROWBACK_ADMIN_DSN": control,
                 "ROWBACK_API_KEY": "agent-k", "ROWBACK_ADMIN_KEY": "admin-k"}.items():
        monkeypatch.setenv(k, v)
    ex, pid, before = _executor(dsn, 2), _pending(dsn), _val(dsn)
    app.dependency_overrides[get_executor] = lambda: ex
    try:
        with TestClient(app) as c:
            for _ in range(2):
                r = c.post(f"/v1/checkpoints/{pid}/approve", headers={"X-API-Key": "admin-k"})
                assert r.status_code == 202 and r.json()["status"] == "awaiting_approval"
    finally:
        app.dependency_overrides.clear()
    assert _val(dsn) == before
