"""The core promise: a mass write that slips past the AST gate (e.g. WHERE 1=1)
is rolled back and held for a human instead of being applied."""
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from undogate.capture.install import install_undogate
from undogate.config import UndogateConfig
from undogate.executor import UndogateExecutor
from undogate.policy import PolicyEngine
from undogate.sql.classify import classify_sql


@pytest.fixture(scope="module")
def dsns():
    with PostgresContainer("postgres:16-alpine") as pg:
        dsn = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        p = urlparse(dsn)

        def as_role(role):
            return urlunparse((p.scheme, f"{role}:secret@{p.hostname}:{p.port}", p.path, "", "", ""))

        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE ROLE undogate_control LOGIN PASSWORD 'secret'")
            cur.execute("CREATE ROLE mcp_agent LOGIN PASSWORD 'secret'")
        install_undogate(dsn, control_role="undogate_control", agent_role="mcp_agent")
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE TABLE public.payments (id INT PRIMARY KEY, amount INT, card_token TEXT)")
            cur.execute("INSERT INTO public.payments SELECT g, 100, 'tok_secret_' || g FROM generate_series(1, 20) g")
            cur.execute("SELECT undogate.register_table('public', 'payments', 'id', 'mcp_agent')")
        yield dsn, as_role("undogate_control"), as_role("mcp_agent")


def run(executor, sql):
    engine = PolicyEngine(UndogateConfig())
    return executor.execute(engine.evaluate(classify_sql(sql)[0]), principal="attacker")


def amounts(dsn):
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT sum(amount) FROM public.payments")
        return cur.fetchone()[0]


def test_mass_update_is_held_then_approved_then_undone(dsns, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))
    admin, control, agent = dsns
    ex = UndogateExecutor(control, agent, max_rows_without_approval=5)

    res = run(ex, "UPDATE public.payments SET amount = 0 WHERE 1=1")
    assert res.status == "approval_required", res.message
    assert amounts(admin) == 2000, "held write must be rolled back"

    approved = ex.execute_pending(res.public_id)
    assert approved.status == "applied" and approved.rows_affected == 20, approved.message
    assert amounts(admin) == 0

    assert ex.execute_undo(res.public_id).status == "undone"
    assert amounts(admin) == 2000


def test_small_write_under_limit_applies(dsns, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))
    _, control, agent = dsns
    ex = UndogateExecutor(control, agent, max_rows_without_approval=5)
    res = run(ex, "UPDATE public.payments SET amount = 100 WHERE id = 1")
    assert res.status == "applied", res.message


def test_expired_pending_checkpoint_cannot_be_approved(dsns, monkeypatch):
    monkeypatch.setattr("undogate.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))
    _, control, agent = dsns
    ex = UndogateExecutor(control, agent, max_rows_without_approval=0, approval_timeout_minutes=0)
    res = run(ex, "UPDATE public.payments SET amount = 1 WHERE id = 2")
    assert res.status == "approval_required"
    out = ex.execute_pending(res.public_id)
    assert out.status == "denied" and "expired" in out.message
    assert ex.check_status(res.public_id) == "rejected"


def test_secret_columns_leak_nothing(dsns):
    _, control, agent = dsns
    ex = UndogateExecutor(control, agent)
    res = run(ex, "SELECT * FROM public.payments WHERE id = 3")
    assert res.status == "applied", res.message
    assert res.data[0]["card_token"] == "***MASKED***"


def test_row_limit_counts_captured_rows_not_outer_rowcount(dsns, monkeypatch):
    """Defense in depth: even if a hidden write got past the hard gate, the limit is
    enforced on rows the capture trigger actually recorded (cascades included)."""
    monkeypatch.setattr("undogate.sentinel.AISentinel._ast_firewall", lambda self, sql: (True, ""))
    monkeypatch.setattr("undogate.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))
    admin, control, agent = dsns
    ex = UndogateExecutor(control, agent, max_rows_without_approval=5)
    before = amounts(admin)
    res = run(ex, "WITH m AS (UPDATE public.payments SET amount = 0 WHERE true RETURNING id) "
                  "UPDATE public.payments SET amount = 0 WHERE id = (SELECT min(id) FROM m)")
    assert res.status == "approval_required", res.message
    assert amounts(admin) == before


def test_audit_trail_records_who_did_what(dsns, monkeypatch, caplog):
    import json
    import logging
    monkeypatch.setattr("undogate.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))
    _, control, agent = dsns
    ex = UndogateExecutor(control, agent, max_rows_without_approval=1)
    with caplog.at_level(logging.INFO, logger="undogate_audit"):
        denied = run(ex, "DELETE FROM public.payments")
        held = run(ex, "UPDATE public.payments SET amount = 7 WHERE id < 5")
        ex.execute_pending(held.public_id, actor="cli:alice")
        ex.execute_undo(held.public_id, agent_label="cli:bob")
        rejected = run(ex, "UPDATE public.payments SET amount = 8 WHERE id < 5")
        ex.reject(rejected.public_id, actor="api_admin")
    events = [json.loads(r.getMessage()) for r in caplog.records if r.name == "undogate_audit"]
    trail = [(e["event_type"], e["actor"]) for e in events]
    assert denied.status == "denied"
    assert trail == [
        ("undogate.denied", "attacker"),
        ("undogate.held", "attacker"),
        ("undogate.approved", "cli:alice"),
        ("undogate.applied", "cli:alice"),
        ("undogate.undone", "cli:bob"),
        ("undogate.held", "attacker"),
        ("undogate.rejected", "api_admin"),
    ], trail
