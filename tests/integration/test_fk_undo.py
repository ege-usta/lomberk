"""Undo across foreign keys. Real schemas have FKs; undo must restore cascaded
rows, and must never silently lose or destroy rows outside the checkpoint."""
import os
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from lomberk.capture.install import install_lomberk
from lomberk.executor import LomberkExecutor
from lomberk.models import (
    ClassifiedStatement,
    PolicyDecision,
    StatementClass,
    StatementEvaluation,
)


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        dsn = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        p = urlparse(dsn)

        def as_role(role):
            return urlunparse((p.scheme, f"{role}:secret@{p.hostname}:{p.port}", p.path, "", "", ""))

        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE ROLE lomberk_control LOGIN PASSWORD 'secret'")
            cur.execute("CREATE ROLE mcp_agent LOGIN PASSWORD 'secret'")
        install_lomberk(dsn, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE public.users (id INT PRIMARY KEY, name TEXT);
                CREATE TABLE public.payments (id INT PRIMARY KEY, user_id INT REFERENCES public.users(id) ON DELETE CASCADE, amount INT);
                CREATE TABLE public.notes (id INT PRIMARY KEY, user_id INT REFERENCES public.users(id) ON DELETE SET NULL, body TEXT);
                CREATE TABLE public.orgs (id INT PRIMARY KEY);
                CREATE TABLE public.shadow (id INT PRIMARY KEY, org_id INT REFERENCES public.orgs(id) ON DELETE CASCADE);
                INSERT INTO public.users VALUES (1, 'alice'), (2, 'bob');
                INSERT INTO public.payments VALUES (10, 1, 500), (11, 1, 700), (12, 2, 50);
                INSERT INTO public.notes VALUES (20, 1, 'vip');
                INSERT INTO public.orgs VALUES (1);
                INSERT INTO public.shadow VALUES (1, 1);
            """)
            for t in ("users", "payments", "notes", "orgs"):  # shadow deliberately NOT registered
                cur.execute("SELECT lomberk.register_table('public', %s, 'id', 'mcp_agent')", (t,))
        yield dsn, LomberkExecutor(as_role("lomberk_control"), as_role("mcp_agent"))


def run(ex, sql):
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[])
    return ex.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason=""))


def snapshot(dsn):
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        out = {}
        for t in ("users", "payments", "notes", "orgs", "shadow"):
            cur.execute(f"SELECT * FROM public.{t} ORDER BY id")
            out[t] = cur.fetchall()
        return out


@pytest.fixture(autouse=True)
def no_llm(monkeypatch):
    monkeypatch.setattr("lomberk.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))


def test_cascade_delete_is_fully_undone(db):
    dsn, ex = db
    before = snapshot(dsn)
    res = run(ex, "DELETE FROM public.users WHERE id = 1")
    assert res.status == "applied", res.message
    after = snapshot(dsn)
    assert [r[0] for r in after["payments"]] == [12]
    assert after["notes"] == [(20, None, "vip")]

    undo = ex.execute_undo(res.public_id)
    assert undo.status == "undone", undo.message
    assert snapshot(dsn) == before


def test_insert_parent_and_child_is_undone(db):
    dsn, ex = db
    before = snapshot(dsn)
    a = run(ex, "INSERT INTO public.users VALUES (3, 'carol')")
    b = run(ex, "INSERT INTO public.payments VALUES (13, 3, 9)")
    assert a.status == b.status == "applied"
    assert ex.execute_undo(b.public_id).status == "undone"
    assert ex.execute_undo(a.public_id).status == "undone"
    assert snapshot(dsn) == before


def test_undo_refuses_to_cascade_into_rows_outside_checkpoint(db):
    dsn, ex = db
    a = run(ex, "INSERT INTO public.users VALUES (4, 'dave')")
    b = run(ex, "INSERT INTO public.payments VALUES (14, 4, 1)")  # later, separate checkpoint
    assert a.status == b.status == "applied"
    before = snapshot(dsn)
    undo = ex.execute_undo(a.public_id)  # deleting dave would cascade-delete payment 14
    assert undo.status in ("conflict", "failed"), undo.message
    assert snapshot(dsn) == before, "undo must not destroy rows it did not create"


def test_write_that_cascades_into_unregistered_table_is_refused(db):
    dsn, ex = db
    before = snapshot(dsn)
    res = run(ex, "DELETE FROM public.orgs WHERE id = 1")
    assert res.status == "failed" and "shadow" in res.message, res.message
    assert snapshot(dsn) == before


def test_self_referencing_cascade_is_undone(db):
    dsn, ex = db
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE public.tree (id INT PRIMARY KEY, parent INT REFERENCES public.tree(id) ON DELETE CASCADE);
            INSERT INTO public.tree VALUES (1, NULL), (2, 1), (3, 2), (4, 1);
            SELECT lomberk.register_table('public', 'tree', 'id', 'mcp_agent');
        """)
    res = run(ex, "DELETE FROM public.tree WHERE id = 1")
    assert res.status == "applied" and res.rows_affected == 1
    undo = ex.execute_undo(res.public_id)
    assert undo.status == "undone", undo.message
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT id, parent FROM public.tree ORDER BY id")
        assert cur.fetchall() == [(1, None), (2, 1), (3, 2), (4, 1)]


def test_cascade_into_protected_table_is_held(db, monkeypatch):
    dsn, ex = db
    ex.protected_tables = {"public.users"}
    try:
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE public.tenants (id INT PRIMARY KEY);
                ALTER TABLE public.users ADD COLUMN tenant_id INT REFERENCES public.tenants(id) ON DELETE CASCADE;
                INSERT INTO public.tenants VALUES (7);
                UPDATE public.users SET tenant_id = 7 WHERE id = 2;
                SELECT lomberk.register_table('public', 'tenants', 'id', 'mcp_agent');
                SELECT lomberk.register_table('public', 'users', 'id', 'mcp_agent');
            """)
        before = snapshot(dsn)
        res = run(ex, "DELETE FROM public.tenants WHERE id = 7")
        assert res.status == "approval_required" and "public.users" in res.message, res.message
        assert snapshot(dsn) == before
        assert ex.execute_pending(res.public_id).status == "applied"
    finally:
        ex.protected_tables = set()
