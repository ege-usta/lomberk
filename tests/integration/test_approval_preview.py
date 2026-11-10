"""Approvers see what a held write would change, not just its SQL: the write runs once,
its captured rows are read, it is rolled back, and the preview is stored with the hold."""
import os
import uuid

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from lomberk.capture.install import install_lomberk
from lomberk.config import LomberkConfig
from lomberk.executor import MASK, LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.sql.classify import classify_sql

PROTECTED = ["public.users"]


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE TABLE public.users (id INT PRIMARY KEY, email TEXT, plan TEXT, api_token TEXT, ssn_hidden TEXT)")
            c.execute("CREATE TABLE public.payments (id INT PRIMARY KEY, user_id INT REFERENCES public.users ON DELETE CASCADE, amount INT)")
            c.execute("CREATE TABLE public.notes (id INT PRIMARY KEY, body TEXT)")
            c.execute("INSERT INTO public.users VALUES (1, 'a@x.io', 'free', 'tok_1', 'H1'), (2, 'b@x.io', 'free', 'tok_2', 'H2')")
            c.execute("INSERT INTO public.payments VALUES (10, 1, 5), (11, 1, 7), (12, 2, 9)")
            c.execute("INSERT INTO public.notes SELECT g, 'n' FROM generate_series(1, 40) g")
            # ssn_hidden is hidden from the agent by PostgreSQL; api_token stays readable but masked by name.
            c.execute("SELECT lomberk.register_table('public', 'users', NULL, 'mcp_agent', ARRAY['ssn_hidden'])")
            c.execute("SELECT lomberk.register_table('public', 'payments', NULL, 'mcp_agent')")
            c.execute("SELECT lomberk.register_table('public', 'notes', NULL, 'mcp_agent')")
        host = url.split("@", 1)[1]
        control, agent = f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"
        yield url, control, agent


def executor(db, preview=True):
    _, control, agent = db
    return LomberkExecutor(control, agent, max_rows_without_approval=25, protected_tables=PROTECTED, preview_writes=preview)


def run(ex, sql):
    config = LomberkConfig(protected_tables=PROTECTED)
    return ex.execute(PolicyEngine(config).evaluate(classify_sql(sql)[0]), agent_label="t", principal="t")


def count(url, sql):
    with psycopg.connect(url) as c:
        return c.execute(sql).fetchone()[0]


def test_held_delete_shows_the_row_and_its_cascade_without_changing_anything(db):
    url = db[0]
    ex = executor(db)
    res = run(ex, "DELETE FROM public.users WHERE id = 1")
    assert res.status == "approval_required" and "Policy requires explicit approval" in res.message
    assert count(url, "SELECT count(*) FROM public.users") == 2 and count(url, "SELECT count(*) FROM public.payments") == 3

    p = ex.get_checkpoint(res.public_id)["preview"]
    assert p["rows"] == 3 and p["tables"] == {"public.users": 1, "public.payments": 2} and not p["truncated"]
    user = next(s for s in p["sample"] if s["table"] == "public.users")
    assert user["op"] == "delete" and user["key"] == {"id": "1"}
    assert user["row"]["email"] == "a@x.io" and user["row"]["api_token"] == MASK
    assert "ssn_hidden" not in user["row"]  # hidden from the agent role, so not in its preview either

    # The person approves: it now runs for real, and the preview stays for the audit trail.
    assert ex.execute_pending(res.public_id, actor="alice").status == "applied"
    assert count(url, "SELECT count(*) FROM public.payments WHERE user_id = 1") == 0
    assert ex.get_checkpoint(res.public_id)["preview"]["rows"] == 3


def test_update_preview_lists_only_changed_columns(db):
    ex = executor(db)
    res = run(ex, "UPDATE public.users SET plan = 'pro' WHERE id = 2")
    assert res.status == "approval_required"
    (entry,) = ex.get_checkpoint(res.public_id)["preview"]["sample"]
    assert entry["op"] == "update" and entry["changes"] == {"plan": ["free", "pro"]}


def test_row_limit_hold_previews_a_sample_and_says_it_is_partial(db):
    url = db[0]
    ex = executor(db)
    res = run(ex, "UPDATE public.notes SET body = 'x' WHERE id > 0")
    assert res.status == "approval_required" and "exceeds limit" in res.message
    p = ex.get_checkpoint(res.public_id)["preview"]
    assert p["rows"] == 40 and len(p["sample"]) == 20 and p["truncated"]
    assert count(url, "SELECT count(*) FROM public.notes WHERE body = 'x'") == 0


def test_a_held_write_that_would_fail_is_refused_instead_of_queued(db):
    # public.users is protected, so this takes the held path; the dry run hits the duplicate key,
    # and the agent learns now rather than after a person approved something that can't run.
    ex = executor(db)
    res = run(ex, "INSERT INTO public.users (id, email) VALUES (2, 'dup@x.io')")
    assert res.status == "failed" and "duplicate key" in res.message
    assert ex.list_checkpoints(limit=1)[0]["status"] == "failed"


def test_preview_off_keeps_the_old_hold_without_running_the_write(db):
    ex = executor(db, preview=False)
    res = run(ex, "DELETE FROM public.users WHERE id = 2")
    assert res.status == "approval_required"
    assert ex.get_checkpoint(res.public_id)["preview"] is None


def test_preview_function_needs_the_live_token(db):
    _, _, agent = db
    with psycopg.connect(agent) as c, pytest.raises(psycopg.errors.RaiseException, match="live execution token"):
        c.execute("SELECT lomberk.preview_changes(%s)", (str(uuid.uuid4()),))
