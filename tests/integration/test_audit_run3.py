"""Regressions for security-audit run-3 (2026-10-18), one test per confirmed finding."""
import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from lomberk.capture.install import install_lomberk
from lomberk.config import LomberkConfig
from lomberk.executor import LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.sql.classify import classify_sql

PROTECTED = ["public.plans", "public.events"]


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE TABLE public.plans (id INT PRIMARY KEY, tier TEXT, note TEXT)")
            c.execute("INSERT INTO public.plans VALUES (1, 'free', 'a'), (2, 'pro', 'b'), (3, 'pro', 'c')")
            c.execute("CREATE TABLE public.events (region TEXT, id INT, v TEXT, pin TEXT, PRIMARY KEY (region, id)) PARTITION BY LIST (region)")
            c.execute("CREATE TABLE public.events_eu PARTITION OF public.events FOR VALUES IN ('eu')")
            c.execute("INSERT INTO public.events VALUES ('eu', 1, 'x', '1234')")
            # A grant the agent had on a partition before registration must not survive it.
            c.execute("GRANT SELECT ON public.events_eu TO mcp_agent")
            c.execute("CREATE TABLE public.parents (id INT PRIMARY KEY)")
            c.execute("CREATE TABLE public.kids (id INT PRIMARY KEY, parent_id INT REFERENCES public.parents ON DELETE CASCADE, seen TIMESTAMPTZ)")
            c.execute("CREATE FUNCTION public.stamp() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN OLD; END $$")
            c.execute("CREATE TRIGGER stamp BEFORE DELETE ON public.kids FOR EACH ROW EXECUTE FUNCTION public.stamp()")
            c.execute("INSERT INTO public.parents VALUES (1), (2)")
            c.execute("INSERT INTO public.kids VALUES (10, 1, NULL)")
            c.execute("SELECT lomberk.register_table('public', 'plans', NULL, 'mcp_agent')")
            c.execute("SELECT lomberk.register_table('public', 'events', NULL, 'mcp_agent', ARRAY['pin'])")
            c.execute("SELECT lomberk.register_table('public', 'parents', NULL, 'mcp_agent')")
            c.execute("SELECT lomberk.register_table('public', 'kids', NULL, 'mcp_agent')")
        host = url.split("@", 1)[1]
        yield url, LomberkExecutor(f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}",
                                   max_rows_without_approval=50, protected_tables=PROTECTED, preview_writes=True)


def run(ex, sql):
    return ex.execute(PolicyEngine(LomberkConfig(protected_tables=PROTECTED)).evaluate(classify_sql(sql)[0]),
                      agent_label="t", principal="t")


def sql(url, q):
    with psycopg.connect(url, autocommit=True) as c:
        cur = c.execute(q)
        return cur.fetchall() if cur.description else None


def test_approval_refuses_a_write_that_now_changes_other_rows_than_previewed(db):
    # Finding 3: the preview said one row; by approval time the WHERE matches more (data moved,
    # or `now()` passed a deadline). Running it anyway would make the preview a lie.
    url, ex = db
    held = run(ex, "UPDATE public.plans SET note = 'upgraded' WHERE tier = 'free'")
    assert held.status == "approval_required" and ex.get_checkpoint(held.public_id)["preview"]["rows"] == 1
    sql(url, "UPDATE public.plans SET tier = 'free' WHERE id = 2")
    res = ex.execute_pending(held.public_id, actor="alice")
    assert res.status == "failed" and "not the 1 previewed" in res.message
    assert sql(url, "SELECT count(*) FROM public.plans WHERE note = 'upgraded'") == [(0,)]


def test_approval_runs_when_the_rows_match_the_preview(db):
    url, ex = db
    held = run(ex, "UPDATE public.plans SET note = 'kept' WHERE id = 3")
    assert ex.execute_pending(held.public_id, actor="alice").status == "applied"
    assert sql(url, "SELECT note FROM public.plans WHERE id = 3") == [("kept",)]


def test_held_update_on_a_partitioned_table_gets_a_preview(db):
    # Finding 5: privileges live on the partitioned table, not the leaf the rows are in.
    _, ex = db
    held = run(ex, "UPDATE public.events SET v = 'y' WHERE region = 'eu' AND id = 1")
    assert held.status == "approval_required", held.message
    p = ex.get_checkpoint(held.public_id)["preview"]
    assert p["tables"] == {"public.events": 1}
    assert p["sample"][0]["changes"] == {"v": ["x", "y"]} and "pin" not in str(p)  # hidden column stays hidden


def test_registration_takes_away_direct_access_to_partitions(db):
    # Finding 6: column hiding happens on the partitioned table; a partition must not be a side door.
    url, _ = db
    assert sql(url, "SELECT has_table_privilege('mcp_agent', 'public.events_eu', 'SELECT')") == [(False,)]


def test_preview_values_cannot_disguise_themselves(db):
    # Finding 7: right-to-left overrides and huge values in row data would mislead an approver.
    url, ex = db
    sql(url, "UPDATE public.plans SET note = 'ok' || chr(8238) || 'evil' || repeat('z', 5000) WHERE id = 1")
    held = run(ex, "UPDATE public.plans SET note = note || '!' WHERE id = 1")  # both sides shown
    row = ex.get_checkpoint(held.public_id)["preview"]["sample"][0]
    text = str(row)
    assert "‮" not in text and "\\u202e" in text
    assert len(text) < 1500 and "more characters" in text


def test_a_cascade_into_a_table_with_its_own_triggers_waits_for_a_person(db):
    # Found while reviewing run-3: undo refuses tables with their own triggers, and that includes
    # tables reached by a cascade, so such a write could be applied but never undone.
    url, ex = db
    res = run(ex, "DELETE FROM public.parents WHERE id = 1")
    assert res.status == "approval_required" and "public.kids" in res.message
    assert sql(url, "SELECT count(*) FROM public.kids") == [(1,)]
    assert "public.kids" in (ex.get_checkpoint(res.public_id)["undo_warning"] or "")
    # Decided per table, before running: a dry run would fire the child's trigger.
    sql(url, "DROP TRIGGER stamp ON public.kids")
    assert run(ex, "DELETE FROM public.parents WHERE id = 2").status == "applied"
