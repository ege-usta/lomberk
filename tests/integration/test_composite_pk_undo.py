"""Undo on tables keyed by more than one column: join tables (org, user), tenant-scoped rows
(tenant_id, id) and every partitioned table, whose key must include the partition key."""
import os
import uuid

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from lomberk.capture.install import install_lomberk
from lomberk.config import LomberkConfig
from lomberk.executor import LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.sql.classify import classify_sql

T1 = str(uuid.UUID(int=1))


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE TABLE public.memberships (org_id INT, user_id INT, role TEXT NOT NULL, "
                      "PRIMARY KEY (org_id, user_id))")
            c.execute("INSERT INTO public.memberships VALUES (1, 1, 'owner'), (1, 2, 'member'), (2, 1, 'member')")
            # Composite FK with a cascade: deleting a membership deletes its grants.
            c.execute("CREATE TABLE public.grants (org_id INT, user_id INT, perm TEXT, PRIMARY KEY (org_id, user_id, perm), "
                      "FOREIGN KEY (org_id, user_id) REFERENCES public.memberships ON DELETE CASCADE)")
            c.execute("INSERT INTO public.grants VALUES (1, 2, 'read'), (1, 2, 'write'), (1, 1, 'admin')")
            c.execute("CREATE TABLE public.docs (tenant UUID, id INT, title TEXT, PRIMARY KEY (tenant, id))")
            c.execute("INSERT INTO public.docs VALUES (%s, 1, 'a'), (%s, 2, 'b')", (T1, T1))
            c.execute("CREATE TABLE public.covered (id INT, note TEXT, PRIMARY KEY (id) INCLUDE (note))")
            for t in ("memberships", "grants", "docs", "covered"):
                # No key given: registration reads it from the table.
                c.execute("SELECT lomberk.register_table('public', %s, NULL, 'mcp_agent')", (t,))
        host = url.split("@", 1)[1]
        yield url, LomberkExecutor(f"postgresql://lomberk_control:secret@{host}",
                                   f"postgresql://mcp_agent:secret@{host}", max_rows_without_approval=50)


def run(ex, sql):
    return ex.execute(PolicyEngine(LomberkConfig()).evaluate(classify_sql(sql)[0]), agent_label="t", principal="t")


def rows(url, sql):
    with psycopg.connect(url) as c:
        return c.execute(sql).fetchall()


def test_registration_reads_the_key_and_skips_covering_columns(db):
    url, _ = db
    assert dict(rows(url, "SELECT table_name, pk_column FROM lomberk.registered_tables")) == {
        "memberships": "org_id,user_id", "grants": "org_id,user_id,perm", "docs": "tenant,id", "covered": "id"}


def test_registration_refuses_a_wrong_key_up_front(db):
    url, _ = db
    with psycopg.connect(url, autocommit=True) as c, pytest.raises(psycopg.errors.RaiseException, match=r"is \(org_id,user_id\), not \(id\)"):
        c.execute("SELECT lomberk.register_table('public', 'memberships', 'id', 'mcp_agent')")


def test_update_undo_touches_only_the_row_with_the_full_key(db):
    url, ex = db
    res = run(ex, "UPDATE public.memberships SET role = 'admin' WHERE org_id = 1 AND user_id = 2")
    assert res.status == "applied" and res.rows_affected == 1
    # Another write to a row sharing org_id must not be confused with it.
    assert run(ex, "UPDATE public.memberships SET role = 'billing' WHERE org_id = 1 AND user_id = 1").status == "applied"
    assert ex.execute_undo(res.public_id).status == "undone"
    assert rows(url, "SELECT org_id, user_id, role FROM public.memberships ORDER BY 1, 2") == [
        (1, 1, "billing"), (1, 2, "member"), (2, 1, "member")]


def test_delete_with_composite_fk_cascade_comes_back(db):
    url, ex = db
    before_m = rows(url, "SELECT * FROM public.memberships ORDER BY 1, 2")
    before_g = rows(url, "SELECT * FROM public.grants ORDER BY 1, 2, 3")
    res = run(ex, "DELETE FROM public.memberships WHERE org_id = 1")
    assert res.status == "applied"
    assert rows(url, "SELECT count(*) FROM public.grants")[0][0] == 0
    undo = ex.execute_undo(res.public_id)
    assert undo.status == "undone" and undo.rows_affected == 5  # 2 memberships + 3 cascaded grants
    assert rows(url, "SELECT * FROM public.memberships ORDER BY 1, 2") == before_m
    assert rows(url, "SELECT * FROM public.grants ORDER BY 1, 2, 3") == before_g


def test_insert_undo_deletes_only_the_inserted_row(db):
    url, ex = db
    res = run(ex, f"INSERT INTO public.docs VALUES ('{T1}', 3, 'c')")
    assert res.status == "applied"
    assert ex.execute_undo(res.public_id).status == "undone"
    assert rows(url, "SELECT id FROM public.docs ORDER BY 1") == [(1,), (2,)]


def test_changing_any_key_column_is_refused(db):
    url, ex = db
    res = run(ex, "UPDATE public.memberships SET user_id = 9 WHERE org_id = 2 AND user_id = 1")
    assert res.status == "failed" and "Primary key updates are forbidden" in res.message
    assert rows(url, "SELECT count(*) FROM public.memberships WHERE user_id = 9")[0][0] == 0


def test_undo_refuses_when_the_key_changed_shape(db):
    url, ex = db
    res = run(ex, "UPDATE public.covered SET note = 'x' WHERE id = 1")
    assert res.status == "applied"
    run(ex, "INSERT INTO public.covered VALUES (1, 'a')")
    res = run(ex, "UPDATE public.covered SET note = 'b' WHERE id = 1")
    assert res.status == "applied"
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("ALTER TABLE public.covered DROP CONSTRAINT covered_pkey")
        c.execute("ALTER TABLE public.covered ADD PRIMARY KEY (id, note)")
    undo = ex.execute_undo(res.public_id)
    assert undo.status == "failed" and "PK identity drifted" in undo.message
    assert rows(url, "SELECT note FROM public.covered") == [("b",)]
