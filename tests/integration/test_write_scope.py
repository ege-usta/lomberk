"""A write Rowback lets through must be fully captured. Inheritance children and rewrite
rules move rows the capture trigger never sees, so such tables are refused before the write."""
import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback
from rowback.config import RowbackConfig
from rowback.executor import RowbackExecutor
from rowback.policy import PolicyEngine
from rowback.sql.classify import classify_sql


@pytest.fixture(scope="module")
def db():
    with PostgresContainer("postgres:16-alpine") as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_rowback(url, control_role="rowback_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE TABLE public.parent (id INT PRIMARY KEY, v TEXT)")
            c.execute("CREATE TABLE public.child_archive (note TEXT) INHERITS (public.parent)")
            c.execute("INSERT INTO public.parent VALUES (1, 'p')")
            c.execute("INSERT INTO public.child_archive VALUES (2, 'c', 'x')")
            c.execute("CREATE TABLE public.ruled (id INT PRIMARY KEY, v TEXT)")
            c.execute("CREATE TABLE public.elsewhere (id INT, v TEXT)")
            c.execute("CREATE RULE redirect AS ON UPDATE TO public.ruled DO ALSO INSERT INTO public.elsewhere VALUES (NEW.id, NEW.v)")
            c.execute("INSERT INTO public.ruled VALUES (1, 'a')")
            c.execute("CREATE TABLE public.stamped (id INT PRIMARY KEY, v TEXT, updated_at TIMESTAMPTZ)")
            c.execute("CREATE FUNCTION public.touch() RETURNS trigger LANGUAGE plpgsql AS "
                      "$$ BEGIN NEW.updated_at := now(); RETURN NEW; END $$")
            c.execute("CREATE TRIGGER touch BEFORE UPDATE ON public.stamped FOR EACH ROW EXECUTE FUNCTION public.touch()")
            c.execute("INSERT INTO public.stamped VALUES (1, 'a', NULL)")
            c.execute("CREATE TABLE public.people (id INT PRIMARY KEY, name TEXT NOT NULL, age INT CHECK (age >= 0), "
                      "password_hash TEXT)")
            c.execute("INSERT INTO public.people VALUES (1, 'a', 30, 'SECRETHASH_1')")
            for t in ("parent", "ruled", "stamped", "people"):
                c.execute("SELECT rowback.register_table('public', %s, 'id', 'mcp_agent')", (t,))
        host = url.split("@", 1)[1]
        yield url, RowbackExecutor(f"postgresql://rowback_control:secret@{host}",
                                   f"postgresql://mcp_agent:secret@{host}", max_rows_without_approval=10)


def run(ex, sql):
    return ex.execute(PolicyEngine(RowbackConfig()).evaluate(classify_sql(sql)[0]), agent_label="t", principal="t")


def test_write_through_an_inheritance_parent_is_refused(db):
    url, ex = db
    res = run(ex, "DELETE FROM public.parent WHERE id > 0")
    assert res.status == "failed" and "inheritance" in res.message
    with psycopg.connect(url) as c:
        assert c.execute("SELECT count(*) FROM public.child_archive").fetchone()[0] == 1
        assert c.execute("SELECT count(*) FROM ONLY public.parent").fetchone()[0] == 1


def test_write_to_a_table_with_rewrite_rules_is_refused(db):
    url, ex = db
    res = run(ex, "UPDATE public.ruled SET v = 'b' WHERE id = 1")
    assert res.status == "failed" and "rule" in res.message
    with psycopg.connect(url) as c:
        assert c.execute("SELECT count(*) FROM public.elsewhere").fetchone()[0] == 0


def test_write_to_a_table_with_its_own_triggers_waits_for_a_person(db):
    url, ex = db
    res = run(ex, "UPDATE public.stamped SET v = 'b' WHERE id = 1")
    assert res.status == "approval_required" and "can't be undone" in res.message
    with psycopg.connect(url) as c:
        assert c.execute("SELECT v FROM public.stamped").fetchone()[0] == "a"
    assert ex.execute_pending(res.public_id, actor="cli:ops").status == "applied"  # a person accepted it


@pytest.mark.parametrize("sql", ["UPDATE public.people SET name = NULL WHERE id = 1",
                                 "UPDATE public.people SET age = -1 WHERE id = 1"])
def test_constraint_errors_never_show_the_failing_row(db, sql):
    # PostgreSQL's DETAIL prints the whole row, secret columns included.
    _, ex = db
    res = run(ex, sql)
    assert res.status == "failed" and "violates" in res.message
    assert "SECRETHASH" not in res.message and "Failing row" not in res.message


def test_registered_secret_columns_are_hidden_by_the_database(db):
    # Column privileges: PostgreSQL itself refuses, whatever the SQL looks like.
    url, ex = db
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("SELECT rowback.register_table('public', 'people', 'id', 'mcp_agent', ARRAY['password_hash'])")
        assert c.execute("SELECT has_column_privilege('mcp_agent', 'public.people', 'password_hash', 'SELECT'), "
                         "has_column_privilege('mcp_agent', 'public.people', 'name', 'SELECT')").fetchone() == (False, True)
    res = run(ex, "SELECT * FROM public.people")
    assert res.status == "failed" and "permission denied" in res.message and "name the columns" in res.message
    assert run(ex, "SELECT id, name FROM public.people WHERE id = 1").data == [{"id": 1, "name": "a"}]
    assert run(ex, "UPDATE public.people SET age = 31 WHERE id = 1").status == "applied"
