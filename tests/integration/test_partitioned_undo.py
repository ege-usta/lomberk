"""Declarative partitioning: register the partitioned table once, and every write through it,
including one that moves a row to another partition, is captured and can be undone.
Runs on whichever PostgreSQL ROWBACK_TEST_PG_IMAGE names (CI covers 14-18); 14 differs because
triggers cloned to partitions are marked internal there."""
import os

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
    with PostgresContainer(os.environ.get("ROWBACK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_rowback(url, control_role="rowback_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE TABLE public.events (region TEXT, id INT, v TEXT, PRIMARY KEY (region, id)) PARTITION BY LIST (region)")
            c.execute("CREATE TABLE public.events_eu PARTITION OF public.events FOR VALUES IN ('eu')")
            c.execute("CREATE TABLE public.events_us PARTITION OF public.events FOR VALUES IN ('us') PARTITION BY RANGE (id)")
            c.execute("CREATE TABLE public.events_us_low PARTITION OF public.events_us FOR VALUES FROM (0) TO (1000)")
            c.execute("CREATE TABLE public.events_us_high PARTITION OF public.events_us FOR VALUES FROM (1000) TO (MAXVALUE)")
            c.execute("INSERT INTO public.events VALUES ('eu', 1, 'a'), ('eu', 2, 'b'), ('us', 5, 'c'), ('us', 2000, 'd')")
            c.execute("SELECT rowback.register_table('public', 'events', NULL, 'mcp_agent')")
            c.execute("CREATE TABLE public.stamped (k INT, id INT, v TEXT, PRIMARY KEY (k, id)) PARTITION BY LIST (k)")
            c.execute("CREATE TABLE public.stamped_1 PARTITION OF public.stamped FOR VALUES IN (1)")
            c.execute("INSERT INTO public.stamped VALUES (1, 1, 'x')")
            c.execute("SELECT rowback.register_table('public', 'stamped', NULL, 'mcp_agent')")
            c.execute("CREATE FUNCTION public.noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$")
            c.execute("CREATE TRIGGER noop BEFORE UPDATE ON public.stamped FOR EACH ROW EXECUTE FUNCTION public.noop()")
        host = url.split("@", 1)[1]
        yield url, RowbackExecutor(f"postgresql://rowback_control:secret@{host}",
                                   f"postgresql://mcp_agent:secret@{host}", max_rows_without_approval=50)


def run(ex, sql):
    return ex.execute(PolicyEngine(RowbackConfig()).evaluate(classify_sql(sql)[0]), agent_label="t", principal="t")


def snapshot(url):
    with psycopg.connect(url) as c:
        return c.execute("SELECT tableoid::regclass::text, region, id, v FROM public.events ORDER BY 2, 3").fetchall()


def test_update_delete_insert_through_the_partitioned_table_undo(db):
    url, ex = db
    before = snapshot(url)
    for sql in ("UPDATE public.events SET v = 'z' WHERE id IN (1, 5, 2000)",
                "DELETE FROM public.events WHERE id > 0",
                "INSERT INTO public.events VALUES ('eu', 9, 'n'), ('us', 1500, 'm')"):
        res = run(ex, sql)
        assert res.status == "applied", res.message
        assert ex.execute_undo(res.public_id).status == "undone"
        assert snapshot(url) == before, sql


def test_a_row_moved_to_another_partition_comes_back_where_it_was(db):
    url, ex = db
    before = snapshot(url)
    res = run(ex, "UPDATE public.events SET region = 'us', id = 1001 WHERE region = 'eu' AND id = 1")
    assert res.status == "applied"
    with psycopg.connect(url) as c:
        assert c.execute("SELECT tableoid::regclass::text FROM public.events WHERE id = 1001").fetchone()[0] == "events_us_high"
    undo = ex.execute_undo(res.public_id)
    assert undo.status == "undone" and undo.rows_affected == 2  # captured as DELETE + INSERT
    assert snapshot(url) == before


def test_a_partition_added_later_is_captured_too(db):
    url, ex = db
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("CREATE TABLE public.events_ap PARTITION OF public.events FOR VALUES IN ('ap')")
    res = run(ex, "INSERT INTO public.events VALUES ('ap', 1, 'new')")
    assert res.status == "applied"
    assert ex.execute_undo(res.public_id).status == "undone"
    with psycopg.connect(url) as c:
        assert c.execute("SELECT count(*) FROM public.events_ap").fetchone()[0] == 0


def test_writing_to_a_partition_directly_is_refused(db):
    _, ex = db
    res = run(ex, "UPDATE public.events_eu SET v = 'x' WHERE id = 1")
    assert res.status == "failed" and "not registered" in res.message


def test_registering_a_partition_points_at_its_parent(db):
    url, _ = db
    with psycopg.connect(url, autocommit=True) as c, pytest.raises(psycopg.errors.RaiseException, match="register its partitioned table public.events instead"):
        c.execute("SELECT rowback.register_table('public', 'events_eu', NULL, 'mcp_agent')")


def test_a_partition_with_capture_switched_off_blocks_the_write(db):
    url, ex = db
    with psycopg.connect(url, autocommit=True) as c:
        c.execute("ALTER TABLE public.events_us_low DISABLE TRIGGER rowback_capture")
    try:
        res = run(ex, "UPDATE public.events SET v = 'q' WHERE region = 'eu' AND id = 1")
        assert res.status == "failed" and "events_us_low has no enabled Rowback capture trigger" in res.message
    finally:
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("ALTER TABLE public.events_us_low ENABLE TRIGGER rowback_capture")


def test_partitioned_table_with_its_own_trigger_is_refused_before_writing(db):
    url, ex = db
    res = run(ex, "UPDATE public.stamped SET v = 'y' WHERE k = 1 AND id = 1")
    assert res.status == "failed" and "own trigger noop" in res.message
    with psycopg.connect(url) as c:
        assert c.execute("SELECT v FROM public.stamped").fetchone()[0] == "x"
    with psycopg.connect(url, autocommit=True) as c, pytest.raises(psycopg.errors.RaiseException, match="not supported yet"):
        c.execute("SELECT rowback.register_table('public', 'stamped', NULL, 'mcp_agent', '{}', true)")
