"""A write that fails at COMMIT was rolled back for certain: report it as failed, not 'unknown'."""
import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from lomberk.capture.install import install_lomberk
from lomberk.config import LomberkConfig
from lomberk.executor import LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.sql.classify import classify_sql


@pytest.fixture(scope="module")
def dsns():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE lomberk_control LOGIN PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent LOGIN PASSWORD 'secret'")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE TABLE public.parent (id INT PRIMARY KEY)")
            conn.execute("CREATE TABLE public.child (id INT PRIMARY KEY, parent_id INT "
                         "REFERENCES public.parent(id) DEFERRABLE INITIALLY DEFERRED)")
            conn.execute("INSERT INTO public.parent VALUES (1)")
            conn.execute("INSERT INTO public.child VALUES (1, 1)")
            for t in ("parent", "child"):
                conn.execute("SELECT lomberk.register_table('public', %s, 'id', 'mcp_agent')", (t,))
        host = url.split("@", 1)[1]
        yield url, f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


def test_deferred_constraint_failure_is_failed_not_unknown(dsns):
    admin, control, agent = dsns
    ex = LomberkExecutor(control, agent)
    stmt = classify_sql("UPDATE public.child SET parent_id = 99 WHERE id = 1")[0]
    res = ex.execute(PolicyEngine(LomberkConfig()).evaluate(stmt), principal="agent")
    assert res.status == "failed", res.message
    assert ex.check_status(res.public_id) == "failed"
    with psycopg.connect(admin) as conn:
        assert conn.execute("SELECT parent_id FROM public.child WHERE id = 1").fetchone()[0] == 1


def test_a_checkpoint_left_approved_by_a_crash_can_be_closed(dsns):
    _, control, agent = dsns
    ex = LomberkExecutor(control, agent)
    pid = ex.create_pending_checkpoint("UPDATE public.parent SET id = 2 WHERE id = 1", "WRITE_DML", "REQUIRE_APPROVAL", "agent")
    with psycopg.connect(control, autocommit=True) as conn:  # approved, then the gateway died before running it
        conn.execute("SELECT lomberk.approve_checkpoint(%s, 'ALLOW')", (pid,))
    assert ex.check_status(pid) == "approved"
    assert ex.reject(pid, actor="cli:ops") is True
    assert ex.check_status(pid) == "failed"
    assert ex.reject(pid, actor="cli:ops") is False
