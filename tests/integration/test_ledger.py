"""Tamper evidence: the checkpoint ledger is append-only and hash-chained, so even
a database owner editing history is detected by verify_ledger()."""
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
            cur.execute("CREATE TABLE public.t (id INT PRIMARY KEY, v TEXT)")
            cur.execute("SELECT lomberk.register_table('public', 't', 'id', 'mcp_agent')")
        yield dsn, as_role("lomberk_control"), LomberkExecutor(as_role("lomberk_control"), as_role("mcp_agent"))


def write(ex, sql):
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[])
    return ex.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason=""))


def verify(dsn):
    with psycopg.connect(dsn) as conn:
        return conn.execute("SELECT * FROM lomberk.verify_ledger()").fetchone()


def test_ledger_chains_every_checkpoint_including_undo(db, monkeypatch):
    monkeypatch.setattr("lomberk.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))
    _, control, ex = db
    for i in range(3):
        assert write(ex, f"INSERT INTO public.t VALUES ({i}, 'x')").status == "applied"
    res = write(ex, "UPDATE public.t SET v = 'y' WHERE id = 1")
    assert ex.execute_undo(res.public_id).status == "undone"
    checked, broken, head = verify(control)  # control role may verify
    assert (checked, broken) == (5, None) and len(head) == 64


@pytest.mark.parametrize("attack", [
    "UPDATE lomberk.checkpoints SET sql_text = 'SELECT 1' WHERE chain_seq = 1",
    "DELETE FROM lomberk.checkpoints WHERE chain_seq = 2",
])
def test_history_edits_are_blocked(db, attack):
    admin, _, _ = db
    with psycopg.connect(admin, autocommit=True) as conn, pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        conn.execute(attack)


def test_owner_bypassing_guards_is_detected(db):
    admin, _, _ = db
    with psycopg.connect(admin, autocommit=True) as conn:
        conn.execute("ALTER TABLE lomberk.checkpoints DISABLE TRIGGER lomberk_immutable")
        conn.execute("UPDATE lomberk.checkpoints SET sql_text = 'INSERT INTO public.t VALUES (99, $$innocent$$)' WHERE chain_seq = 2")
        conn.execute("ALTER TABLE lomberk.checkpoints ENABLE TRIGGER lomberk_immutable")
        second = conn.execute("SELECT public_id FROM lomberk.checkpoints WHERE chain_seq = 2").fetchone()[0]
    checked, broken, head = verify(admin)
    assert broken == second and checked == 1 and head is None
