"""Undo puts every column back bit for bit, whatever its type, and whatever its name: a column
called `t`, `r` or `row` must not be mistaken for the row itself inside undo's own queries."""
import os
from urllib.parse import urlparse, urlunparse

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback
from rowback.executor import RowbackExecutor
from rowback.models import ClassifiedStatement, PolicyDecision, StatementClass, StatementEvaluation


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("ROWBACK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        dsn = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        p = urlparse(dsn)

        def as_role(role):
            return urlunparse((p.scheme, f"{role}:secret@{p.hostname}:{p.port}", p.path, "", "", ""))

        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE ROLE rowback_control LOGIN PASSWORD 'secret'")
            cur.execute("CREATE ROLE mcp_agent LOGIN PASSWORD 'secret'")
        install_rowback(dsn, control_role="rowback_control", agent_role="mcp_agent")
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TYPE public.mood AS ENUM ('ok', 'sad');
                CREATE TABLE public.typed (
                    id int PRIMARY KEY, t timestamp, r real, "row" text, j jsonb, ja json, arr int[], tarr text[],
                    b bytea, n numeric(30,10), f float8, ts timestamptz, d date, iv interval, u uuid,
                    m public.mood, big text, ip inet, nul text, money_c money, pt point, bits bit varying(8),
                    tsr tstzrange, jn jsonb, g int GENERATED ALWAYS AS (id * 2) STORED);
            """)
            cur.execute("SELECT rowback.register_table('public', 'typed', 'id', 'mcp_agent')")
        yield dsn, RowbackExecutor(as_role("rowback_control"), as_role("mcp_agent"))


@pytest.fixture(autouse=True)
def seed(db):
    """Every case starts from the same two rows, so one case's damage can't hide another's."""
    with psycopg.connect(db[0], autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                SET session_replication_role = replica;
                DELETE FROM public.typed;
                INSERT INTO public.typed (id, t, r, "row", j, ja, arr, tarr, b, n, f, ts, d, iv, u, m, big, ip, nul,
                                          money_c, pt, bits, tsr, jn) VALUES
                 (1, '2026-01-01 10:00:00.654321', 3.14159, 'r1', '{"a":[1,2,{"b":null}],"ü":"ş"}', '{"k": 1,  "k": 2}',
                  '{1,NULL,3}', '{"a,b","c\\"d",NULL}', '\\x00ff10', '12345678901234567890.0123456789',
                  1.0000000000000002, '2026-01-01 10:00:00.123456+03', '2026-02-28', '1 year 2 mons 3 days 04:05:06.789',
                  'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', 'sad', repeat('Z', 300000), '10.0.0.1/24', NULL,
                  '$1,234.56', '(1.5,2.5)', B'1011', '[2026-01-01,2026-02-01)', 'null'),
                 (2, '-infinity', 'NaN', '', '[]', 'null', '{}', '{}', '', '0', -0.0, 'infinity', 'epoch', '0',
                  '00000000-0000-0000-0000-000000000000', 'ok', '', '::1', '', '0', '(0,0)', B'', 'empty', NULL);
        """)


@pytest.fixture(autouse=True)
def no_llm(monkeypatch):
    monkeypatch.setattr("rowback.sentinel.AISentinel.evaluate_intent", lambda self, sql, tables: (True, ""))


def snapshot(dsn):
    """Each value as Postgres prints it, so json whitespace or a float's last digit counts."""
    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute("SELECT * FROM public.typed LIMIT 0")
        cols = [d.name for d in cur.description]
        cur.execute("SELECT " + ", ".join(f'"{c}"::text' for c in cols) + " FROM public.typed ORDER BY id")
        return [dict(zip(cols, row, strict=True)) for row in cur.fetchall()]


@pytest.mark.parametrize("sql", [
    "UPDATE public.typed SET t = now(), r = 1, \"row\" = 'x', j = '{}', ja = '[]', arr = '{9}', tarr = '{x}', "
    "b = '\\x01', n = 1, f = 2, ts = now(), d = now(), iv = '1s', u = 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a12', "
    "m = 'ok', big = 'small', ip = '1.1.1.1', nul = 'was null', money_c = 5, pt = '(9,9)', bits = B'1', "
    "tsr = '[2020-01-01,2020-01-02)', jn = '1' WHERE id IN (1, 2)",
    "DELETE FROM public.typed WHERE id IN (1, 2)",
    "INSERT INTO public.typed (id, t, j) VALUES (3, now(), '{\"new\": true}')",
])
def test_undo_restores_every_type_exactly(db, sql):
    dsn, ex = db
    before = snapshot(dsn)
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[])
    res = ex.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason=""))
    assert res.status == "applied", res.message
    assert snapshot(dsn) != before
    undo = ex.execute_undo(res.public_id)
    assert undo.status == "undone", undo.message
    after = snapshot(dsn)
    changed = {(r["id"], k): (r[k], a.get(k)) for r, a in zip(before, after, strict=True) for k in r if r[k] != a.get(k)}
    assert len(after) == len(before) and not changed, changed


def test_rows_captured_before_the_exact_copy_still_undo(db):
    """Checkpoints written by an older Rowback have no old_text: undo falls back to the JSON copy."""
    dsn, ex = db
    before = snapshot(dsn)
    sql = "UPDATE public.typed SET big = 'x', n = 2, arr = '{7}' WHERE id = 1"
    stmt = ClassifiedStatement(sql=sql, stmt_class=StatementClass.WRITE_DML, tables=[])
    res = ex.execute(StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason=""))
    assert res.status == "applied", res.message
    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute("UPDATE rowback.row_changes SET old_text = NULL")
    undo = ex.execute_undo(res.public_id)
    assert undo.status == "undone", undo.message
    after = snapshot(dsn)
    assert [r["big"] for r in after] == [r["big"] for r in before]
    assert after[0]["n"] == before[0]["n"] and after[0]["arr"] == before[0]["arr"]
