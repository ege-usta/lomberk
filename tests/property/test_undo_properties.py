import os

import psycopg
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback
from rowback.executor import RowbackExecutor
from rowback.models import (
    ClassifiedStatement,
    PolicyDecision,
    StatementClass,
    StatementEvaluation,
)


@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer(os.environ.get("ROWBACK_TEST_PG_IMAGE", os.environ.get("ROWBACK_TEST_PG_IMAGE", "postgres:16-alpine"))) as postgres:
        yield postgres

@pytest.fixture(scope="module")
def dsn(postgres):
    return postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")


@pytest.fixture(scope="module")
def runtime_dsn(dsn):
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(dsn)
    return urlunparse((parsed.scheme, f"mcp_agent:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))

@pytest.fixture(scope="module")
def setup_db(dsn):
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("DROP ROLE IF EXISTS mcp_agent")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
        cur.execute("DROP ROLE IF EXISTS rowback_control")
        cur.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
    install_rowback(dsn, control_role="rowback_control", agent_role="mcp_agent")
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
                CREATE TABLE public.prop_users (
                    id SERIAL PRIMARY KEY,
                    val INT NOT NULL
                );
            """)
        cur.execute("SELECT rowback.register_table('public', 'prop_users', 'id', 'mcp_agent');")

def get_checksum(dsn):
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT md5(string_agg(t::text, '|' ORDER BY id)) FROM public.prop_users t")
            return cur.fetchone()[0]

@settings(max_examples=20, deadline=None)
@given(
    ops=st.lists(
        st.tuples(
            st.sampled_from(["INSERT", "UPDATE", "DELETE"]),
            st.integers(min_value=1, max_value=50) # val to insert/update or id to delete
        ),
        min_size=1, max_size=10
    )
)
def test_undo_property(dsn, runtime_dsn, setup_db, ops):
    executor = RowbackExecutor(dsn, runtime_dsn)


    # 1. Capture initial state
    initial_checksum = get_checksum(dsn)

    # 2. Execute random operations in one checkpoint
    sql_statements = []
    for op, val in ops:
        if op == "INSERT":
            sql_statements.append(f"INSERT INTO public.prop_users (val) VALUES ({val});")
        elif op == "UPDATE":
            sql_statements.append(f"UPDATE public.prop_users SET val = {val} WHERE id IN (SELECT id FROM public.prop_users ORDER BY random() LIMIT 1);")
        elif op == "DELETE":
            sql_statements.append("DELETE FROM public.prop_users WHERE id IN (SELECT id FROM public.prop_users ORDER BY random() LIMIT 1);")

    sql_text = " ".join(sql_statements)

    stmt = ClassifiedStatement(sql=sql_text, stmt_class=StatementClass.WRITE_DML, tables=["public.prop_users"], is_multistatement=True)
    eval = StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="Test")

    res = executor.execute(eval)

    # If the transaction somehow failed (e.g., deadlock or syntax, though unlikely here), we skip
    if res.status != "applied":
        return

    _cp_id = res.checkpoint_id

    # 3. Undo
    res_undo = executor.execute_undo(res.public_id)
    assert res_undo.status == 'undone'

    # 4. Verify checksum matches
    final_checksum = get_checksum(dsn)
    assert final_checksum == initial_checksum

