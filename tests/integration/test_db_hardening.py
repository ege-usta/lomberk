"""Database-level guarantees that no single code change should quietly undo."""
import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from lomberk.capture.install import install_lomberk

# primary_key_columns: a plain catalog read (not SECURITY DEFINER) the pre-write check needs.
AGENT_MAY_EXECUTE = {"claim_checkpoint", "finish_checkpoint", "unprotected_cascade_child", "primary_key_columns", "preview_changes",
                     "inheritance_problem"}


@pytest.fixture(scope="module")
def dsn():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")  # upgrades re-run it
        yield url


def _functions(conn, where: str) -> set[str]:
    return {r[0] for r in conn.execute(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        f"WHERE n.nspname = 'lomberk' AND {where}")}


def test_every_security_definer_function_pins_search_path(dsn):
    # Without it, a caller who can create objects (PUBLIC on PostgreSQL <= 14) can shadow
    # an unqualified function and run code as the function's owner.
    with psycopg.connect(dsn) as conn:
        unpinned = _functions(conn, "p.prosecdef AND NOT EXISTS (SELECT 1 FROM unnest(coalesce(p.proconfig, '{}')) c "
                                    "WHERE c LIKE 'search_path=%')")
    assert unpinned == set()


def test_public_executes_nothing_and_agent_only_its_runtime_functions(dsn):
    with psycopg.connect(dsn) as conn:
        assert _functions(conn, "has_function_privilege('public', p.oid, 'EXECUTE')") == set()
        assert _functions(conn, "has_function_privilege('mcp_agent', p.oid, 'EXECUTE')") <= AGENT_MAY_EXECUTE | {
            "capture_row_change"}  # trigger function; it checks the capability token itself


def test_retired_table_lock_function_is_gone(dsn):
    with psycopg.connect(dsn) as conn:
        assert _functions(conn, "p.proname = 'lock_table_for_undo'") == set()


def test_control_role_cannot_run_register_table(dsn):
    # register_table is SECURITY DEFINER (runs as the installer). A leaked control DSN
    # must not be able to grant itself DML/SELECT on arbitrary tables through it.
    with psycopg.connect(dsn) as conn:
        assert not _functions(conn, "p.proname = 'register_table' "
                              "AND has_function_privilege('lomberk_control', p.oid, 'EXECUTE')")
