"""Database-level guarantees that no single code change should quietly undo."""
import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback

AGENT_MAY_EXECUTE = {"claim_checkpoint", "finish_checkpoint", "unprotected_cascade_child"}


@pytest.fixture(scope="module")
def dsn():
    with PostgresContainer("postgres:16-alpine") as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_rowback(url, control_role="rowback_control", agent_role="mcp_agent")
        install_rowback(url, control_role="rowback_control", agent_role="mcp_agent")  # upgrades re-run it
        yield url


def _functions(conn, where: str) -> set[str]:
    return {r[0] for r in conn.execute(
        "SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
        f"WHERE n.nspname = 'rowback' AND {where}")}


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
