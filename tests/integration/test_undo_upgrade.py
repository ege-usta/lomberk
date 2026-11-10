import os

import psycopg
import pytest

from lomberk.capture.install import install_lomberk


@pytest.fixture(scope="module")
def postgres():
    from testcontainers.community.postgres import PostgresContainer
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as postgres:
        yield postgres

@pytest.fixture(scope="module")
def dsn(postgres):
    return postgres.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")

def test_upgrade_removes_old_signatures_and_grants(dsn):
    # 1. Setup roles
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")

    # 2. Run current installer
    install_lomberk(dsn, control_role="lomberk_control", agent_role="mcp_agent")

    # 3. Simulate old state by creating the old function and granting bad privileges
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""
        CREATE OR REPLACE FUNCTION lomberk.execute_undo_dml(
            p_public_id TEXT, p_schema TEXT, p_op CHAR, p_pk_col TEXT, p_pk_val TEXT, p_old JSONB, p_new JSONB
        ) RETURNS VOID AS $$ BEGIN END; $$ LANGUAGE plpgsql;
        """)
        cur.execute("GRANT UPDATE ON lomberk.checkpoints TO lomberk_control")
        cur.execute("CREATE OR REPLACE FUNCTION lomberk.claim_checkpoint(BIGINT) RETURNS UUID AS $$ BEGIN RETURN NULL; END; $$ LANGUAGE plpgsql;")
        cur.execute("GRANT EXECUTE ON FUNCTION lomberk.claim_checkpoint(BIGINT) TO lomberk_control")

    # 4. Run installer again (Upgrade)
    install_lomberk(dsn, control_role="lomberk_control", agent_role="mcp_agent")

    # 5. Assert function is dropped and grants are revoked
    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_proc JOIN pg_namespace ON pg_namespace.oid = pg_proc.pronamespace WHERE nspname = 'lomberk' AND proname = 'execute_undo_dml'")
        assert not cur.fetchone(), "execute_undo_dml was not dropped!"

        cur.execute("SELECT has_table_privilege('lomberk_control', 'lomberk.checkpoints', 'UPDATE')")
        assert not cur.fetchone()[0], "control_role still has UPDATE on checkpoints!"

        cur.execute("SELECT 1 FROM pg_proc JOIN pg_namespace ON pg_namespace.oid = pg_proc.pronamespace WHERE nspname = 'lomberk' AND proname = 'claim_checkpoint' AND pg_get_function_arguments(pg_proc.oid) = 'p_checkpoint_id bigint'")
        assert not cur.fetchone(), "claim_checkpoint(BIGINT) was not dropped!"
