import os
import threading

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from rowback.capture.install import install_rowback
from rowback.executor import RowbackExecutor


@pytest.fixture(scope="module")
def postgres():
    with PostgresContainer(os.environ.get("ROWBACK_TEST_PG_IMAGE", "postgres:16-alpine")) as postgres:
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
        cur.execute("DROP ROLE IF EXISTS rowback_control")
        cur.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
    install_rowback(dsn, control_role="rowback_control", agent_role="mcp_agent")

    with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("CREATE TABLE public.test_race (id SERIAL PRIMARY KEY, val INT);")
        cur.execute("INSERT INTO public.test_race (val) VALUES (0);")
        cur.execute("SELECT rowback.register_table('public', 'test_race', 'id', 'mcp_agent');")

def test_concurrent_approval(dsn, runtime_dsn, setup_db):
    # Insert a pending checkpoint manually
    import uuid
    public_id = f"cp_{uuid.uuid4().hex[:8]}"
    sql_text = "UPDATE public.test_race SET val = val + 1 WHERE id = 1;"

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO rowback.checkpoints (public_id, agent_label, sql_text, classification, decision, status) VALUES (%s, %s, %s, %s, %s, %s)",
                (public_id, "test_agent", sql_text, "DML_WRITE", "REQUIRE_APPROVAL", "pending")
            )

    # We will spawn 5 threads to approve concurrently
    results = []
    exceptions = []
    barrier = threading.Barrier(5)

    def worker():
        try:
            barrier.wait(timeout=5)
            executor = RowbackExecutor(dsn, runtime_dsn)
            res = executor.execute_pending(public_id)
            results.append(res)
        except Exception as e:
            exceptions.append(e)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

# Only 1 should succeed
    successes = [r for r in results if r.status == "applied"]
    failures = [r for r in results if r.status == "failed"]

    assert len(successes) == 1
    print([r.status for r in results]); assert len(failures) == 4
    for f in failures:
        assert "not pending" in f.message or "Token not found" in f.message

    # Verify the value was only incremented ONCE
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT val FROM public.test_race LIMIT 1")
            val = cur.fetchone()[0]
            assert val == 1
