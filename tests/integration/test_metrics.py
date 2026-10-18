"""/metrics: Prometheus counts for dashboards and alerts (held writes piling up, a burst of
denials). Off unless ROWBACK_METRICS_KEY is set, and it never shows SQL, rows or people."""
import os

import psycopg
import pytest
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer

from rowback.api import app, get_executor
from rowback.capture.install import install_rowback
from rowback.config import RowbackConfig
from rowback.executor import RowbackExecutor
from rowback.policy import PolicyEngine
from rowback.sql.classify import classify_sql

KEY = "metrics-test-key"


@pytest.fixture(scope="module")
def stack():
    with PostgresContainer(os.environ.get("ROWBACK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_rowback(url, control_role="rowback_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE TABLE public.vault (id INT PRIMARY KEY, secret_note TEXT)")
            c.execute("INSERT INTO public.vault VALUES (1, 'TOPSECRET')")
            c.execute("SELECT rowback.register_table('public', 'vault', NULL, 'mcp_agent')")
        host = url.split("@", 1)[1]
        control, agent = f"postgresql://rowback_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"
        env = {"ROWBACK_AGENT_DSN": agent, "ROWBACK_ADMIN_DSN": control, "ROWBACK_API_KEY": "agent-k",
               "ROWBACK_ADMIN_KEY": "admin-k", "ROWBACK_METRICS_KEY": KEY}
        with pytest.MonkeyPatch.context() as mp:
            for k, v in env.items():
                mp.setenv(k, v)
            executor = RowbackExecutor(control, agent, protected_tables=["public.vault"])
            app.dependency_overrides[get_executor] = lambda: executor
            with TestClient(app) as client:
                yield client, executor
            app.dependency_overrides.clear()


def test_metrics_need_their_own_key(stack):
    client, _ = stack
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer admin-k"}).status_code == 401
    assert client.get("/metrics", headers={"X-API-Key": KEY}).status_code == 401


def test_metrics_count_decisions_and_held_writes_without_leaking_data(stack):
    client, ex = stack
    engine = PolicyEngine(RowbackConfig(protected_tables=["public.vault"]))
    ex.execute(engine.evaluate(classify_sql("DROP TABLE public.vault")[0]), principal="t")
    ex.execute(engine.evaluate(classify_sql("UPDATE public.vault SET secret_note = 'x' WHERE id = 1")[0]), principal="t")
    res = client.get("/metrics", headers={"Authorization": f"Bearer {KEY}"})
    assert res.status_code == 200 and res.headers["content-type"].startswith("text/plain")
    body = res.text
    assert 'rowback_events_total{event="denied"}' in body and 'rowback_events_total{event="held"}' in body
    assert "rowback_pending_checkpoints 1" in body and "rowback_database_up 1" in body
    assert "vault" not in body and "TOPSECRET" not in body and "UPDATE" not in body


def test_metrics_are_off_without_a_key(stack, monkeypatch):
    import rowback.api as api
    monkeypatch.setattr(api, "_METRICS_KEY", None)
    client, _ = stack
    assert client.get("/metrics", headers={"Authorization": f"Bearer {KEY}"}).status_code == 404
