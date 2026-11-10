"""/metrics: Prometheus counts for dashboards and alerts (held writes piling up, a burst of
denials). Off unless LOMBERK_METRICS_KEY is set, and it never shows SQL, rows or people."""
import os

import psycopg
import pytest
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer

from lomberk.api import app, get_executor
from lomberk.capture.install import install_lomberk
from lomberk.config import LomberkConfig
from lomberk.executor import LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.sql.classify import classify_sql

KEY = "metrics-test-key"


@pytest.fixture(scope="module")
def stack():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE TABLE public.vault (id INT PRIMARY KEY, secret_note TEXT)")
            c.execute("INSERT INTO public.vault VALUES (1, 'TOPSECRET')")
            c.execute("SELECT lomberk.register_table('public', 'vault', NULL, 'mcp_agent')")
        host = url.split("@", 1)[1]
        control, agent = f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"
        env = {"LOMBERK_AGENT_DSN": agent, "LOMBERK_ADMIN_DSN": control, "LOMBERK_API_KEY": "agent-k",
               "LOMBERK_ADMIN_KEY": "admin-k", "LOMBERK_METRICS_KEY": KEY}
        with pytest.MonkeyPatch.context() as mp:
            for k, v in env.items():
                mp.setenv(k, v)
            executor = LomberkExecutor(control, agent, protected_tables=["public.vault"])
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
    engine = PolicyEngine(LomberkConfig(protected_tables=["public.vault"]))
    ex.execute(engine.evaluate(classify_sql("DROP TABLE public.vault")[0]), principal="t")
    ex.execute(engine.evaluate(classify_sql("UPDATE public.vault SET secret_note = 'x' WHERE id = 1")[0]), principal="t")
    res = client.get("/metrics", headers={"Authorization": f"Bearer {KEY}"})
    assert res.status_code == 200 and res.headers["content-type"].startswith("text/plain")
    body = res.text
    assert 'lomberk_events_total{event="denied"}' in body and 'lomberk_events_total{event="held"}' in body
    assert "lomberk_pending_checkpoints 1" in body and "lomberk_database_up 1" in body
    assert "vault" not in body and "TOPSECRET" not in body and "UPDATE" not in body


def test_metrics_are_off_without_a_key(stack, monkeypatch):
    import lomberk.api as api
    monkeypatch.setattr(api, "_METRICS_KEY", None)
    client, _ = stack
    assert client.get("/metrics", headers={"Authorization": f"Bearer {KEY}"}).status_code == 404
