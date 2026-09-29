"""rowback doctor: every problem gets a plain message and a fix, and the exit code says if it's safe to start."""
import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer
from typer.testing import CliRunner

import rowback.ee.license as lic
from rowback.capture.install import install_rowback
from rowback.cli import app

KEYS = {"ROWBACK_API_KEY": "a" * 40, "ROWBACK_ADMIN_KEY": "b" * 40}


@pytest.fixture(scope="module")
def db():
    with PostgresContainer("postgres:16-alpine") as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE DATABASE empty")
        install_rowback(url, control_role="rowback_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE TABLE public.orders (id INT PRIMARY KEY)")
            conn.execute("SELECT rowback.register_table('public', 'orders', 'id', 'mcp_agent')")
        host = url.split("@", 1)[1]
        yield f"postgresql://rowback_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


def doctor(monkeypatch, tmp_path, env, yaml=""):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "rowback.yaml").write_text(yaml)
    for k in ("ROWBACK_ADMIN_DSN", "ROWBACK_AGENT_DSN", "ROWBACK_API_KEY", "ROWBACK_ADMIN_KEY", "ROWBACK_LICENSE_KEY"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return CliRunner().invoke(app, ["doctor"])


def test_healthy_deployment(db, monkeypatch, tmp_path):
    control, agent = db
    r = doctor(monkeypatch, tmp_path, {"ROWBACK_ADMIN_DSN": control, "ROWBACK_AGENT_DSN": agent, **KEYS},
               "protected_tables: [public.orders]\n")
    assert r.exit_code == 0, r.output
    assert "public.orders" in r.output and "ledger intact" in r.output and "Ready" in r.output


def test_missing_env_and_same_keys(db, monkeypatch, tmp_path):
    control, _ = db
    r = doctor(monkeypatch, tmp_path, {"ROWBACK_ADMIN_DSN": control, "ROWBACK_API_KEY": "k", "ROWBACK_ADMIN_KEY": "k"})
    assert r.exit_code == 1
    assert "ROWBACK_AGENT_DSN is not set" in r.output and "are the same" in r.output and "openssl rand" in r.output


def test_same_role_twice_and_uninstalled_db(db, monkeypatch, tmp_path):
    control, _ = db
    empty = control.rsplit("/", 1)[0] + "/empty"
    r = doctor(monkeypatch, tmp_path, {"ROWBACK_ADMIN_DSN": empty, "ROWBACK_AGENT_DSN": empty, **KEYS})
    assert r.exit_code == 1 and "both connection strings log in as rowback_control" in r.output
    assert "not installed" in r.output and "rowback init" in r.output


def test_config_typo_and_unregistered_protected_table(db, monkeypatch, tmp_path):
    control, agent = db
    env = {"ROWBACK_ADMIN_DSN": control, "ROWBACK_AGENT_DSN": agent, **KEYS}
    r = doctor(monkeypatch, tmp_path, env, "protected_table: [public.users]\n")
    assert r.exit_code == 1 and "invalid" in r.output
    r = doctor(monkeypatch, tmp_path, env, "protected_tables: [public.users]\n")
    assert r.exit_code == 0 and "protected but not registered: public.users" in r.output


def test_pro_feature_without_or_with_bad_key(db, monkeypatch, tmp_path):
    control, agent = db
    env = {"ROWBACK_ADMIN_DSN": control, "ROWBACK_AGENT_DSN": agent, **KEYS}
    r = doctor(monkeypatch, tmp_path, env, "approvals:\n  required: 2\n")
    assert r.exit_code == 1 and "two-person approval needs a Pro license key" in r.output
    monkeypatch.setattr(lic, "validate_key", lambda key: "invalid")
    r = doctor(monkeypatch, tmp_path, {**env, "ROWBACK_LICENSE_KEY": "bad"}, "approvals:\n  required: 2\n")
    assert r.exit_code == 1 and "invalid, expired or cancelled" in r.output
