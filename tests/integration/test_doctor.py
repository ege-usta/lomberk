"""lomberk doctor: every problem gets a plain message and a fix, and the exit code says if it's safe to start."""
import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer
from typer.testing import CliRunner

import lomberk.ee.license as lic
from lomberk.capture.install import install_lomberk
from lomberk.cli import app

KEYS = {"LOMBERK_API_KEY": "3f9c2a7e1b8d4065c7a9e2f1d3b5a8c6", "LOMBERK_ADMIN_KEY": "8e1d7c4b2a9f6035e1c8b7a4d2f9e6c3"}


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE DATABASE empty")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE TABLE public.orders (id INT PRIMARY KEY)")
            conn.execute("SELECT lomberk.register_table('public', 'orders', 'id', 'mcp_agent')")
        host = url.split("@", 1)[1]
        yield f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


def doctor(monkeypatch, tmp_path, env, yaml=""):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "lomberk.yaml").write_text(yaml)
    for k in ("LOMBERK_ADMIN_DSN", "LOMBERK_AGENT_DSN", "LOMBERK_API_KEY", "LOMBERK_ADMIN_KEY", "LOMBERK_LICENSE_KEY",
              "LOMBERK_CONFIG"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return CliRunner().invoke(app, ["doctor"])


def test_healthy_deployment(db, monkeypatch, tmp_path):
    control, agent = db
    r = doctor(monkeypatch, tmp_path, {"LOMBERK_ADMIN_DSN": control, "LOMBERK_AGENT_DSN": agent, **KEYS},
               "protected_tables: [public.orders]\n")
    assert r.exit_code == 0, r.output
    assert "public.orders" in r.output and "ledger intact" in r.output and "Ready" in r.output


def test_missing_env_and_same_keys(db, monkeypatch, tmp_path):
    control, _ = db
    r = doctor(monkeypatch, tmp_path, {"LOMBERK_ADMIN_DSN": control, "LOMBERK_API_KEY": "k", "LOMBERK_ADMIN_KEY": "k"})
    assert r.exit_code == 1
    assert "LOMBERK_AGENT_DSN is not set" in r.output and "are the same" in r.output and "openssl rand" in r.output


def test_same_role_twice_and_uninstalled_db(db, monkeypatch, tmp_path):
    control, _ = db
    empty = control.rsplit("/", 1)[0] + "/empty"
    r = doctor(monkeypatch, tmp_path, {"LOMBERK_ADMIN_DSN": empty, "LOMBERK_AGENT_DSN": empty, **KEYS})
    assert r.exit_code == 1 and "both connection strings log in as lomberk_control" in r.output
    assert "not installed" in r.output and "lomberk init" in r.output


def test_config_typo_and_unregistered_protected_table(db, monkeypatch, tmp_path):
    control, agent = db
    env = {"LOMBERK_ADMIN_DSN": control, "LOMBERK_AGENT_DSN": agent, **KEYS}
    r = doctor(monkeypatch, tmp_path, env, "protected_table: [public.users]\n")
    assert r.exit_code == 1 and "invalid: protected_table" in r.output
    r = doctor(monkeypatch, tmp_path, env, "protected_tables: [public.users]\n")
    assert r.exit_code == 0 and "protected but not registered: public.users" in r.output


def test_config_named_by_lomberk_config(db, monkeypatch, tmp_path):
    control, agent = db
    elsewhere = tmp_path / "etc"
    elsewhere.mkdir()
    (elsewhere / "prod.yaml").write_text("protected_tables: [public.orders]\n")
    env = {"LOMBERK_ADMIN_DSN": control, "LOMBERK_AGENT_DSN": agent, **KEYS,
           "LOMBERK_CONFIG": str(elsewhere / "prod.yaml")}
    r = doctor(monkeypatch, tmp_path, env)
    assert r.exit_code == 0 and "prod.yaml is valid" in r.output and "public.orders" in r.output, r.output
    env["LOMBERK_CONFIG"] = str(elsewhere / "missing.yaml")
    r = doctor(monkeypatch, tmp_path, env)
    assert r.exit_code == 1 and "does not exist" in r.output and "refuse to start" in r.output


def test_pro_feature_without_or_with_bad_key(db, monkeypatch, tmp_path):
    control, agent = db
    env = {"LOMBERK_ADMIN_DSN": control, "LOMBERK_AGENT_DSN": agent, **KEYS}
    r = doctor(monkeypatch, tmp_path, env, "approvals:\n  required: 2\n")
    assert r.exit_code == 1 and "two-person approval needs a Pro license key" in r.output
    monkeypatch.setattr(lic, "validate_key", lambda key, activation_id=None: lic.Validation("invalid"))
    r = doctor(monkeypatch, tmp_path, {**env, "LOMBERK_LICENSE_KEY": "bad"}, "approvals:\n  required: 2\n")
    assert r.exit_code == 1 and "invalid, expired or cancelled" in r.output


def test_secret_columns_the_database_still_shows(db, monkeypatch, tmp_path):
    control, agent = db
    install = control.replace("lomberk_control:secret", "test:test")
    with psycopg.connect(install, autocommit=True) as conn:
        conn.execute("CREATE TABLE public.members (id INT PRIMARY KEY, password_hash TEXT, card_pin TEXT, prefs JSONB)")
        conn.execute("SELECT lomberk.register_table('public', 'members', 'id', 'mcp_agent')")
    env = {"LOMBERK_ADMIN_DSN": control, "LOMBERK_AGENT_DSN": agent, **KEYS}
    out = " ".join(doctor(monkeypatch, tmp_path, env).output.split())  # the console wraps lines
    assert "can read secret columns in the database: public.members.password_hash" in out, out
    assert "public.members.card_pin" in out and "JSON columns: public.members.prefs" in out
    with psycopg.connect(install, autocommit=True) as conn:
        conn.execute("SELECT lomberk.register_table('public', 'members', 'id', 'mcp_agent', "
                     "ARRAY['password_hash', 'card_pin', 'prefs'])")
    out = " ".join(doctor(monkeypatch, tmp_path, env, "sensitive_columns: [card_pin, prefs]\n").output.split())
    assert "no secret-looking column is readable" in out, out


def test_sequences_no_registered_table_draws_from(db, monkeypatch, tmp_path):
    control, agent = db
    install = control.replace("lomberk_control:secret", "test:test")
    with psycopg.connect(install, autocommit=True) as conn:
        conn.execute("CREATE TABLE public.tickets (id SERIAL PRIMARY KEY, title TEXT)")
        conn.execute("SELECT lomberk.register_table('public', 'tickets', 'id', 'mcp_agent')")
        conn.execute("CREATE TABLE public.invoices (id BIGSERIAL PRIMARY KEY)")  # not registered
    env = {"LOMBERK_ADMIN_DSN": control, "LOMBERK_AGENT_DSN": agent, **KEYS}
    out = " ".join(doctor(monkeypatch, tmp_path, env).output.split())
    assert "sequence(s)" not in out, out  # the registered table's own sequence is expected
    with psycopg.connect(install, autocommit=True) as conn:  # what older versions granted
        conn.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_agent")
    try:
        out = " ".join(doctor(monkeypatch, tmp_path, env).output.split())
        assert "may use 1 sequence(s) no registered table draws from: invoices_id_seq" in out, out
        assert "REVOKE USAGE, SELECT ON SEQUENCE invoices_id_seq FROM mcp_agent" in out
        assert "public.tickets_id_seq" not in out and "tickets_id_seq," not in out
    finally:
        with psycopg.connect(install, autocommit=True) as conn:
            conn.execute("REVOKE USAGE, SELECT ON SEQUENCE public.invoices_id_seq FROM mcp_agent")
