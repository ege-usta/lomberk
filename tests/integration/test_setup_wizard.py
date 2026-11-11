"""`lomberk setup`: one owner connection string in, a working, doctor-clean deployment out."""
import os
import stat

import dotenv
import psycopg
import pytest
import yaml
from testcontainers.community.postgres import PostgresContainer
from typer.testing import CliRunner

from lomberk.cli import app

ENV_KEYS = ("LOMBERK_ADMIN_DSN", "LOMBERK_AGENT_DSN", "LOMBERK_API_KEY", "LOMBERK_ADMIN_KEY", "LOMBERK_CONFIG",
            "LOMBERK_INSTALL_DSN", "LOMBERK_ALLOW_WEAK_KEYS")


@pytest.fixture
def owner():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE TABLE public.orders (id INT PRIMARY KEY, total INT)")
            conn.execute("CREATE TABLE public.customers (id INT PRIMARY KEY, name TEXT, password TEXT)")
            conn.execute("CREATE TABLE public.events (payload TEXT)")  # no primary key: can't be undone
            conn.execute("CREATE TABLE public.notes (id INT PRIMARY KEY, body TEXT)")
            conn.execute("ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY")
        yield url


def run_setup(monkeypatch, tmp_path, args):
    monkeypatch.chdir(tmp_path)
    for k in ENV_KEYS:  # setenv first so monkeypatch restores what setup writes into os.environ
        monkeypatch.setenv(k, "")
        monkeypatch.delenv(k)
    return CliRunner().invoke(app, ["setup", *args])


def test_setup_end_to_end(owner, monkeypatch, tmp_path):
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", owner, "--tables", "public.orders,public.customers,public.notes",
                                          "--protect", "public.customers", "--yes"])
    assert r.exit_code == 0, r.output

    env = dotenv.dotenv_values(tmp_path / ".env")
    assert stat.S_IMODE(os.stat(tmp_path / ".env").st_mode) == 0o600
    assert len(env["LOMBERK_API_KEY"]) >= 32 and env["LOMBERK_API_KEY"] != env["LOMBERK_ADMIN_KEY"]
    assert env["LOMBERK_CONFIG"] == str(tmp_path / "lomberk.yaml")
    config = yaml.safe_load((tmp_path / "lomberk.yaml").read_text())
    assert config["protected_tables"] == ["public.customers"]

    with psycopg.connect(env["LOMBERK_AGENT_DSN"]) as conn:
        user, = conn.execute("SELECT current_user").fetchone()
        assert user == "lomberk_agent"
        assert not conn.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user").fetchone()[0]
    with psycopg.connect(owner) as conn:
        registered = {r[0] for r in conn.execute("SELECT table_name FROM lomberk.registered_tables")}
        assert registered == {"orders", "customers", "notes"}

    # The wizard ran doctor on what it wrote, and points the agent's client at it.
    assert "Ready" in r.output
    assert "password" in r.output  # hidden from the agent by the database
    assert "row level security" in r.output.lower() and "public.notes" in r.output
    assert "claude mcp add lomberk" in r.output and str(tmp_path / "lomberk.yaml") in r.output
    assert "\n  [mcp_servers.lomberk]\n" in r.output  # pasteable TOML: no rich escape backslash
    assert env["LOMBERK_AGENT_DSN"] not in r.output  # secrets stay in .env, not in scrollback


def test_setup_lists_tables_and_skips_ones_without_a_key(owner, monkeypatch, tmp_path):
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", owner, "--tables", "public.orders,public.events", "--yes"])
    assert r.exit_code == 0, r.output
    assert "public.events" in r.output and "no primary key" in r.output
    with psycopg.connect(owner) as conn:
        assert {r[0] for r in conn.execute("SELECT table_name FROM lomberk.registered_tables")} == {"orders"}


def test_setup_never_overwrites_or_rotates(owner, monkeypatch, tmp_path):
    assert run_setup(monkeypatch, tmp_path, ["--owner-dsn", owner, "--tables", "public.orders", "--yes"]).exit_code == 0
    before = (tmp_path / ".env").read_text()
    r = run_setup(monkeypatch, tmp_path / "..", ["--owner-dsn", owner, "--tables", "public.orders", "--yes"])
    assert r.exit_code == 1 and "lomberk_control already exists" in r.output
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", owner, "--tables", "public.orders", "--yes"])
    assert r.exit_code == 1 and "Setup never overwrites" in r.output
    assert (tmp_path / ".env").read_text() == before


def test_setup_bad_dsn_is_one_line(monkeypatch, tmp_path):
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", "postgresql://nobody:x@127.0.0.1:1/db", "--yes"])
    assert r.exit_code == 1 and "Traceback" not in r.output and "could not connect" in r.output.lower()
    assert not (tmp_path / ".env").exists()


def test_setup_checks_the_folder_before_touching_the_database(owner, monkeypatch, tmp_path):
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", owner, "--dir", str(tmp_path / "missing"), "--yes"])
    assert r.exit_code == 1 and "is not a directory" in r.output
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", owner, "--dir", str(locked), "--yes"])
    assert r.exit_code == 1 and "can't write to" in r.output
    with psycopg.connect(owner) as conn:  # nothing was created, so a retry starts clean
        assert not conn.execute("SELECT 1 FROM pg_roles WHERE rolname LIKE 'lomberk%'").fetchone()


def test_setup_shows_the_passwords_once_if_env_cant_be_written(owner, monkeypatch, tmp_path):
    from lomberk import setup as wizard

    def fail(*a):
        raise PermissionError(13, "Permission denied")
    monkeypatch.setattr(wizard, "write_files", fail)
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", owner, "--tables", "public.orders", "--yes"])
    assert r.exit_code == 1 and "Traceback" not in r.output and "shown once" in r.output
    dsn = r.output.split("LOMBERK_AGENT_DSN=", 1)[1].splitlines()[0]
    with psycopg.connect(dotenv.dotenv_values(stream=__import__("io").StringIO(f"X={dsn}"))["X"]) as conn:
        assert conn.execute("SELECT current_user").fetchone()[0] == "lomberk_agent"


def test_env_values_survive_quotes_and_spaces(monkeypatch, tmp_path):
    from lomberk import setup as wizard
    for k in ENV_KEYS:  # write_files exports what it wrote; keep that out of the other tests
        monkeypatch.setenv(k, "")
    tricky = "host=db user=lomberk_agent password=a\"b\\c options='-c search_path=x' sslrootcert=/a b/ca.pem"
    wizard.write_files(str(tmp_path / "lomberk.yaml"), str(tmp_path / ".env"), [], tricky, tricky)
    assert dotenv.dotenv_values(tmp_path / ".env")["LOMBERK_AGENT_DSN"] == tricky


def test_client_snippets_quote_the_path(monkeypatch):
    import json
    import shlex

    from lomberk import setup as wizard
    monkeypatch.setattr(wizard, "client_command", lambda: ["uvx", "lomberk", "serve"])
    path = '/Users/me/My "DB" Files/lomberk.yaml'
    out = wizard.client_instructions(path)
    claude = next(line for line in out.splitlines() if "claude mcp add" in line)
    assert shlex.split(claude)[5] == f"LOMBERK_CONFIG={path}"
    cursor = out.splitlines()[out.splitlines().index(next(x for x in out.splitlines() if x.startswith("Cursor"))) + 1]
    assert json.loads(cursor)["mcpServers"]["lomberk"]["env"]["LOMBERK_CONFIG"] == path


def test_setup_shows_the_passwords_once_if_install_fails(owner, monkeypatch, tmp_path):
    import lomberk.cli

    def fail(*a, **kw):
        raise psycopg.errors.InsufficientPrivilege("permission denied for database app")
    monkeypatch.setattr(lomberk.cli, "install_lomberk", fail)
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", owner, "--tables", "public.orders", "--yes"])
    assert r.exit_code == 1 and "install failed" in r.output and "shown once" in r.output
    dsn = r.output.split("LOMBERK_ADMIN_DSN=", 1)[1].splitlines()[0]
    with psycopg.connect(dotenv.dotenv_values(stream=__import__("io").StringIO(f"X={dsn}"))["X"]) as conn:
        assert conn.execute("SELECT current_user").fetchone()[0] == "lomberk_control"


def test_setup_refuses_a_dsn_dotenv_would_expand(monkeypatch, tmp_path):
    r = run_setup(monkeypatch, tmp_path, ["--owner-dsn", "postgresql://o:x@db/app?sslrootcert=${HOME}/ca.pem", "--yes"])
    assert r.exit_code == 1 and "${" in r.output and not (tmp_path / ".env").exists()
