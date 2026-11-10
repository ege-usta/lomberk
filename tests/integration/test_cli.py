"""The operator's CLI end to end on a real database: install, register, review, decide, verify."""
import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer
from typer.testing import CliRunner

from lomberk.cli import app
from lomberk.config import LomberkConfig
from lomberk.executor import LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.sql.classify import classify_sql

runner = CliRunner()


@pytest.fixture(scope="module")
def db():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            c.execute("CREATE TABLE public.accounts (org INT, id INT, email TEXT, api_token TEXT, PRIMARY KEY (org, id))")
            c.execute("CREATE TABLE public.sessions (id INT PRIMARY KEY, account_org INT, account_id INT, "
                      "FOREIGN KEY (account_org, account_id) REFERENCES public.accounts ON DELETE CASCADE)")
            c.execute("CREATE TABLE public.metrics (day DATE, v INT, PRIMARY KEY (day)) PARTITION BY RANGE (day)")
            c.execute("CREATE TABLE public.metrics_2026 PARTITION OF public.metrics FOR VALUES FROM ('2026-01-01') TO ('2027-01-01')")
            c.execute("CREATE TABLE public.nokey (v INT)")
            c.execute("INSERT INTO public.accounts VALUES (1, 1, 'a@x.io', 'tok'), (1, 2, 'b@x.io', 'tok2')")
        host = url.split("@", 1)[1]
        yield url, f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


@pytest.fixture
def env(db, monkeypatch, tmp_path):
    url, control, agent = db
    monkeypatch.chdir(tmp_path)  # default config, no stray lomberk.yaml
    monkeypatch.setenv("LOMBERK_INSTALL_DSN", url)
    monkeypatch.setenv("LOMBERK_ADMIN_DSN", control)
    monkeypatch.setenv("LOMBERK_AGENT_DSN", agent)
    return db


def cli(*args):
    return runner.invoke(app, list(args))


def test_01_init_installs_once_and_again(env):
    for _ in range(2):  # re-running is an upgrade, not an error
        res = cli("init", "--control-role", "lomberk_control", "--agent-role", "mcp_agent")
        assert res.exit_code == 0 and "installed successfully" in res.stdout


def test_02_register_reads_the_key_and_hides_secret_columns(env):
    res = cli("register", "public.accounts", "--agent-role", "mcp_agent")
    assert res.exit_code == 0, res.stdout
    assert "public.accounts is now protected" in res.stdout and "Hidden from the agent by the database itself: api_token" in res.stdout
    assert "cascade into public.sessions" in res.stdout  # deletes cascade into a table not registered yet
    assert cli("register", "public.sessions", "--agent-role", "mcp_agent").exit_code == 0
    assert cli("register", "public.metrics", "--agent-role", "mcp_agent").exit_code == 0


@pytest.mark.parametrize("args, message", [
    (["public.accounts", "--pk", "id"], "is (org,id), not (id)"),
    (["public.nokey"], "has no primary key"),
    (["public.metrics_2026"], "register its partitioned table public.metrics instead"),
    (["accounts"], "must be schema-qualified"),
])
def test_03_register_refuses_with_a_reason(env, args, message):
    res = cli("register", *args, "--agent-role", "mcp_agent")
    assert res.exit_code == 1 and message in " ".join(res.stdout.split())


def test_04_show_approve_reject_a_held_write_with_its_preview(env):
    _, control, agent = env
    ex = LomberkExecutor(control, agent, protected_tables=["public.accounts"], preview_writes=True)
    engine = PolicyEngine(LomberkConfig(protected_tables=["public.accounts"]))
    held = ex.execute(engine.evaluate(classify_sql("UPDATE public.accounts SET email = 'new@x.io' WHERE org = 1 AND id = 1")[0]))
    assert held.status == "approval_required"

    res = cli("show", held.public_id)
    assert res.exit_code == 0
    assert "UPDATE public.accounts SET email = 'new@x.io'" in res.stdout
    assert "would change: 1 row(s) in public.accounts (1)" in res.stdout
    assert '{"email": ["a@x.io", "new@x.io"]}' in res.stdout

    res = cli("approve", held.public_id)
    assert res.exit_code == 0 and "Rows affected: 1" in res.stdout and f"lomberk undo {held.public_id}" in res.stdout
    assert cli("approve", held.public_id).exit_code == 1  # not pending any more

    other = ex.execute(engine.evaluate(classify_sql("DELETE FROM public.accounts WHERE org = 1 AND id = 2")[0]))
    assert cli("reject", other.public_id).exit_code == 0
    res = cli("reject", other.public_id)
    assert res.exit_code == 1 and "not pending" in res.stdout


def test_05_show_unknown_checkpoint(env):
    res = cli("show", "cp_nope")
    assert res.exit_code == 1 and "not found" in res.stdout


def test_06_verify_ledger_reports_an_intact_chain(env):
    res = cli("verify-ledger")
    assert res.exit_code == 0 and "Ledger intact" in res.stdout and "Head hash" in res.stdout


def test_07_preview_classifies_without_a_database(env, monkeypatch):
    monkeypatch.delenv("LOMBERK_ADMIN_DSN")
    res = cli("preview", "DELETE FROM public.accounts")
    assert res.exit_code == 0 and "WRITE_DML" in res.stdout


def test_08_commands_say_which_dsn_is_missing(env, monkeypatch):
    monkeypatch.delenv("LOMBERK_AGENT_DSN")
    res = cli("undo", "cp_x")
    assert res.exit_code == 1 and "LOMBERK_AGENT_DSN" in res.stdout
    monkeypatch.delenv("LOMBERK_INSTALL_DSN")
    res = cli("register", "public.accounts", "--agent-role", "mcp_agent")
    assert res.exit_code == 1 and "LOMBERK_INSTALL_DSN" in res.stdout
