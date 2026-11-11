"""The stdio MCP server refuses the same unsafe setups as the HTTP gateway."""
import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer

from lomberk import server
from lomberk.capture.install import install_lomberk


@pytest.fixture(scope="module")
def pg():
    with PostgresContainer(os.environ.get("LOMBERK_TEST_PG_IMAGE", "postgres:16-alpine")) as c:
        url = c.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE lomberk_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        host = url.split("@", 1)[1]
        yield url, f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


@pytest.fixture
def env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no lomberk.yaml: defaults
    monkeypatch.delenv("LOMBERK_LICENSE_KEY", raising=False)
    monkeypatch.delenv("LOMBERK_SLACK_ENABLED", raising=False)

    def set_dsns(agent, admin):
        monkeypatch.setenv("LOMBERK_AGENT_DSN", agent)
        monkeypatch.setenv("LOMBERK_ADMIN_DSN", admin)
    return set_dsns


@pytest.mark.parametrize("which", ["superuser_agent", "superuser_admin", "same_role"])
def test_unsafe_dsns_are_refused(pg, env, which):
    su, control, agent = pg
    env(*{"superuser_agent": (su, control), "superuser_admin": (agent, su), "same_role": (agent, agent)}[which])
    with pytest.raises(ValueError, match="Startup Refusal"):
        server.build_executor()


def test_free_plan_gets_the_free_undo_window(pg, env):
    from lomberk.executor import UNDO_WINDOW_HOURS
    _, control, agent = pg
    env(agent, control)
    executor, _ = server.build_executor()
    assert executor.undo_window_hours == UNDO_WINDOW_HOURS["free"]


def test_two_person_rule_without_license_is_refused(pg, env, tmp_path):
    _, control, agent = pg
    env(agent, control)
    (tmp_path / "lomberk.yaml").write_text("approvals:\n  required: 2\nsso:\n  issuer: https://idp.example\n")
    with pytest.raises(Exception, match="(?i)license"):
        server.build_executor()


def test_main_exits_cleanly_on_refusal(pg, env, capsys):
    su, control, _ = pg
    env(su, control)
    with pytest.raises(SystemExit) as e:
        server.main()
    assert e.value.code == 1 and "Startup Refusal" in capsys.readouterr().err


@pytest.mark.parametrize("state", ["not_installed", "older_schema"])
def test_a_schema_older_than_the_gateway_is_refused(pg, env, state):
    """New code against an old schema would break every hold; refuse at startup and say how to upgrade."""
    su, control, agent = pg
    db = f"stale_{state}"
    with psycopg.connect(su, autocommit=True) as conn:
        conn.execute(f"CREATE DATABASE {db}")
    stale = su.rsplit("/", 1)[0] + f"/{db}"
    if state == "older_schema":
        install_lomberk(stale, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(stale, autocommit=True) as conn:
            conn.execute("ALTER TABLE lomberk.checkpoints DROP COLUMN required_approvals CASCADE")
    host_db = lambda dsn: dsn.rsplit("/", 1)[0] + f"/{db}"
    env(host_db(agent), host_db(control))
    with pytest.raises(ValueError, match=r"Startup Refusal: .*lomberk init"):
        server.build_executor()
