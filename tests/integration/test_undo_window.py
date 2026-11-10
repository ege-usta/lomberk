"""How far back undo reaches: 24 hours free, 30 days Pro, no limit Enterprise."""
import os

import psycopg
import pytest
from testcontainers.community.postgres import PostgresContainer
from typer.testing import CliRunner

from lomberk.api import _UNDO_HTTP_STATUS
from lomberk.capture.install import install_lomberk
from lomberk.cli import app
from lomberk.config import LomberkConfig
from lomberk.executor import UNDO_WINDOW_HOURS, LicenseActivationStore, LomberkExecutor
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
            c.execute("CREATE TABLE public.items (id INT PRIMARY KEY, v TEXT)")
        install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as c:
            c.execute("SELECT lomberk.register_table('public', 'items', 'id', 'mcp_agent')")
        host = url.split("@", 1)[1]
        yield url, f"postgresql://lomberk_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


def write(db, n: int, protected: bool = False):
    _, control, agent = db
    tables = ["public.items"] if protected else []
    ex = LomberkExecutor(control, agent, protected_tables=tables)
    engine = PolicyEngine(LomberkConfig(protected_tables=tables))
    return ex.execute(engine.evaluate(classify_sql(f"INSERT INTO public.items VALUES ({n}, 'x')")[0]))


def age(db, public_id: str, hours: int):
    """Backdates a checkpoint. The ledger is append-only, so this goes around its trigger."""
    with psycopg.connect(db[0], autocommit=True) as c:
        c.execute("SET session_replication_role = replica")
        c.execute("UPDATE lomberk.checkpoints SET created_at = now() - make_interval(hours => %s) WHERE public_id = %s",
                  (hours, public_id))


def exists(db, n: int) -> bool:
    with psycopg.connect(db[0]) as c:
        return c.execute("SELECT count(*) FROM public.items WHERE id = %s", (n,)).fetchone()[0] == 1


def test_plans():
    assert UNDO_WINDOW_HOURS == {"free": 24, "pro": 720, "enterprise": None}
    assert _UNDO_HTTP_STATUS["expired"] == 403


def test_free_window_refuses_an_old_write_and_leaves_it_in_place(db):
    _, control, agent = db
    cp = write(db, 1)
    age(db, cp.public_id, 25)
    res = LomberkExecutor(control, agent, undo_window_hours=24).execute_undo(cp.public_id, "test")
    assert res.status == "expired" and "24 hours undo window" in res.message and "30 days" in res.message
    assert exists(db, 1)
    assert LomberkExecutor(control, agent, undo_window_hours=720).execute_undo(cp.public_id, "test").status == "undone"
    assert not exists(db, 1)


def test_inside_the_window_undo_works(db):
    _, control, agent = db
    cp = write(db, 2)
    age(db, cp.public_id, 23)
    assert LomberkExecutor(control, agent, undo_window_hours=24).execute_undo(cp.public_id, "test").status == "undone"


def test_pro_window_ends_at_30_days_and_enterprise_never(db):
    _, control, agent = db
    cp = write(db, 3)
    age(db, cp.public_id, 31 * 24)
    res = LomberkExecutor(control, agent, undo_window_hours=720).execute_undo(cp.public_id, "test")
    assert res.status == "expired" and "30 days undo window" in res.message
    assert LomberkExecutor(control, agent, undo_window_hours=None).execute_undo(cp.public_id, "test").status == "undone"


def test_a_held_write_counts_from_its_approval(db):
    _, control, agent = db
    held = write(db, 4, protected=True)
    assert held.status == "approval_required"
    age(db, held.public_id, 48)  # held for two days, approved just now
    ex = LomberkExecutor(control, agent, protected_tables=["public.items"], undo_window_hours=24)
    assert ex.execute_pending(held.public_id, actor="cli:ops").status == "applied"
    assert ex.execute_undo(held.public_id, "test").status == "undone"


def test_unknown_checkpoint_is_still_not_found(db):
    _, control, agent = db
    assert LomberkExecutor(control, agent, undo_window_hours=24).execute_undo("cp_nope", "test").status == "denied"


@pytest.fixture
def env(db, monkeypatch, tmp_path):
    _, control, agent = db
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("LOMBERK_ADMIN_DSN", control)
    monkeypatch.setenv("LOMBERK_AGENT_DSN", agent)
    return db


def test_cli_without_a_key_stays_on_the_free_window(env, monkeypatch):
    monkeypatch.delenv("LOMBERK_LICENSE_KEY", raising=False)
    cp = write(env, 5)
    age(env, cp.public_id, 25)
    res = runner.invoke(app, ["undo", cp.public_id])
    assert res.exit_code == 1 and "undo window" in res.stdout
    assert exists(env, 5)


def test_activation_row_is_the_control_roles_alone(db):
    url, control, agent = db
    store = LicenseActivationStore(control)
    label, activation = store.load()
    assert label.startswith("lomberk-") and activation is None
    store.save("act-1")
    assert store.load() == (label, "act-1")
    install_lomberk(url, control_role="lomberk_control", agent_role="mcp_agent")  # upgrade keeps it
    assert store.load() == (label, "act-1")
    with psycopg.connect(control) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("UPDATE lomberk.license_activation SET label = 'other'")
    with psycopg.connect(agent) as c, pytest.raises(psycopg.errors.InsufficientPrivilege):
        c.execute("SELECT * FROM lomberk.license_activation")
    with psycopg.connect(url) as c, pytest.raises(psycopg.errors.IntegrityError):
        c.execute("INSERT INTO lomberk.license_activation (only_row) VALUES (false)")
