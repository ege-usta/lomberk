"""The CLI's undo window with a license key. Split from test_undo_window.py, which runs without ee/."""
import test_undo_window as base

import lomberk.ee.license as lic
from lomberk.cli import app

db, env = base.db, base.env  # the same database fixtures
age, exists, runner, write = base.age, base.exists, base.runner, base.write


def test_cli_with_a_key_asks_polar_only_for_old_writes(env, monkeypatch):
    calls = []
    monkeypatch.setattr(lic, "validate_key", lambda key, activation_id=None: calls.append(key) or lic.Validation("granted"))
    fresh = write(env, 6)
    assert runner.invoke(app, ["undo", fresh.public_id]).exit_code == 0
    assert calls == []  # everyday undo never calls Polar
    old = write(env, 7)
    age(env, old.public_id, 25)
    res = runner.invoke(app, ["undo", old.public_id])
    assert res.exit_code == 0, res.stdout
    assert calls == ["test-license"] and not exists(env, 7)
