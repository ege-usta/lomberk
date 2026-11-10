"""A guessable gateway key is refused at startup, so brute-forcing the admin key is not feasible."""
import pytest
from fastapi.testclient import TestClient

from lomberk.config import weak_key_reason

STRONG = "3f9c2a7e1b8d4065c7a9e2f1d3b5a8c6"


@pytest.mark.parametrize("key", ["demo-admin-key", "short-key", "a" * 40, "abababababababababababababababab"])
def test_weak_keys(key):
    assert weak_key_reason(key)


def test_random_key_is_fine():
    assert weak_key_reason(STRONG) is None


def test_gateway_refuses_to_start_with_a_weak_admin_key(monkeypatch, tmp_path):
    from lomberk.api import app
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LOMBERK_ALLOW_WEAK_KEYS", raising=False)
    for k, v in {"LOMBERK_AGENT_DSN": "postgresql://unused", "LOMBERK_ADMIN_DSN": "postgresql://unused",
                 "LOMBERK_API_KEY": STRONG, "LOMBERK_ADMIN_KEY": "demo-admin-key"}.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValueError, match="LOMBERK_ADMIN_KEY is a public demo key"), TestClient(app):
        pass


@pytest.mark.parametrize("metrics_key, error", [
    ("demo-admin-key", "LOMBERK_METRICS_KEY is a public demo key"),
    ("7a1c9e3f5b2d8064a1c3e5f7b9d2a4c6", "must differ from the agent and admin keys"),
])
def test_gateway_refuses_a_weak_or_reused_metrics_key(monkeypatch, tmp_path, metrics_key, error):
    from lomberk.api import app
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LOMBERK_ALLOW_WEAK_KEYS", raising=False)
    admin = "7a1c9e3f5b2d8064a1c3e5f7b9d2a4c6"
    for k, v in {"LOMBERK_AGENT_DSN": "postgresql://unused", "LOMBERK_ADMIN_DSN": "postgresql://unused",
                 "LOMBERK_API_KEY": STRONG, "LOMBERK_ADMIN_KEY": admin, "LOMBERK_METRICS_KEY": metrics_key}.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValueError, match=error), TestClient(app):
        pass
