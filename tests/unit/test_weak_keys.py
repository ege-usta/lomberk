"""A guessable gateway key is refused at startup, so brute-forcing the admin key is not feasible."""
import pytest
from fastapi.testclient import TestClient

from rowback.config import weak_key_reason

STRONG = "3f9c2a7e1b8d4065c7a9e2f1d3b5a8c6"


@pytest.mark.parametrize("key", ["demo-admin-key", "short-key", "a" * 40, "abababababababababababababababab"])
def test_weak_keys(key):
    assert weak_key_reason(key)


def test_random_key_is_fine():
    assert weak_key_reason(STRONG) is None


def test_gateway_refuses_to_start_with_a_weak_admin_key(monkeypatch, tmp_path):
    from rowback.api import app
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ROWBACK_ALLOW_WEAK_KEYS", raising=False)
    for k, v in {"ROWBACK_AGENT_DSN": "postgresql://unused", "ROWBACK_ADMIN_DSN": "postgresql://unused",
                 "ROWBACK_API_KEY": STRONG, "ROWBACK_ADMIN_KEY": "demo-admin-key"}.items():
        monkeypatch.setenv(k, v)
    with pytest.raises(ValueError, match="ROWBACK_ADMIN_KEY is a public demo key"), TestClient(app):
        pass
