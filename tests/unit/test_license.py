import http.server
import json
import threading

import pytest

import rowback.ee.license as lic

validate_key = lic.validate_key  # the real one; conftest stubs the module attribute for other tests


@pytest.fixture
def polar(monkeypatch):
    """A fake Polar validate endpoint. Set .reply = (status_code, body)."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            fake.requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            code, body = fake.reply
            self.send_response(code)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *a):
            pass

    class Fake:
        reply, requests = (200, '{"status": "granted"}'), []

    fake = Fake()
    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(lic, "POLAR_VALIDATE_URL", f"http://127.0.0.1:{srv.server_port}/validate")
    yield fake
    srv.shutdown()


@pytest.mark.parametrize("reply, expected", [
    ((200, '{"status": "granted"}'), "granted"),
    ((404, '{"detail": "not found"}'), "invalid"),   # unknown, revoked or expired key
    ((422, '{"detail": []}'), "invalid"),
    ((500, "oops"), "unreachable"),
    ((429, "slow down"), "unreachable"),
    ((200, "not json"), "unreachable"),
])
def test_validate_key_maps_polar_replies(polar, reply, expected):
    polar.reply = reply
    assert validate_key("KEY-1") == expected
    assert polar.requests[-1] == {"key": "KEY-1", "organization_id": lic.POLAR_ORGANIZATION_ID}


def test_validate_key_when_polar_is_down(monkeypatch):
    monkeypatch.setattr(lic, "POLAR_VALIDATE_URL", "http://127.0.0.1:9/validate")  # nothing listens
    assert validate_key("KEY-1") == "unreachable"


@pytest.mark.parametrize("result, features, expected", [
    ("granted", ["sso"], True),
    ("unreachable", ["sso"], True),   # our vendor's outage must not take the gateway down
    ("invalid", [], False),
    ("granted", [], True),
])
def test_check_license(monkeypatch, result, features, expected):
    monkeypatch.setattr(lic, "validate_key", lambda key: result)
    assert lic.check_license("KEY-1", features) is expected


def test_invalid_key_with_pro_features_refuses_startup(monkeypatch):
    monkeypatch.setattr(lic, "validate_key", lambda key: "invalid")
    with pytest.raises(lic.LicenseError, match="invalid, expired or cancelled"):
        lic.check_license("KEY-1", ["two-person approval"])


def test_missing_key(monkeypatch):
    monkeypatch.setattr(lic, "validate_key", lambda key: pytest.fail("must not call Polar without a key"))
    assert lic.check_license(None, []) is False
    with pytest.raises(lic.LicenseError, match="SSO, Slack approvals need a Rowback Pro license"):
        lic.check_license("", ["SSO", "Slack approvals"])
