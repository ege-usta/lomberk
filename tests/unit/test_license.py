import http.server
import json
import threading

import pytest

import lomberk.ee.license as lic

validate_key = lic.validate_key  # the real one; conftest stubs the module attribute for other tests
PRO = next(iter(lic.PRO_BENEFIT_IDS))
GRANTED = f'{{"status": "granted", "benefit_id": "{PRO}"}}'
LIMITED_BODY = f'{{"status": "granted", "benefit_id": "{PRO}", "limit_activations": 3}}'


@pytest.fixture
def polar(monkeypatch):
    """A fake Polar. Set .reply = (status_code, body) for validate, .activate = (status_code, body)."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            fake.requests.append((self.path, req))
            code, body = fake.activate if self.path == "/activate" else fake.reply
            if self.path == "/validate" and req.get("activation_id") and req["activation_id"] not in fake.activations:
                code, body = 404, '{"detail": "not found"}'
            self.send_response(code)
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *a):
            pass

    class Fake:
        reply, activate, requests, activations = (200, GRANTED), (201, '{"id": "act-9"}'), [], {"act-1"}

    fake = Fake()
    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(lic, "POLAR_VALIDATE_URL", f"http://127.0.0.1:{srv.server_port}/validate")
    monkeypatch.setattr(lic, "POLAR_ACTIVATE_URL", f"http://127.0.0.1:{srv.server_port}/activate")
    monkeypatch.setattr(lic, "validate_key", validate_key)  # check_license talks to the fake, not the stub
    yield fake
    srv.shutdown()


class Store:
    def __init__(self, activation_id=None):
        self.label, self.activation_id = "lomberk-test-db", activation_id

    def load(self):
        return self.label, self.activation_id

    def save(self, activation_id):
        self.activation_id = activation_id


@pytest.mark.parametrize("reply, expected", [
    ((200, GRANTED), "granted"),
    ((200, '{"status": "granted"}'), "invalid"),  # no benefit: not a Lomberk key
    ((200, '{"status": "revoked"}'), "invalid"),
    ((404, '{"detail": "not found"}'), "invalid"),   # unknown, revoked or expired key
    ((422, '{"detail": []}'), "invalid"),
    ((500, "oops"), "unreachable"),
    ((429, "slow down"), "unreachable"),
    ((200, "not json"), "unreachable"),
])
def test_validate_key_maps_polar_replies(polar, reply, expected):
    polar.reply = reply
    assert validate_key("KEY-1").status == expected
    assert polar.requests[-1] == ("/validate", {"key": "KEY-1", "organization_id": lic.POLAR_ORGANIZATION_ID})


def test_validate_key_when_polar_is_down(monkeypatch):
    monkeypatch.setattr(lic, "POLAR_VALIDATE_URL", "http://127.0.0.1:9/validate")  # nothing listens
    assert validate_key("KEY-1").status == "unreachable"


def test_a_key_for_another_product_of_the_organization_is_invalid(polar):
    polar.reply = (200, '{"status": "granted", "benefit_id": "ben-other-product"}')
    assert validate_key("KEY-1") == lic.Validation("invalid")
    with pytest.raises(lic.LicenseError, match="invalid, expired or cancelled"):
        lic.check_license("KEY-1", ["SSO"])


def test_enterprise_is_the_benefit_not_the_customer_claim(polar, monkeypatch):
    polar.reply = (200, GRANTED)
    assert validate_key("KEY-1") == lic.Validation("granted")
    polar.reply = (200, '{"status": "granted", "benefit_id": "ben-ent"}')
    assert validate_key("KEY-1").status == "invalid"  # no Enterprise ids configured
    monkeypatch.setattr(lic, "ENTERPRISE_BENEFIT_IDS", frozenset({"ben-ent"}))
    assert validate_key("KEY-1").enterprise
    assert lic.check_license("KEY-1", []) == "enterprise"


@pytest.mark.parametrize("result, features, expected", [
    ("granted", ["sso"], "pro"),
    ("unreachable", ["sso"], "pro"),   # our vendor's outage must not take the gateway down
    ("invalid", [], "free"),
    ("granted", [], "pro"),
])
def test_check_license(monkeypatch, result, features, expected):
    monkeypatch.setattr(lic, "validate_key", lambda key, activation_id=None: lic.Validation(result))
    assert lic.check_license("KEY-1", features) == expected


def test_invalid_key_with_pro_features_refuses_startup(monkeypatch):
    monkeypatch.setattr(lic, "validate_key", lambda key, activation_id=None: lic.Validation("invalid"))
    with pytest.raises(lic.LicenseError, match="invalid, expired or cancelled"):
        lic.check_license("KEY-1", ["two-person approval"])


def test_missing_key(monkeypatch):
    monkeypatch.setattr(lic, "validate_key", lambda key, activation_id=None: pytest.fail("must not call Polar without a key"))
    assert lic.check_license(None, []) == "free"
    with pytest.raises(lic.LicenseError, match="SSO, Slack approvals need a Lomberk Pro license"):
        lic.check_license("", ["SSO", "Slack approvals"])


LIMITED = (200, LIMITED_BODY)


def test_first_start_on_a_database_activates_it_once(polar):
    polar.reply, store = LIMITED, Store()
    assert lic.check_license("KEY-1", [], store) == "pro"
    assert store.activation_id == "act-9"
    assert polar.requests[-1] == ("/activate", {"key": "KEY-1", "organization_id": lic.POLAR_ORGANIZATION_ID,
                                                "label": "lomberk-test-db"})
    polar.activations.add("act-9")
    polar.requests.clear()
    assert lic.check_license("KEY-1", [], store) == "pro"  # a restart reuses the activation
    assert [path for path, _ in polar.requests] == ["/validate"]
    assert polar.requests[0][1]["activation_id"] == "act-9"


def test_a_fourth_database_is_refused(polar):
    polar.reply, polar.activate = LIMITED, (403, '{"detail": "License key activation limit reached"}')
    with pytest.raises(lic.LicenseError, match="already in use on as many databases"):
        lic.check_license("KEY-1", ["SSO"], Store())
    store = Store()
    assert lic.check_license("KEY-1", [], store) == "free"  # no paid feature configured: runs as free
    assert store.activation_id is None


def test_an_activation_removed_in_the_portal_is_replaced(polar):
    polar.reply, store = LIMITED, Store("act-gone")
    assert lic.check_license("KEY-1", [], store) == "pro"
    assert store.activation_id == "act-9"


def test_a_kept_activation_is_not_counted_again(polar):
    polar.reply, store = LIMITED, Store("act-1")
    assert lic.check_license("KEY-1", [], store) == "pro"
    assert "/activate" not in [path for path, _ in polar.requests]


def test_unlimited_keys_never_activate(polar):
    store = Store()
    assert lic.check_license("KEY-1", [], store) == "pro"
    assert store.activation_id is None and [p for p, _ in polar.requests] == ["/validate"]


def test_activation_outage_keeps_the_plan(polar, monkeypatch):
    polar.reply, store = LIMITED, Store()
    monkeypatch.setattr(lic, "POLAR_ACTIVATE_URL", "http://127.0.0.1:9/activate")
    assert lic.check_license("KEY-1", ["SSO"], store) == "pro"
    assert store.activation_id is None  # tried again at the next start
