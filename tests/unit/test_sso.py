"""SSO approvers (ee): only an ID token signed by the configured IdP, for this
audience, unexpired, from an approver group, may approve, and the audit actor is
the person. Every forgery below must be refused."""
import base64
import hashlib
import hmac
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from lomberk import api
from lomberk.config import SsoConfig
from lomberk.ee.sso import OidcVerifier, SsoError

AUD = "lomberk-approvals"


def _rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


IDP_KEY, ATTACKER_KEY = _rsa(), _rsa()


@pytest.fixture(scope="module")
def idp():
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(IDP_KEY.public_key()))
    jwk.update(kid="k1", use="sig", alg="RS256")
    hits = {"jwks": 0}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/.well-known/openid-configuration":
                body = {"issuer": issuer, "jwks_uri": issuer + "/jwks"}
            else:
                hits["jwks"] += 1
                body = {"keys": [jwk]}
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    issuer = f"http://127.0.0.1:{srv.server_port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield issuer, hits
    srv.shutdown()


def token(issuer, key=IDP_KEY, kid="k1", alg="RS256", **over):
    now = int(time.time())
    claims = {"iss": issuer, "aud": AUD, "sub": "u1", "email": "alice@corp.com", "email_verified": True,
              "groups": ["db-approvers"], "iat": now, "exp": now + 300}
    claims.update(over)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def verifier(issuer, **cfg):
    return OidcVerifier(SsoConfig(issuer=issuer, audience=AUD, allowed_groups=["db-approvers"], **cfg))


def test_valid_token_names_the_person(idp):
    issuer, _ = idp
    assert verifier(issuer).verify(token(issuer)) == "oidc:alice@corp.com"


@pytest.mark.parametrize("forge", [
    lambda iss: token(iss, key=ATTACKER_KEY),                       # signed by someone else
    lambda iss: token("https://evil.example"),                      # another issuer
    lambda iss: token(iss, aud="some-other-app"),                   # token minted for another app
    lambda iss: token(iss, exp=int(time.time()) - 3600),            # expired
    lambda iss: token(iss, exp=None),                               # never expires
    lambda iss: token(iss, groups=["engineering"]),                 # not an approver
    lambda iss: token(iss, groups="db-approvers"),                  # malformed groups claim
    lambda iss: token(iss, email_verified=False),                   # unverified email
    lambda iss: token(iss, email_verified=None),                    # IdP never says it's verified
    lambda iss: token(iss, groups=None),                            # no groups, not listed by name
    lambda iss: token(iss, email=None),                             # no identity
    lambda iss: token(iss, kid="unknown"),                          # unknown key
    lambda iss: jwt.encode({"iss": iss, "aud": AUD, "sub": "u", "email": "a@b", "groups": ["db-approvers"],
                            "iat": int(time.time()), "exp": int(time.time()) + 60}, None, algorithm="none",
                           headers={"kid": "k1"}),                  # unsigned
    lambda iss: "not-a-jwt",
])
def test_forged_tokens_are_refused(idp, forge):
    issuer, _ = idp
    with pytest.raises(SsoError):
        verifier(issuer).verify(forge(issuer))


def test_hs256_key_confusion_is_refused(idp):
    """Classic attack: sign with HMAC using the IdP's *public* key as the secret."""
    issuer, _ = idp
    pub = IDP_KEY.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    now = int(time.time())

    def b64(obj):
        return base64.urlsafe_b64encode(obj).rstrip(b"=")
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode())
    body = b64(json.dumps({"iss": issuer, "aud": AUD, "sub": "u", "email": "a@b", "groups": ["db-approvers"],
                           "iat": now, "exp": now + 60}).encode())
    forged = (head + b"." + body + b"." + b64(hmac.new(pub, head + b"." + body, hashlib.sha256).digest())).decode()
    with pytest.raises(SsoError):
        verifier(issuer).verify(forged)


def test_unknown_kid_flood_does_not_hammer_the_idp(idp):
    issuer, hits = idp
    v = verifier(issuer)
    before = hits["jwks"]
    for i in range(50):
        with pytest.raises(SsoError):
            v.verify(token(issuer, kid=f"bogus-{i}"))
    assert hits["jwks"] == before


def test_named_identity_without_group(idp):
    issuer, _ = idp
    v = OidcVerifier(SsoConfig(issuer=issuer, audience=AUD, allowed_identities=["alice@corp.com"]))
    assert v.verify(token(issuer, groups=None)) == "oidc:alice@corp.com"
    with pytest.raises(SsoError):
        v.verify(token(issuer, email="mallory@corp.com", groups=None))


def test_open_door_config_refused(idp):
    """Google signs ID tokens for any Google account: no allowlist must not mean everyone."""
    issuer, _ = idp
    with pytest.raises(ValueError, match="allowed_groups"):
        OidcVerifier(SsoConfig(issuer=issuer, audience=AUD))


def test_plain_http_issuer_refused():
    with pytest.raises(ValueError, match="https"):
        OidcVerifier(SsoConfig(issuer="http://idp.corp.com", audience=AUD, allowed_groups=["g"]))


class FakeExecutor:
    def __init__(self):
        self.calls = []

    def reject(self, public_id, actor):
        self.calls.append(actor)
        return True


@pytest.fixture
def client(idp, monkeypatch):
    issuer, _ = idp
    ex = FakeExecutor()
    monkeypatch.setattr(api, "_SSO", verifier(issuer))
    monkeypatch.setattr(api, "_ADMIN_KEY", "k-admin")
    monkeypatch.setattr(api, "_ALLOW_ADMIN_KEY", True)
    api.app.dependency_overrides[api.get_executor] = lambda: ex
    yield TestClient(api.app), ex, issuer
    api.app.dependency_overrides.clear()


def test_api_audits_the_sso_person(client):
    c, ex, issuer = client
    r = c.post("/v1/checkpoints/cp_1/reject", headers={"Authorization": f"Bearer {token(issuer)}"})
    assert r.status_code == 200, r.text
    assert ex.calls == ["oidc:alice@corp.com"]


def test_api_bad_sso_token_is_401_even_with_admin_key(client):
    c, ex, issuer = client
    r = c.post("/v1/checkpoints/cp_1/reject",
               headers={"Authorization": f"Bearer {token(issuer, key=ATTACKER_KEY)}", "X-API-Key": "k-admin"})
    assert r.status_code == 401 and ex.calls == []


def test_admin_key_can_be_switched_off(client, monkeypatch):
    c, ex, _ = client
    assert c.post("/v1/checkpoints/cp_1/reject", headers={"X-API-Key": "k-admin"}).status_code == 200
    monkeypatch.setattr(api, "_ALLOW_ADMIN_KEY", False)
    assert c.post("/v1/checkpoints/cp_1/reject", headers={"X-API-Key": "k-admin"}).status_code == 401
    assert ex.calls == ["api_admin"]
