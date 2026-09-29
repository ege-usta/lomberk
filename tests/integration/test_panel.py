"""Web panel (Pro): sign-in, session, CSRF, SSO login flow, approvals and export."""
import base64
import hashlib
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import jwt
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from testcontainers.community.postgres import PostgresContainer

import rowback.ee.license as lic
from rowback.api import app
from rowback.capture.install import install_rowback
from rowback.executor import RowbackExecutor

IDP_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CLIENT_ID = "rowback-panel"
H = {"X-Rowback-Panel": "1"}


@pytest.fixture(scope="module")
def idp():
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(IDP_KEY.public_key()))
    jwk.update(kid="k1", use="sig", alg="RS256")
    state = {"challenge": None, "nonce": None, "email": "alice@corp.com", "form": None}

    class Handler(BaseHTTPRequestHandler):
        def _json(self, body, code=200):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/.well-known/openid-configuration":
                self._json({"issuer": issuer, "jwks_uri": issuer + "/jwks",
                            "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token"})
            else:
                self._json({"keys": [jwk]})

        def do_POST(self):  # token endpoint
            form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
            state["form"] = form
            pkce_ok = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=").decode() == state["challenge"]
            if form.get("code") != "good-code" or not pkce_ok:
                return self._json({"error": "invalid_grant"}, 400)
            now = int(time.time())
            tok = jwt.encode({"iss": issuer, "aud": CLIENT_ID, "sub": "u1", "email": state["email"], "email_verified": True,
                              "groups": ["db-approvers"], "iat": now, "exp": now + 300, "nonce": state["nonce"]},
                             IDP_KEY, algorithm="RS256", headers={"kid": "k1"})
            self._json({"id_token": tok, "access_token": "x", "token_type": "Bearer"})

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    issuer = f"http://127.0.0.1:{srv.server_port}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield issuer, state
    srv.shutdown()


@pytest.fixture(scope="module")
def db():
    with PostgresContainer("postgres:16-alpine") as pg:
        url = pg.get_connection_url().replace("postgresql+psycopg2://", "postgresql://")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE ROLE rowback_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            conn.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
        install_rowback(url, control_role="rowback_control", agent_role="mcp_agent")
        with psycopg.connect(url, autocommit=True) as conn:
            conn.execute("CREATE TABLE public.acct (id INT PRIMARY KEY, val INT)")
            conn.execute("INSERT INTO public.acct VALUES (1, 0)")
            conn.execute("SELECT rowback.register_table('public', 'acct', 'id', 'mcp_agent')")
        host = url.split("@", 1)[1]
        yield url, f"postgresql://rowback_control:secret@{host}", f"postgresql://mcp_agent:secret@{host}"


@pytest.fixture
def gateway(db, idp, monkeypatch, tmp_path):
    """Starts the gateway with a rowback.yaml; yields (make_client, control_dsn)."""
    _, control, runtime = db
    issuer, _ = idp
    for k, v in {"ROWBACK_AGENT_DSN": runtime, "ROWBACK_ADMIN_DSN": control,
                 "ROWBACK_API_KEY": "agent-k", "ROWBACK_ADMIN_KEY": "admin-k"}.items():
        monkeypatch.setenv(k, v)
    monkeypatch.chdir(tmp_path)

    def start(yaml: str):
        (tmp_path / "rowback.yaml").write_text(yaml.replace("ISSUER", issuer))
        return TestClient(app, base_url="https://testserver")
    return start, control


SSO_YAML = f"""approvals:
  required: 2
sso:
  issuer: ISSUER
  audience: {CLIENT_ID}
  allowed_groups: [db-approvers]
  allow_admin_key: true
  panel_url: http://localhost:8000
"""


def pending(control, sql="UPDATE public.acct SET val = val + 1 WHERE id = 1"):
    return RowbackExecutor(control, "unused").create_pending_checkpoint(sql, "DML_WRITE", "REQUIRE_APPROVAL", "agent")


def admin_login(c):
    r = c.post("/panel/login", json={"key": "admin-k"}, headers=H)
    assert r.status_code == 200, r.text


def test_panel_needs_a_license(gateway, monkeypatch):
    start, _ = gateway
    monkeypatch.setattr(lic, "validate_key", lambda key: "invalid")
    with start("") as c:
        assert c.get("/panel/").status_code == 403
        assert "Pro feature" in c.get("/panel/api/session").text
        assert c.get("/v1/audit/export", headers={"X-API-Key": "admin-k"}).status_code == 403


def test_admin_key_sign_in_session_and_csrf(gateway):
    start, control = gateway
    with start("approvals:\n  required: 2\n") as c:
        page = c.get("/panel/")
        assert page.status_code == 200 and "script-src 'self'" in page.headers["content-security-policy"]
        assert c.get("/panel/api/session").json()["actor"] is None
        assert c.get("/panel/api/checkpoints").status_code == 401

        assert c.post("/panel/login", json={"key": "admin-k"}).status_code == 403          # no CSRF header
        assert c.post("/panel/login", json={"key": "wrong"}, headers=H).status_code == 401
        admin_login(c)
        cookie = c.cookies.get("rowback_session")
        assert c.get("/panel/api/session").json()["actor"] == "api_admin"

        pid = pending(control)
        assert c.post(f"/panel/api/checkpoints/{pid}/approve").status_code == 403           # no CSRF header
        r = c.post(f"/panel/api/checkpoints/{pid}/approve", headers=H)
        assert r.json()["status"] == "awaiting_approval"
        items = {i["public_id"]: i for i in c.get("/panel/api/checkpoints").json()["items"]}
        assert items[pid]["approved_by"] == ["api_admin"] and items[pid]["status"] == "pending"

        payload, sig = cookie.split(".")
        forged = base64.urlsafe_b64encode(json.dumps({"actor": "oidc:boss@corp.com", "p": "session",
                                                      "exp": 9999999999}).encode()).rstrip(b"=").decode()
        c.cookies.clear()
        send = lambda value: c.get("/panel/api/checkpoints", headers={"Cookie": f"rowback_session={value}"})
        assert send(cookie).status_code == 200                      # the real cookie works when sent this way
        assert send(forged + "." + sig).status_code == 401          # another actor under the old signature
        assert send(payload + "." + sig[:-2] + "AA").status_code == 401


def test_sso_sign_in_then_two_people_apply(gateway, idp):
    start, control = gateway
    _, fake = idp
    with start(SSO_YAML) as c:
        assert c.get("/panel/api/session").json()["sso"] is True
        r = c.get("/panel/sso/login", follow_redirects=False)
        assert r.status_code == 303
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(r.headers["location"]).query))
        assert q["client_id"] == CLIENT_ID and q["code_challenge_method"] == "S256"
        assert q["redirect_uri"] == "http://localhost:8000/panel/sso/callback"
        fake["challenge"], fake["nonce"] = q["code_challenge"], q["nonce"]

        assert c.get("/panel/sso/callback", params={"code": "good-code", "state": "forged"},
                     follow_redirects=False).status_code == 400
        r = c.get("/panel/sso/callback", params={"code": "good-code", "state": q["state"]}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/panel/"
        assert c.get("/panel/api/session").json()["actor"] == "oidc:alice@corp.com"

        pid = pending(control)
        assert c.post(f"/panel/api/checkpoints/{pid}/approve", headers=H).json()["status"] == "awaiting_approval"
        admin_login(c)  # the shared key proves no identity, so it can't be the second person
        assert c.post(f"/panel/api/checkpoints/{pid}/approve", headers=H).json()["status"] == "awaiting_approval"

        fake["email"] = "bob@corp.com"  # a second person signs in with SSO
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(
            c.get("/panel/sso/login", follow_redirects=False).headers["location"]).query))
        fake["challenge"], fake["nonce"] = q["code_challenge"], q["nonce"]
        c.get("/panel/sso/callback", params={"code": "good-code", "state": q["state"]}, follow_redirects=False)
        assert c.post(f"/panel/api/checkpoints/{pid}/approve", headers=H).json()["status"] == "applied"
        fake["email"] = "alice@corp.com"


def test_sso_token_with_another_nonce_is_refused(gateway, idp):
    start, _ = gateway
    _, fake = idp
    with start(SSO_YAML) as c:
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(
            c.get("/panel/sso/login", follow_redirects=False).headers["location"]).query))
        fake["challenge"], fake["nonce"] = q["code_challenge"], "a-replayed-token-nonce"
        r = c.get("/panel/sso/callback", params={"code": "good-code", "state": q["state"]}, follow_redirects=False)
        assert r.status_code == 403 and c.get("/panel/api/session").json()["actor"] is None


def test_export_escapes_formulas_and_names_approvers(gateway):
    start, control = gateway
    with start("") as c:
        admin_login(c)
        pid = pending(control, sql="=HYPERLINK(\"http://evil\") -- UPDATE public.acct SET val = 1 WHERE id = 1")
        c.post(f"/panel/api/checkpoints/{pid}/reject", headers=H)
        csv_text = c.get("/panel/api/export", params={"format": "csv"}).text
        assert "'=HYPERLINK" in csv_text and ",=HYPERLINK" not in csv_text
        api_csv = c.get("/v1/audit/export", headers={"X-API-Key": "admin-k"})
        assert api_csv.status_code == 200 and api_csv.headers["content-type"].startswith("text/csv")
        first = json.loads(c.get("/panel/api/export", params={"format": "jsonl"}).text.splitlines()[0])
        assert set(first) >= {"public_id", "approved_by", "hash", "sql_text"}
