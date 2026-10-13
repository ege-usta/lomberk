"""Web approval panel (Pro): writes waiting for approval, history, approve/reject/undo, export.

Sign-in: SSO (OIDC authorization code flow with PKCE, done server side) or the shared admin key.
Session: an HMAC-signed cookie keyed from a random per-process server secret, independent of
ROWBACK_ADMIN_KEY (so holding the admin key cannot forge a session, and a restart signs
everyone out), HttpOnly and SameSite=Strict. State-changing requests also need the
X-Rowback-Panel header, which a cross-site form cannot send. Agent SQL is untrusted input: the
page renders it as text only, and the CSP allows no inline script.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel

from rowback.audit import audit
from rowback.ee.sso import SsoError, _get_json, _require_https

SESSION_COOKIE = "rowback_session"
OIDC_COOKIE = "rowback_oidc"
# Admin-key sessions; SSO sessions end sooner, when the IdP's ID token expires (usually 1 hour),
# so removing someone at the IdP signs them out of the panel then.
SESSION_SECONDS = 8 * 3600
OIDC_SECONDS = 600
HISTORY_LIMIT = 200
HTTP_TIMEOUT_SECONDS = 5
STATIC = Path(__file__).parent / "panel_static"
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                                "img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
_discovery: dict = {}


def _api():
    # The running gateway's state; imported late to avoid an import cycle.
    from rowback import api
    return api


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _mac(payload: str) -> str:
    # Keyed from a random per-process server secret, NOT ROWBACK_ADMIN_KEY: the admin key is
    # deliberately excluded from the approval quorum, so holding it must not let anyone forge a
    # panel session (and assert an `oidc:` approver that never signed in).
    key = hmac.new(_api()._SESSION_SECRET, b"rowback-panel-session-v1", hashlib.sha256).digest()
    return _b64(hmac.new(key, payload.encode(), hashlib.sha256).digest())


def sign(purpose: str, data: dict, ttl: int) -> str:
    payload = _b64(json.dumps({**data, "p": purpose, "exp": int(time.time()) + ttl}).encode())
    return payload + "." + _mac(payload)


def unsign(purpose: str, token: str | None) -> dict | None:
    """The signed data, or None if forged, expired or signed for another purpose."""
    if not token or token.count(".") != 1:
        return None
    payload, sig = token.split(".")
    if not hmac.compare_digest(sig, _mac(payload)):
        return None
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("p") != purpose or data.get("exp", 0) <= time.time():
        return None
    return data


def _secure(request: Request) -> bool:
    # A TLS proxy may reach us as http://127.0.0.1; its X-Forwarded-Proto only ever adds Secure.
    return request.headers.get("x-forwarded-proto") == "https" or request.url.hostname not in ("localhost", "127.0.0.1")


def _set_session(resp: Response, request: Request, actor: str, ttl: int = SESSION_SECONDS, groups=()) -> None:
    resp.set_cookie(SESSION_COOKIE, sign("session", {"actor": actor, "groups": list(groups)}, ttl), max_age=ttl,
                    httponly=True, secure=_secure(request), samesite="strict", path="/panel")


def _session_actor(request: Request) -> str | None:
    data = unsign("session", request.cookies.get(SESSION_COOKIE))
    actor = data and data.get("actor")
    if not isinstance(actor, str):
        return None
    api = _api()
    # Re-check against today's config: a session must not outlive the sign-in method it used.
    if actor == "api_admin" and not api._ALLOW_ADMIN_KEY:
        return None
    if actor.startswith("oidc:"):
        # Today's allowlist decides, so removing a person or group from the config takes effect now.
        groups = data.get("groups")
        if api._SSO is None or api._SSO.allowed(actor[len("oidc:"):], groups if isinstance(groups, list) else []) is None:
            return None
    return actor


def _actor(request: Request) -> str:
    actor = _session_actor(request)
    if actor is None:
        raise HTTPException(status_code=401, detail="Sign in first.")
    return actor


def _csrf(request: Request) -> None:
    if request.headers.get("x-rowback-panel") != "1":
        raise HTTPException(status_code=403, detail="Missing X-Rowback-Panel header.")


def _oidc():
    """(sso config, discovery document) when "Sign in with SSO" is set up, else 404."""
    sso = _api()._SSO
    if sso is None or not sso.cfg.panel_url:
        raise HTTPException(status_code=404, detail="SSO sign-in is not configured.")
    cfg = sso.cfg
    if cfg.issuer not in _discovery:
        doc = _get_json(cfg.issuer.rstrip("/") + "/.well-known/openid-configuration")
        if doc.get("issuer") != cfg.issuer:
            raise HTTPException(status_code=502, detail="SSO discovery document names a different issuer.")
        for key in ("authorization_endpoint", "token_endpoint"):
            _require_https(doc[key])
        _discovery[cfg.issuer] = doc
    return cfg, _discovery[cfg.issuer]


def _redirect_uri(cfg) -> str:
    _require_https(cfg.panel_url)
    return cfg.panel_url.rstrip("/") + "/panel/sso/callback"


def _exchange_code(cfg, doc: dict, code: str, verifier: str) -> str:
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": _redirect_uri(cfg),
            "client_id": cfg.audience, "code_verifier": verifier}
    if os.environ.get("ROWBACK_SSO_CLIENT_SECRET"):
        form["client_secret"] = os.environ["ROWBACK_SSO_CLIENT_SECRET"]
    req = urllib.request.Request(doc["token_endpoint"], data=urllib.parse.urlencode(form).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as r:  # token_endpoint https-validated in _discovery  # nosec B310
            token = json.load(r)["id_token"]
    except (OSError, ValueError, KeyError, TypeError):
        raise HTTPException(status_code=502, detail="The identity provider did not return a token.") from None
    if not isinstance(token, str):
        raise HTTPException(status_code=502, detail="The identity provider did not return a token.")
    return token


class _Login(BaseModel):
    key: str


def build_panel() -> FastAPI:
    panel = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @panel.middleware("http")
    async def security_headers(request: Request, call_next):
        resp = await call_next(request)
        resp.headers.update(SECURITY_HEADERS)
        return resp

    @panel.get("/")
    def index():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @panel.get("/app.js")
    def script():
        return FileResponse(STATIC / "app.js", media_type="text/javascript")

    @panel.get("/app.css")
    def style():
        return FileResponse(STATIC / "app.css", media_type="text/css")

    @panel.get("/api/session")
    def session(request: Request):
        api = _api()
        sso = api._SSO is not None and bool(api._SSO.cfg.panel_url)
        return {"actor": _session_actor(request), "sso": sso, "admin_key": api._ALLOW_ADMIN_KEY,
                "required_approvals": api._executor_instance.required_approvals}

    @panel.post("/login")
    def login(body: _Login, request: Request):
        _csrf(request)
        api = _api()
        if not api._ALLOW_ADMIN_KEY:
            raise HTTPException(status_code=403, detail="Admin key sign-in is off; use SSO.")
        if not api._key_matches(body.key, api._ADMIN_KEY):
            audit("panel_login_failed", actor="api_admin")
            raise HTTPException(status_code=401, detail="Wrong admin key.")
        resp = JSONResponse({"actor": "api_admin"})
        _set_session(resp, request, "api_admin")
        audit("panel_login", actor="api_admin")
        return resp

    @panel.post("/logout")
    def logout(request: Request):
        _csrf(request)
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(SESSION_COOKIE, path="/panel")
        return resp

    @panel.get("/sso/login")
    def sso_login(request: Request):
        cfg, doc = _oidc()
        state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = _b64(hashlib.sha256(verifier.encode()).digest())
        query = urllib.parse.urlencode({
            "response_type": "code", "client_id": cfg.audience, "redirect_uri": _redirect_uri(cfg),
            "scope": "openid email profile", "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256"})
        resp = RedirectResponse(doc["authorization_endpoint"] + "?" + query, status_code=303)
        # Lax, not Strict: the IdP's redirect back is a cross-site navigation.
        resp.set_cookie(OIDC_COOKIE, sign("oidc", {"state": state, "nonce": nonce, "v": verifier}, OIDC_SECONDS),
                        max_age=OIDC_SECONDS, httponly=True, secure=_secure(request), samesite="lax", path="/panel/sso")
        return resp

    @panel.get("/sso/callback")
    def sso_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        cfg, doc = _oidc()
        data = unsign("oidc", request.cookies.get(OIDC_COOKIE))
        if error or not code or not data or not hmac.compare_digest(state, data["state"]):
            raise HTTPException(status_code=400, detail="Sign-in failed or expired. Start again from the panel.")
        try:
            sso = _api()._SSO
            actor, claims = sso.verify_claims(_exchange_code(cfg, doc, code, data["v"]), nonce=data["nonce"])
            ttl = min(SESSION_SECONDS, int(claims["exp"]) - int(time.time()))
            if ttl <= 0:
                raise SsoError("token already expired")
        except SsoError as e:
            audit("panel_login_failed", actor="oidc", reason=str(e))
            raise HTTPException(status_code=403, detail="Your account is not an allowed approver.") from None
        resp = RedirectResponse("/panel/", status_code=303)
        resp.delete_cookie(OIDC_COOKIE, path="/panel/sso")
        _set_session(resp, request, actor, ttl, sso.allowed(actor[len("oidc:"):], claims.get(sso.cfg.groups_claim)))
        audit("panel_login", actor=actor)
        return resp

    @panel.get("/api/checkpoints")
    def checkpoints(request: Request):
        _actor(request)
        return {"items": _api()._executor_instance.list_checkpoints(limit=HISTORY_LIMIT)}

    @panel.post("/api/checkpoints/{public_id}/{action}")
    def act(public_id: str, action: str, request: Request):
        _csrf(request)
        actor = _actor(request)
        executor = _api()._executor_instance
        if action == "approve":
            res = executor.execute_pending(public_id, actor=actor)
        elif action == "undo":
            res = executor.execute_undo(public_id, agent_label=actor)
        elif action == "reject":
            if not executor.reject(public_id, actor=actor):
                raise HTTPException(status_code=409, detail="Not pending any more.")
            return {"status": "rejected", "message": "Rejected."}
        else:
            raise HTTPException(status_code=404, detail="Unknown action.")
        return {"status": res.status, "message": res.message}

    @panel.get("/api/export")
    def export(request: Request, format: str = "csv"):
        actor = _actor(request)
        from rowback.ee.export import FORMATS, render
        if format not in FORMATS:
            raise HTTPException(status_code=422, detail=f"format must be one of {sorted(FORMATS)}")
        rows = _api()._executor_instance.list_checkpoints()
        audit("exported", actor=actor, rows=len(rows), format=format)
        return Response(render(rows, format), media_type=FORMATS[format],
                        headers={"Content-Disposition": f'attachment; filename="rowback-audit.{format}"'})

    return panel
