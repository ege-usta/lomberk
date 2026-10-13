"""OIDC approvers: an approval carries a person's ID token from the company IdP
(Okta, Entra ID, Google...), so the audit trail names a human, not a shared key."""
import hmac
import json
import threading
import time
import urllib.parse
import urllib.request

import jwt

# Asymmetric only: "none" and HS* would let anyone who knows the public key sign.
ALLOWED_ALGS = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
JWKS_MIN_REFRESH_SECONDS = 60  # unknown key IDs are attacker-chosen; don't let them hammer the IdP
HTTP_TIMEOUT_SECONDS = 5
CLOCK_LEEWAY_SECONDS = 30


class SsoError(Exception):
    pass


def _require_https(url: str) -> None:
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" and not (u.scheme == "http" and u.hostname in ("localhost", "127.0.0.1")):
        raise ValueError(f"Startup Refusal: SSO URL must be https: {url}")


def _get_json(url: str) -> dict:
    _require_https(url)  # scheme is validated here; only https:// reaches urlopen
    with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_SECONDS) as r:  # _require_https restricts to https  # nosec B310
        return json.load(r)


class OidcVerifier:
    def __init__(self, cfg):
        if not cfg.issuer or not cfg.audience:
            raise ValueError("Startup Refusal: sso.issuer and sso.audience are both required.")
        if not cfg.allowed_groups and not cfg.allowed_identities:
            raise ValueError("Startup Refusal: set sso.allowed_groups or sso.allowed_identities.")
        _require_https(cfg.issuer)
        self.cfg = cfg
        if cfg.jwks_url:
            self.jwks_url = cfg.jwks_url
        else:
            doc = _get_json(cfg.issuer.rstrip("/") + "/.well-known/openid-configuration")
            if doc.get("issuer") != cfg.issuer:
                raise ValueError("Startup Refusal: SSO discovery document names a different issuer.")
            self.jwks_url = doc["jwks_uri"]
        _require_https(self.jwks_url)
        self._lock = threading.Lock()
        self._keys: dict = {}
        self._fetched_at = float("-inf")
        self._refresh()

    def _refresh(self) -> None:
        keyset = jwt.PyJWKSet.from_dict(_get_json(self.jwks_url))
        self._keys = {k.key_id: k for k in keyset.keys}
        self._fetched_at = time.monotonic()

    def _key(self, kid):
        # ponytail: the fetch runs under the lock, so a key rotation stalls other approvals
        # for up to HTTP_TIMEOUT_SECONDS once per JWKS_MIN_REFRESH_SECONDS; fine at approval rates.
        with self._lock:
            if kid not in self._keys and time.monotonic() - self._fetched_at >= JWKS_MIN_REFRESH_SECONDS:
                self._refresh()  # the IdP rotated its keys
            return self._keys.get(kid)

    def verify(self, token: str, nonce: str | None = None) -> str:
        """Returns the audited actor ("oidc:<identity>") or raises SsoError.

        nonce: set for tokens from the panel's login flow, so a replayed token is refused."""
        return self.verify_claims(token, nonce)[0]

    def allowed(self, identity: str, groups) -> list[str] | None:
        """The allowed groups that admit this person ([] if listed by identity), or None if not allowed."""
        matched = sorted(set(groups) & set(self.cfg.allowed_groups)) if isinstance(groups, list) else []
        return matched if matched or identity in self.cfg.allowed_identities else None

    def verify_claims(self, token: str, nonce: str | None = None) -> tuple[str, dict]:
        """verify(), plus the token's claims (the panel ties its session to their exp and groups)."""
        try:
            key = self._key(jwt.get_unverified_header(token).get("kid"))
            if key is None:
                raise SsoError("unknown signing key")
            claims = jwt.decode(
                token, key.key, algorithms=ALLOWED_ALGS, audience=self.cfg.audience, issuer=self.cfg.issuer,
                leeway=CLOCK_LEEWAY_SECONDS, options={"require": ["exp", "iat", "iss", "aud", "sub"]})
        except SsoError:
            raise
        except Exception as e:
            raise SsoError(type(e).__name__) from None
        if nonce is not None and not hmac.compare_digest(str(claims.get("nonce", "")), nonce):
            raise SsoError("nonce mismatch")
        # Fail closed: IdPs that omit email_verified (e.g. Entra ID) must use another
        # identity_claim, since their email attribute may be user-editable.
        if self.cfg.identity_claim == "email" and claims.get("email_verified") is not True:
            raise SsoError("email not verified")
        identity = claims.get(self.cfg.identity_claim)
        if not isinstance(identity, str) or not identity:
            raise SsoError(f"token has no {self.cfg.identity_claim}")
        if self.allowed(identity, claims.get(self.cfg.groups_claim)) is None:
            raise SsoError("not an allowed approver")
        return f"oidc:{identity}", claims
