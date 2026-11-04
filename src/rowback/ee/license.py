"""Pro license check. Keys are sold and revoked by Polar (polar.sh), our merchant of record.

Checked once at startup. The key sets the plan: how far back undo reaches and which features
are on. Pro keys cover a fixed number of databases, counted with Polar activations. The core
safety path (gate, holds, capture, undo, ledger) never needs a key.
"""
import json
import logging
import urllib.error
import urllib.request
from typing import NamedTuple, Protocol

logger = logging.getLogger("rowback.license")

POLAR_ORGANIZATION_ID = "493a1901-78e3-4579-9c47-01bb8125a314"
POLAR_VALIDATE_URL = "https://api.polar.sh/v1/customer-portal/license-keys/validate"
POLAR_ACTIVATE_URL = "https://api.polar.sh/v1/customer-portal/license-keys/activate"
BUY_URL = "https://buy.polar.sh/polar_cl_ar1Nqmcc0aEByc0Z6pMf3mke7yp1rm22gUQy73Uaomv"
HTTP_TIMEOUT_SECONDS = 5
# Polar benefit ids that make a key Enterprise (no undo window limit, no database limit).
# Empty until the Enterprise product exists in Polar; every other granted key is Pro.
ENTERPRISE_BENEFIT_IDS: frozenset[str] = frozenset()


def _need(features: list[str]) -> str:
    return f"{', '.join(features)} {'needs' if len(features) == 1 else 'need'}"


class LicenseError(ValueError):  # a startup refusal, like the other config errors
    pass


class Validation(NamedTuple):
    status: str  # "granted", "invalid" or "unreachable"
    enterprise: bool = False  # the key carries an Enterprise benefit
    needs_activation: bool = False  # the key has a database limit and this database holds no activation yet


def _post(url: str, payload: dict) -> tuple[int, dict]:
    """POSTs JSON to Polar: (HTTP status, body). Raises OSError/ValueError when Polar can't be reached."""
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "rowback"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as r:  # hardcoded https Polar URL constants  # nosec B310
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, {}


def validate_key(key: str, activation_id: str | None = None) -> Validation:
    """Asks Polar about a key, and about this database's activation of it when one is stored."""
    payload = {"key": key, "organization_id": POLAR_ORGANIZATION_ID}
    try:
        code, body = _post(POLAR_VALIDATE_URL, payload | ({"activation_id": activation_id} if activation_id else {}))
        if code == 404 and activation_id:  # the activation was removed in the customer portal; the key may still be fine
            activation_id = None
            code, body = _post(POLAR_VALIDATE_URL, payload)
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return Validation("unreachable")
    if code in (400, 404, 422):  # 404: unknown, revoked, disabled or expired key. 400/422: malformed.
        return Validation("invalid")
    if code != 200:
        return Validation("unreachable")
    if body.get("status") != "granted":
        return Validation("invalid")
    return Validation("granted", enterprise=body.get("benefit_id") in ENTERPRISE_BENEFIT_IDS,
                      needs_activation=bool(body.get("limit_activations")) and not activation_id)


def activate_key(key: str, label: str) -> str:
    """Counts this database against the key's limit: an activation id, "limit", "invalid" or "unreachable"."""
    try:
        code, body = _post(POLAR_ACTIVATE_URL, {"key": key, "organization_id": POLAR_ORGANIZATION_ID, "label": label})
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return "unreachable"
    if code == 403:  # Polar: activation limit reached
        return "limit"
    if code in (400, 404, 422):
        return "invalid"
    if code not in (200, 201) or not body.get("id"):
        return "unreachable"
    return str(body["id"])


class ActivationStore(Protocol):
    """Where this database keeps its activation of the key (rowback.license_activation)."""
    def load(self) -> tuple[str, str | None]: ...  # (install label, activation id or None)
    def save(self, activation_id: str) -> None: ...


def check_license(key: str | None, features: list[str], store: ActivationStore | None = None) -> str:
    """Startup gate for paid features: the plan, "free", "pro" or "enterprise".
    Raises LicenseError to refuse startup.

    ponytail: when Polar can't be reached (outage, air-gapped network) the paid plan stays on
    with a warning, so our vendor's downtime never takes a customer's gateway down. That also
    means blocking api.polar.sh skips the check; the license terms, not code, cover that case.
    """
    if not key:
        if features:
            raise LicenseError(f"Startup Refusal: {_need(features)} a Rowback Pro license. "
                               f"Set ROWBACK_LICENSE_KEY (get one at {BUY_URL}) or remove them from the config.")
        return "free"
    label, activation_id = store.load() if store else ("", None)
    result = validate_key(key, activation_id)
    if result.status == "unreachable":
        logger.warning("Could not reach Polar to check the Rowback license; paid features stay on.")
        return "pro"
    if result.status != "granted":
        return _refuse(features, "the Rowback license key is invalid, expired or cancelled",
                       "ROWBACK_LICENSE_KEY is invalid, expired or cancelled")
    tier = "enterprise" if result.enterprise else "pro"
    if result.needs_activation and store:
        activation = activate_key(key, label)
        if activation == "limit":
            return _refuse(features, "this Rowback license is already in use on as many databases as it covers",
                           "ROWBACK_LICENSE_KEY is already in use on as many databases as it covers",
                           "Free one up in the Polar customer portal, or move to Enterprise.")
        if activation == "invalid":
            return _refuse(features, "the Rowback license key is invalid, expired or cancelled",
                           "ROWBACK_LICENSE_KEY is invalid, expired or cancelled")
        if activation == "unreachable":
            logger.warning("Could not reach Polar to activate the Rowback license; paid features stay on.")
            return tier
        store.save(activation)
    return tier


def _refuse(features: list[str], why: str, warning: str, fix: str = "") -> str:
    fix = fix or f"Renew at {BUY_URL}."
    if features:
        raise LicenseError(f"Startup Refusal: {why}, and {_need(features)} one. {fix} Or remove them from the config.")
    logger.warning(f"{warning}; paid features are off. {fix}")
    return "free"
