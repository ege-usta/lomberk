"""Pro license check. Keys are sold and revoked by Polar (polar.sh), our merchant of record.

Checked once at startup, only when a Pro feature is configured. The core safety path
(gate, holds, capture, undo, ledger) never needs a key.
"""
import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger("rowback.license")

# ponytail: set to the real Polar organization ID before the first sale; see BACKLOG.md.
POLAR_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000000"
POLAR_VALIDATE_URL = "https://api.polar.sh/v1/customer-portal/license-keys/validate"
BUY_URL = "https://github.com/ege-usta/rowback#pricing"
HTTP_TIMEOUT_SECONDS = 5


def _need(features: list[str]) -> str:
    return f"{', '.join(features)} {'needs' if len(features) == 1 else 'need'}"


class LicenseError(ValueError):  # a startup refusal, like the other config errors
    pass


def validate_key(key: str) -> str:
    """Asks Polar about a key: "granted", "invalid", or "unreachable"."""
    body = json.dumps({"key": key, "organization_id": POLAR_ORGANIZATION_ID}).encode()
    req = urllib.request.Request(POLAR_VALIDATE_URL, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "rowback"})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as r:
            return "granted" if json.load(r).get("status") == "granted" else "invalid"
    except urllib.error.HTTPError as e:
        # 404: unknown, revoked, disabled or expired key. 400/422: malformed.
        return "invalid" if e.code in (400, 404, 422) else "unreachable"
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        return "unreachable"


def check_license(key: str | None, features: list[str]) -> bool:
    """Startup gate for Pro features. True = Pro is on. Raises LicenseError to refuse startup.

    ponytail: when Polar can't be reached (outage, air-gapped network) Pro stays on with a
    warning, so our vendor's downtime never takes a customer's gateway down. That also means
    blocking api.polar.sh skips the check; the license terms, not code, cover that case.
    """
    if not key:
        if features:
            raise LicenseError(f"Startup Refusal: {_need(features)} a Rowback Pro license. "
                               f"Set ROWBACK_LICENSE_KEY (get one at {BUY_URL}) or remove them from the config.")
        return False
    result = validate_key(key)
    if result == "granted":
        return True
    if result == "unreachable":
        logger.warning("Could not reach Polar to check the Rowback license; Pro features stay on.")
        return True
    if features:
        raise LicenseError(f"Startup Refusal: the Rowback license key is invalid, expired or cancelled, and "
                           f"{_need(features)} one. Renew at {BUY_URL} or remove them from the config.")
    logger.warning("ROWBACK_LICENSE_KEY is invalid, expired or cancelled; Pro features are off.")
    return False
