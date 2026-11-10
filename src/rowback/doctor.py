"""`rowback doctor`: checks a deployment read-only and says how to fix each problem."""
import os

import psycopg
import yaml
from pydantic import ValidationError

from rowback.config import (
    CONFIG_ENV,
    RowbackConfig,
    config_error_message,
    config_path,
    load_config,
    pro_features,
    weak_key_reason,
)

OK, WARN, FAIL = "ok", "warn", "fail"
CONNECT_TIMEOUT_SECONDS = 5


def run_checks(path: str | None = None) -> list[tuple[str, str, str]]:
    """(level, what was found, how to fix it) for each check, in order."""
    out: list[tuple[str, str, str]] = []

    def add(level: str, what: str, fix: str = "") -> None:
        out.append((level, what, fix))

    path = path or config_path()
    if not os.path.exists(path) and path == os.environ.get(CONFIG_ENV):
        add(FAIL, f"{CONFIG_ENV} points at {path}, which does not exist, so the gateway will refuse to start",
            f"Fix the path in {CONFIG_ENV} or unset it.")
        return out
    if os.path.exists(path):
        try:
            config = load_config(path)
        except (ValidationError, yaml.YAMLError) as e:
            add(FAIL, f"{path} is invalid: {config_error_message(e)}",
                "Fix the key named above. Unknown keys are refused on purpose, so a typo can't turn protection off.")
            return out
        add(OK, f"{path} is valid")
    else:
        config = RowbackConfig()
        add(WARN, f"no {path} in this directory, so defaults apply (no protected tables)",
            f"Run the gateway from the directory that holds rowback.yaml, or set {CONFIG_ENV} to its path.")

    control, agent = _env_checks(config, add)
    if control and agent:
        _db_checks(config, control, agent, add)
    _pro_checks(config, add)
    return out


def _env_checks(config, add):
    dsns = []
    for label, env in (("control", config.database.admin_dsn_env), ("agent", config.database.agent_dsn_env)):
        value = os.environ.get(env)
        if not value:
            add(FAIL, f"{env} is not set", f"Set it to the {label} role's connection string, e.g. postgresql://{label}_role:…@host/db")
        dsns.append(value)
    agent_key, admin_key = os.environ.get("ROWBACK_API_KEY"), os.environ.get("ROWBACK_ADMIN_KEY")
    for env, value in (("ROWBACK_API_KEY", agent_key), ("ROWBACK_ADMIN_KEY", admin_key)):
        if not value:
            add(FAIL, f"{env} is not set", "Generate one with: openssl rand -hex 32")
        elif reason := weak_key_reason(value):
            if os.environ.get("ROWBACK_ALLOW_WEAK_KEYS", "").lower() == "true":
                add(WARN, f"{env} {reason}; accepted only because ROWBACK_ALLOW_WEAK_KEYS=true",
                    "Fine on a laptop demo. Anywhere else: openssl rand -hex 32, and unset ROWBACK_ALLOW_WEAK_KEYS.")
            else:
                add(FAIL, f"{env} {reason}, so the gateway refuses to start", "Use a random key: openssl rand -hex 32")
    if agent_key and agent_key == admin_key:
        add(FAIL, "the agent key and the admin key are the same", "Give the agent its own key; it must never be able to approve.")
    elif agent_key and admin_key:
        add(OK, "agent and admin keys are set and distinct")
    return dsns


def _db_checks(config, control: str, agent: str, add) -> None:
    roles = {}
    for label, dsn in (("control", control), ("agent", agent)):
        try:
            with psycopg.connect(dsn, connect_timeout=CONNECT_TIMEOUT_SECONDS) as conn:
                roles[label] = conn.execute(
                    "SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)").fetchone()
        except psycopg.Error as e:
            add(FAIL, f"can't connect as the {label} role: {str(e).strip().splitlines()[0]}",
                "Check the host, port, password, and that the database accepts connections from this machine.")
    if len(roles) < 2:
        return
    if roles["control"][0] == roles["agent"][0]:
        add(FAIL, f"both connection strings log in as {roles['agent'][0]}",
            "Use two roles: a control role for Rowback and a separate agent role.")
    for label, (user, superuser) in roles.items():
        if superuser:
            add(FAIL, f"the {label} role {user} is a superuser", f"Use a non-superuser role for {label}.")
    if roles["control"][0] != roles["agent"][0] and not any(s for _, s in roles.values()):
        add(OK, f"connected as {roles['control'][0]} (control) and {roles['agent'][0]} (agent)")

    with psycopg.connect(control, connect_timeout=CONNECT_TIMEOUT_SECONDS) as conn:
        has_schema, has_approvals = conn.execute(
            "SELECT to_regclass('rowback.checkpoints') IS NOT NULL, to_regclass('rowback.approvals') IS NOT NULL").fetchone()
        if not has_schema:
            add(FAIL, "Rowback is not installed in this database",
                "Run: rowback init --control-role <control> --agent-role <agent>  (with ROWBACK_INSTALL_DSN set to an owner)")
            return
        if not has_approvals:
            add(FAIL, "the Rowback schema is from an older version", "Re-run rowback init; it is safe to repeat and upgrades in place.")
            return
        registered = {f"{s}.{t}" for s, t in conn.execute("SELECT schema_name, table_name FROM rowback.registered_tables")}
        _secret_column_checks(config, conn, roles["agent"][0], add)
        checked, broken, _ = conn.execute("SELECT * FROM rowback.verify_ledger()").fetchone()

    if registered:
        add(OK, f"{len(registered)} table(s) registered for undo: {', '.join(sorted(registered))}")
    else:
        add(WARN, "no tables are registered, so the agent can only read",
            "Register each table the agent may write: rowback register public.orders --agent-role <agent>")
    missing = sorted(set(config.protected_tables) - registered)
    if missing:
        add(WARN, f"protected but not registered: {', '.join(missing)}. Agent writes to them will be refused",
            "Register them with rowback register, or remove them from protected_tables.")
    if broken:
        add(FAIL, f"the ledger is broken at checkpoint {broken}", "Someone edited history in the database. Investigate before trusting it.")
    else:
        add(OK, f"ledger intact ({checked} checkpoints)")


# Words that often mean a secret but are too short to match inside other names (passenger, spinner).
SUSPECT_WORDS = {"pass", "pin", "otp", "totp", "mfa", "salt", "cvv", "cvc", "iban", "key", "jwt", "session",
                 "cookie", "auth", "seed", "mnemonic", "passphrase", "signature"}
LIST_LIMIT = 8


def _secret_column_checks(config, conn, agent_role: str, add) -> None:
    """Columns the agent role can SELECT in the database: secret ones should be hidden there too."""
    import re

    from rowback.sql.classify import is_secret
    rows = conn.execute(
        "SELECT n.nspname || '.' || c.relname || '.' || a.attname, a.attname, format_type(a.atttypid, NULL) "
        "FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace "
        "WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND a.attnum > 0 AND NOT a.attisdropped "
        "AND n.nspname NOT LIKE 'pg\\_%%' AND n.nspname NOT IN ('information_schema', 'rowback', 'rowback_trash') "
        "AND has_column_privilege(%s, c.oid, a.attnum, 'SELECT') ORDER BY 1", (agent_role,)).fetchall()
    extra = config.sensitive_columns

    def listed(items):
        return ", ".join(items[:LIST_LIMIT]) + (f" and {len(items) - LIST_LIMIT} more" if len(items) > LIST_LIMIT else "")
    readable = [full for full, name, _ in rows if is_secret(name, extra)]
    if readable:
        add(WARN, f"the agent role can read secret columns in the database: {listed(readable)}. "
                  "Rowback's name filter still refuses them, but the database doesn't",
            "Re-run rowback register for each table (it hides them), or REVOKE SELECT on those columns.")
    suspect = [full for full, name, _ in rows if not is_secret(name, extra)
               and set(re.split(r"[^a-z0-9]+", name.lower())) & SUSPECT_WORDS]
    if suspect:
        add(WARN, f"columns that may hold secrets under a name Rowback doesn't know: {listed(suspect)}",
            "If they do, add their names to sensitive_columns in rowback.yaml and re-run rowback register.")
    json_cols = [full for full, name, typ in rows if typ in ("json", "jsonb") and not is_secret(name, extra)]
    if json_cols:
        add(WARN, f"the agent can read JSON columns: {listed(json_cols)}. Secret-looking keys are masked, "
                  "but JSON can hide a secret under any key",
            "If one holds secrets, add its name to sensitive_columns and re-run rowback register.")
    if not (readable or suspect or json_cols):
        add(OK, "no secret-looking column is readable by the agent role")


def _pro_checks(config, add) -> None:
    features, key = pro_features(config), os.environ.get("ROWBACK_LICENSE_KEY")
    if os.environ.get("ROWBACK_SLACK_ENABLED", "").lower() == "true":
        for env in ("ROWBACK_SLACK_APP_TOKEN", "ROWBACK_SLACK_BOT_TOKEN"):
            if not os.environ.get(env):
                add(FAIL, f"Slack is enabled but {env} is not set", "Copy it from your Slack app settings (see README, Slack).")
    if not features and not key:
        return
    try:
        from rowback.ee.license import BUY_URL, _need, validate_key
    except ImportError:
        add(FAIL, f"{', '.join(features)} are configured but the Pro package (rowback.ee) is missing", "Install the full rowback package.")
        return
    if not key:
        add(FAIL, f"{_need(features)} a Pro license key", f"Set ROWBACK_LICENSE_KEY. Buy one at {BUY_URL}")
        return
    result = validate_key(key).status
    if result == "granted":
        add(OK, "Rowback license is valid")
    elif result == "unreachable":
        add(WARN, "couldn't reach api.polar.sh to check the license", "The gateway still starts. Check outbound HTTPS if you expected it to work.")
    else:
        level = FAIL if features else WARN
        add(level, "the license key is invalid, expired or cancelled", f"Renew or check the key at {BUY_URL}")
    if config.sso.issuer:
        _sso_check(config, add)


def _sso_check(config, add) -> None:
    from rowback.ee.sso import _get_json, _require_https
    try:
        doc = _get_json(config.sso.issuer.rstrip("/") + "/.well-known/openid-configuration")
        if doc.get("issuer") != config.sso.issuer:
            raise ValueError(f"the IdP calls itself {doc.get('issuer')}")
        if config.sso.panel_url:
            _require_https(config.sso.panel_url)
        add(OK, f"SSO issuer {config.sso.issuer} answers")
    except (OSError, ValueError, KeyError) as e:
        add(FAIL, f"SSO issuer check failed: {str(e).splitlines()[0]}",
            "sso.issuer must match your IdP's issuer exactly, over https, and sso.panel_url must be https.")
