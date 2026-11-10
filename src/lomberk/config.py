import os
import sys

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class _Strict(BaseModel):
    # A typo like `protected_table:` must fail startup, not silently disable protection.
    model_config = ConfigDict(extra="forbid")


class DatabaseConfig(_Strict):
    agent_dsn_env: str = "LOMBERK_AGENT_DSN"
    admin_dsn_env: str = "LOMBERK_ADMIN_DSN"

class LimitsConfig(_Strict):
    max_rows_without_approval: int = 100
    max_snapshot_rows: int = 1000000
    statement_timeout_ms: int = 15000

class AgentConfig(_Strict):
    approval_timeout_minutes: int = 30

class SlackConfig(_Strict):
    admin_allowlist: list[str] = Field(default_factory=list)
    team_allowlist: list[str] = Field(default_factory=list)
    # Channel the gateway posts pending approvals to. Unset = no built-in publisher.
    channel_id: str | None = None
    # Off by default: SQL literals may contain regulated data that must not leave for Slack.
    include_sql: bool = False

class ApprovalsConfig(_Strict):
    # Distinct people who must approve a held write before it runs (the two-person rule).
    # Counts identities: SSO emails, Slack users, CLI users. The shared admin key is one person.
    required: int = Field(1, ge=1, le=5)
    # Dry-run every held write (run it, read the rows it changed, roll it back) so approvers see
    # what would change. Turn off if a table's triggers do something a rollback can't take back.
    preview: bool = True

class SsoConfig(_Strict):
    # OIDC approvers (Enterprise). Unset issuer = approvals use the admin key only.
    issuer: str | None = None
    audience: str | None = None
    jwks_url: str | None = None  # default: discovered from the issuer
    identity_claim: str = "email"
    groups_claim: str = "groups"
    # Who may approve. At least one list is required: an issuer like Google signs for
    # anyone with an account, so "anyone the issuer signs for" is never a safe default.
    allowed_groups: list[str] = Field(default_factory=list)
    allowed_identities: list[str] = Field(default_factory=list)
    # Shared admin key next to SSO. Default: on without SSO, off with SSO (the CLI
    # remains the break-glass path if the IdP is down).
    allow_admin_key: bool | None = None
    # Public https URL of this gateway, e.g. https://lomberk.corp.com. Turns on "Sign in
    # with SSO" in the web panel; register <panel_url>/panel/sso/callback at the IdP.
    # The client secret, if the IdP needs one, comes from LOMBERK_SSO_CLIENT_SECRET.
    panel_url: str | None = None

class LomberkConfig(_Strict):
    version: int = 1
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    protected_tables: list[str] = Field(default_factory=list)
    # Column names (any table) treated like `password`: never readable by the agent, and
    # hidden by the database itself on tables you `lomberk register`. Use it for secrets the
    # built-in name list can't guess (`pass`, `pin`) and for JSON columns that hold secrets.
    sensitive_columns: list[str] = Field(default_factory=list)
    deny_patterns: list[str] = Field(default_factory=list)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    slack: SlackConfig = Field(default_factory=SlackConfig)
    sso: SsoConfig = Field(default_factory=SsoConfig)
    approvals: ApprovalsConfig = Field(default_factory=ApprovalsConfig)

    @field_validator("protected_tables")
    @classmethod
    def _schema_qualified(cls, tables: list[str]) -> list[str]:
        # Writes name schema.table; a bare "orders" would never match and silently protect nothing.
        bare = [t for t in tables if "." not in t]
        if bare:
            raise ValueError(f"protected_tables entries must be schema.table, e.g. public.{bare[0]}")
        return tables


DEMO_KEYS = ("demo-agent-key", "demo-admin-key")
MIN_KEY_LENGTH = 32


def weak_key_reason(key: str) -> str | None:
    """Why a gateway key is guessable, or None. Guessing a 32+ character random key is not feasible."""
    if key in DEMO_KEYS:
        return "is a public demo key"
    if len(key) < MIN_KEY_LENGTH:
        return f"is shorter than {MIN_KEY_LENGTH} characters"
    if len(set(key)) < 8:
        return "repeats too few characters to be random"
    return None


CONFIG_ENV = "LOMBERK_CONFIG"
DEFAULT_CONFIG_PATH = "lomberk.yaml"
_warned_missing: set[str] = set()


def config_path() -> str:
    """Where the config is read from: $LOMBERK_CONFIG when set, else ./lomberk.yaml."""
    return os.environ.get(CONFIG_ENV) or DEFAULT_CONFIG_PATH


def load_config(path: str | None = None) -> LomberkConfig:
    """Reads `path`, else $LOMBERK_CONFIG, else ./lomberk.yaml.

    A file named by LOMBERK_CONFIG must exist: if it doesn't, startup is refused rather than
    running without the protected tables it was meant to load. A missing ./lomberk.yaml only
    warns (on stderr, once), because a first run with defaults is a normal way to try Lomberk.
    """
    env_path = os.environ.get(CONFIG_ENV)
    path = path or env_path or DEFAULT_CONFIG_PATH
    if not os.path.exists(path):
        if path == env_path:
            raise ValueError(f"{CONFIG_ENV} points at {path}, which does not exist. "
                             "Fix the path or unset it; Lomberk won't guess which tables to protect.")
        full = os.path.abspath(path)
        if full not in _warned_missing:
            _warned_missing.add(full)
            print(f"lomberk: no config at {full}, so defaults apply (no protected tables). "
                  f"Set {CONFIG_ENV} to your lomberk.yaml.", file=sys.stderr)
        return LomberkConfig()
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    return LomberkConfig(**data)


def config_error_message(e: Exception) -> str:
    """One line that names the bad key, for a validation or YAML error."""
    if isinstance(e, ValidationError):
        err = e.errors()[0]
        where = ".".join(str(p) for p in err["loc"]) or "top level"
        more = f" (and {e.error_count() - 1} more)" if e.error_count() > 1 else ""
        return f"{where}: {err['msg']}{more}"
    return str(e).splitlines()[0]


def pro_features(config: LomberkConfig) -> list[str]:
    """The configured features that need a Lomberk Pro license."""
    slack = os.environ.get("LOMBERK_SLACK_ENABLED", "").lower() == "true"
    return [name for name, on in (("SSO", bool(config.sso.issuer)), ("Slack approvals", slack),
                                  ("two-person approval", config.approvals.required > 1)) if on]


def quorum_without_identity_source(config: LomberkConfig) -> bool:
    """True if a >1 approval quorum is configured with no identity source. Admin-key and CLI
    approvals never count toward the quorum, so with neither SSO nor Slack every held checkpoint
    would be permanently un-approvable — a silent, self-inflicted deadlock caught at startup."""
    slack = os.environ.get("LOMBERK_SLACK_ENABLED", "").lower() == "true"
    return config.approvals.required > 1 and not config.sso.issuer and not slack
