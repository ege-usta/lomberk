import os

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    # A typo like `protected_table:` must fail startup, not silently disable protection.
    model_config = ConfigDict(extra="forbid")


class DatabaseConfig(_Strict):
    agent_dsn_env: str = "ROWBACK_AGENT_DSN"
    admin_dsn_env: str = "ROWBACK_ADMIN_DSN"

class LimitsConfig(_Strict):
    max_rows_without_approval: int = 100
    max_snapshot_rows: int = 1000000
    statement_timeout_ms: int = 15000
    trash_retention_days: int = 7

class AgentConfig(_Strict):
    allow_self_undo: bool = True
    approval_timeout_minutes: int = 30

class SlackConfig(_Strict):
    admin_allowlist: list[str] = Field(default_factory=list)
    team_allowlist: list[str] = Field(default_factory=list)
    # Channel the gateway posts pending approvals to. Unset = no built-in publisher.
    channel_id: str | None = None
    # Off by default: SQL literals may contain regulated data that must not leave for Slack.
    include_sql: bool = False

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

class RowbackConfig(_Strict):
    version: int = 1
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    protected_tables: list[str] = Field(default_factory=list)
    deny_patterns: list[str] = Field(default_factory=list)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    slack: SlackConfig = Field(default_factory=SlackConfig)
    sso: SsoConfig = Field(default_factory=SsoConfig)

def load_config(path: str = "rowback.yaml") -> RowbackConfig:
    if not os.path.exists(path):
        return RowbackConfig()
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return RowbackConfig(**data)
