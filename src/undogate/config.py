import os

import yaml
from pydantic import BaseModel, ConfigDict, Field


class _Strict(BaseModel):
    # A typo like `protected_table:` must fail startup, not silently disable protection.
    model_config = ConfigDict(extra="forbid")


class DatabaseConfig(_Strict):
    agent_dsn_env: str = "UNDOGATE_AGENT_DSN"
    admin_dsn_env: str = "UNDOGATE_ADMIN_DSN"

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

class UndogateConfig(_Strict):
    version: int = 1
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    protected_tables: list[str] = Field(default_factory=list)
    deny_patterns: list[str] = Field(default_factory=list)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    slack: SlackConfig = Field(default_factory=SlackConfig)

def load_config(path: str = "undogate.yaml") -> UndogateConfig:
    if not os.path.exists(path):
        return UndogateConfig()
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}
    return UndogateConfig(**data)
