"""Startup checks shared by the HTTP gateway (api.py) and the stdio MCP server (server.py)."""
import os

from lomberk.config import LomberkConfig, pro_features, quorum_without_identity_source
from lomberk.executor import UNDO_WINDOW_HOURS, LicenseActivationStore, LomberkExecutor


def resolve_plan(config: LomberkConfig) -> str:
    """'free', 'pro' or 'enterprise'. Raises LicenseError if Pro features are configured without a valid key."""
    needs_pro = pro_features(config)
    license_key = os.environ.get("LOMBERK_LICENSE_KEY")
    if not (needs_pro or license_key):
        return "free"
    try:
        from lomberk.ee.license import check_license
    except ImportError:  # a core-only install: nothing paid to turn on
        if needs_pro:
            raise ValueError(f"Startup Refusal: {', '.join(needs_pro)} need a Lomberk Pro license and the Pro package "
                             "(lomberk.ee), which this install doesn't have. Install the full lomberk package "
                             "or remove them from the config.") from None
        return "free"
    control_dsn = os.environ.get(config.database.admin_dsn_env)
    store = LicenseActivationStore(control_dsn) if license_key and control_dsn else None
    return check_license(license_key, needs_pro, store)


def check_config(config: LomberkConfig) -> None:
    if quorum_without_identity_source(config):
        raise ValueError("Startup Refusal: approvals.required > 1 needs an identity source (SSO issuer or Slack); "
                         "admin-key and CLI approvals never count toward the quorum, so held checkpoints would be un-approvable.")


def check_db_roles(admin_dsn: str, dsn: str) -> None:
    """The agent and control DSNs must be two distinct, non-superuser roles, on a current lomberk schema."""
    import psycopg
    with psycopg.connect(admin_dsn) as conn:
        control_user, control_super = conn.execute(
            "SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)").fetchone()
        # The newest column the code relies on: an install from before it can't hold or approve writes.
        schema_current = conn.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = to_regclass('lomberk.checkpoints') "
            "AND attname = 'required_approvals' AND NOT attisdropped)").fetchone()[0]
    with psycopg.connect(dsn) as conn:
        runtime_user, runtime_super = conn.execute(
            "SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)").fetchone()
    if not schema_current:
        raise ValueError("Startup Refusal: the lomberk schema in this database is missing or older than this gateway. "
                         "Run `lomberk init` again as the database owner (it upgrades in place, keeping checkpoints).")
    if control_user == runtime_user:
        raise ValueError("Startup Refusal: Admin DSN and Agent DSN must resolve to distinct database roles.")
    if control_super:
        raise ValueError("Startup Refusal: Admin role must not be a superuser.")
    if runtime_super:
        raise ValueError("Startup Refusal: Agent role must not be a superuser.")


def new_executor(config: LomberkConfig, admin_dsn: str, dsn: str, plan: str) -> LomberkExecutor:
    return LomberkExecutor(
        admin_dsn, dsn,
        max_rows_without_approval=config.limits.max_rows_without_approval,
        approval_timeout_minutes=config.agent.approval_timeout_minutes,
        protected_tables=config.protected_tables,
        statement_timeout_ms=config.limits.statement_timeout_ms,
        required_approvals=config.approvals.required,
        sensitive_columns=config.sensitive_columns,
        preview_writes=config.approvals.preview,
        undo_window_hours=UNDO_WINDOW_HOURS[plan],
    )
