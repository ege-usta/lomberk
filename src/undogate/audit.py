import json
import os
import logging
from datetime import datetime, timezone

# Configure standard logger to write JSON to a file or stream
logger = logging.getLogger("undogate_audit")
logger.setLevel(logging.INFO)

# Audit lines contain full SQL text (may include PII): keep them owner-only, never in /tmp.
log_path = os.environ.get("UNDOGATE_AUDIT_LOG") or os.path.expanduser("~/.local/state/undogate/audit.jsonl")
os.makedirs(os.path.dirname(log_path) or ".", mode=0o700, exist_ok=True)
os.close(os.open(log_path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600))
handler = logging.FileHandler(log_path)
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

def audit(event: str, *, actor: str, public_id: str | None = None, **fields) -> None:
    """One JSON line per security-relevant decision, for shipping to a SIEM.

    event: denied | held | applied | failed | approved | rejected | expired | undone | undo_failed
    actor: who caused it (agent principal, or approver such as "cli:alice" / "api_admin").
    """
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": f"undogate.{event}",
        "actor": actor,
        "public_id": public_id,
        **fields,
    }
    logger.info(json.dumps(record, default=str))
