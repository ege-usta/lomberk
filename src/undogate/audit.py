import json
import os
import logging
from datetime import datetime, timezone

# Configure standard logger to write JSON to a file or stream
logger = logging.getLogger("undogate_audit")
logger.setLevel(logging.INFO)

log_path = os.environ.get("UNDOGATE_AUDIT_LOG", "/tmp/undogate_audit.json")
handler = logging.FileHandler(log_path)
handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(handler)

def emit_audit_event(cp_id: int, public_id: str, sql: str, agent: str, status: str, ddl_plan: list = None, rows: int = 0):
    """Emit a SOC2/HIPAA compliant audit event for external SIEM (Datadog/Splunk)"""
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "undogate_transaction",
        "checkpoint_id": cp_id,
        "public_id": public_id,
        "agent": agent,
        "status": status,
        "rows_affected": rows,
        "sql_text": sql,
        "ddl_undo_plan_present": bool(ddl_plan)
    }
    logger.info(json.dumps(event))
