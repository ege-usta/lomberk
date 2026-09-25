import time
import random
from typing import Callable, Dict, Any

class RecoveryBudgetExhausted(Exception):
    def __init__(self, last_known_state: str, resume_id: str | None, operation_id: str):
        self.last_known_state = last_known_state
        self.resume_id = resume_id
        self.operation_id = operation_id
        super().__init__(f"Recovery budget exhausted. Last known state: {last_known_state}")

def execute_with_recovery(
    operation_id: str,
    submit_fn: Callable[[], Dict[str, Any]],
    status_fn: Callable[[str], str],
    max_retries: int = 5,
    base_delay: float = 0.5,
    max_delay: float = 5.0
) -> Dict[str, Any]:
    """
    submit_fn: A function that submits the operation and returns the result payload (e.g. from API/MCP)
    status_fn: A function that takes a public_id and returns the current status.
    """
    last_known_state = "unknown"
    resume_id = None
    last_res = None
    
    for attempt in range(max_retries + 1):
        try:
            res = submit_fn()
            last_res = res
            
            # Extract status from response (assuming array of results for API, or single for MCP)
            if "results" in res and len(res["results"]) > 0:
                first_res = res["results"][0]
                status = first_res.get("status")
                resume_id = first_res.get("checkpoint_id")
            else:
                status = res.get("status")
                resume_id = res.get("checkpoint_id") or res.get("public_id")
                
            last_known_state = status or last_known_state
            
            # If status is terminal (applied, failed, denied, undone) or needs explicit action (approval_required)
            if status in ["applied", "failed", "denied", "approval_required", "undone"]:
                return res
            
            # If status is 'approved', it means it's approved but not yet executed (or we lost the execution response)
            # We do NOT auto-execute it here. It requires manual intervention or a separate worker.
            if status == "approved":
                return res
                
        except Exception as e:
            # If there's an exception (like 502 unknown), we treat it as unknown
            # For HTTP 409 Conflict, submit_fn should raise it and we just let it propagate
            if hasattr(e, "status_code") and e.status_code == 409:
                raise
            last_known_state = "unknown"
            
        if attempt < max_retries:
            # Exponential backoff with jitter
            delay = min(max_delay, base_delay * (2 ** attempt))
            jitter = random.uniform(0, 0.1 * delay)
            time.sleep(delay + jitter)
            
    raise RecoveryBudgetExhausted(
        last_known_state=last_known_state,
        resume_id=resume_id,
        operation_id=operation_id
    )
