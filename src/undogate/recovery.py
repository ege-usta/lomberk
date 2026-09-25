import time
import random
from typing import Callable, Dict, Any, Tuple

class RecoveryBudgetExhausted(Exception):
    def __init__(self, last_known_state: str, resume_id: str | None, operation_id: str):
        self.last_known_state = last_known_state
        self.resume_id = resume_id
        self.operation_id = operation_id
        super().__init__(f"Recovery budget exhausted. Last known state: {last_known_state}")

class TransientError(Exception):
    pass

def execute_with_recovery(
    operation_id: str,
    submit_fn: Callable[[], Dict[str, Any]],
    status_fn: Callable[[str], str],
    timeout_seconds: float = 15.0,
    base_delay: float = 0.5,
    max_delay: float = 5.0,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep
) -> Dict[str, Any]:
    
    deadline = clock() + timeout_seconds
    last_known_state = "unknown"
    resume_id = None
    last_res = None
    attempt = 0
    
    while clock() < deadline:
        attempt += 1
        try:
            if not resume_id:
                # We don't have a public ID yet; submit or safely look up by operation_id
                res = submit_fn()
                last_res = res
                
                if "results" in res:
                    if len(res["results"]) != 1:
                        raise ValueError(f"Expected exactly 1 result in array, got {len(res['results'])}")
                    item = res["results"][0]
                    status = item.get("status")
                    current_id = item.get("checkpoint_id")
                else:
                    status = res.get("status")
                    current_id = res.get("checkpoint_id") or res.get("public_id")
                    
                if not status:
                    raise ValueError("Response missing status field.")
                    
                last_known_state = status
                if current_id:
                    resume_id = current_id
            else:
                # We have a public ID; use status_fn to poll
                status = status_fn(resume_id)
                last_known_state = status
                
                if last_res is None:
                    last_res = {"results": [{"status": status, "checkpoint_id": resume_id}]}
                elif "results" in last_res:
                    last_res["results"][0]["status"] = status
                else:
                    last_res["status"] = status
                    
            if status in ["applied", "undone", "already_undone", "failed", "denied", "approval_required", "approved"]:
                return last_res
                
        except TransientError:
            pass
        except Exception as e:
            # Re-raise any non-transient configuration/logic/auth/payload errors
            raise e
            
        remaining_time = deadline - clock()
        if remaining_time <= 0:
            break
            
        delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
        jitter = random.uniform(0, 0.1 * delay)
        sleep_time = min(delay + jitter, remaining_time)
        sleeper(sleep_time)
        
    raise RecoveryBudgetExhausted(
        last_known_state=last_known_state,
        resume_id=resume_id,
        operation_id=operation_id
    )
