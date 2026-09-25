import time
import math
import random
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Any, Optional

@dataclass
class RecoveryResult:
    operation_id: str
    status: str
    resume_id: Optional[str] = None
    message: Optional[str] = None
    is_late: bool = False

class RecoveryBudgetExhausted(Exception):
    def __init__(self, last_known_state: str, resume_id: Optional[str], operation_id: str, late_result: Optional[RecoveryResult] = None):
        self.last_known_state = last_known_state
        self.resume_id = resume_id
        self.operation_id = operation_id
        self.late_result = late_result
        super().__init__(f"Recovery budget exhausted. Last known state: {last_known_state}")

class TransientError(Exception):
    pass

class IdMismatchError(Exception):
    pass

def execute_with_recovery(
    operation_id: str,
    submit_fn: Callable[[float], Dict[str, Any]],
    status_fn: Callable[[str, float], str],
    timeout_seconds: float = 15.0,
    base_delay: float = 0.5,
    max_delay: float = 5.0,
    max_attempts: int = 50,
    clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    cancel_event: Optional[threading.Event] = None
) -> RecoveryResult:
    
    if math.isnan(timeout_seconds) or math.isinf(timeout_seconds) or timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be a positive finite number")
    if base_delay <= 0 or max_delay <= 0 or base_delay > max_delay:
        raise ValueError("Invalid delay parameters")
    if max_attempts <= 0:
        raise ValueError("max_attempts must be positive")
        
    deadline = clock() + timeout_seconds
    last_known_state = "unknown"
    resume_id = None
    attempt = 0
    message = None
    
    while True:
        if cancel_event and cancel_event.is_set():
            raise RecoveryBudgetExhausted(last_known_state, resume_id, operation_id)
            
        remaining_time = deadline - clock()
        if remaining_time <= 0 or attempt >= max_attempts:
            break
        
        attempt += 1
        try:
            if not resume_id:
                res = submit_fn(remaining_time)
                
                if "results" in res:
                    if len(res["results"]) != 1:
                        raise ValueError(f"Expected exactly 1 result in array, got {len(res['results'])}")
                    item = res["results"][0]
                    status = item.get("status")
                    current_id = item.get("checkpoint_id") or item.get("public_id")
                    ret_op_id = item.get("operation_id")
                    message = item.get("message")
                else:
                    status = res.get("status")
                    current_id = res.get("checkpoint_id") or res.get("public_id")
                    ret_op_id = res.get("operation_id")
                    message = res.get("message")
                    
                if not status:
                    raise ValueError("Response missing status field.")
                
                if ret_op_id and ret_op_id != operation_id:
                    raise IdMismatchError(f"Response operation_id '{ret_op_id}' does not match requested '{operation_id}'")
                    
                last_known_state = status
                if current_id:
                    resume_id = current_id
            else:
                status = status_fn(resume_id, remaining_time)
                last_known_state = status
                
            is_terminal = status in ["applied", "undone", "already_undone", "failed", "denied", "approval_required", "approved"]
            
            late = clock() > deadline
            if is_terminal:
                if late:
                    late_res = RecoveryResult(operation_id=operation_id, status=status, resume_id=resume_id, message=message, is_late=True)
                    raise RecoveryBudgetExhausted(last_known_state, resume_id, operation_id, late_result=late_res)
                return RecoveryResult(operation_id=operation_id, status=status, resume_id=resume_id, message=message, is_late=False)
                
        except TransientError:
            pass
        except RecoveryBudgetExhausted:
            raise
        except Exception as e:
            raise e
            
        remaining_time = deadline - clock()
        if remaining_time <= 0:
            break
            
        delay = min(max_delay, base_delay * (2 ** (attempt - 1)))
        jitter = random.uniform(0, 0.1 * delay)
        sleep_time = min(delay + jitter, remaining_time)
        
        # If sleep is going to be interrupted by cancel_event
        if cancel_event:
            cancel_event.wait(sleep_time)
        else:
            sleeper(sleep_time)
        
    raise RecoveryBudgetExhausted(last_known_state, resume_id, operation_id)
