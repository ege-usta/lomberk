import threading
import time

import pytest

from rowback.recovery import (
    IdMismatchError,
    RecoveryBudgetExhausted,
    TransientError,
    execute_with_recovery,
)


def test_recovery_input_validation():
    with pytest.raises(ValueError, match="timeout_seconds"):
        execute_with_recovery("op", lambda t: {}, lambda i, t: "x", timeout_seconds=-1)

    with pytest.raises(ValueError, match="Invalid delay"):
        execute_with_recovery("op", lambda t: {}, lambda i, t: "x", base_delay=-1)

def test_recovery_transient_retry():
    attempts = 0
    def failing_submit(t):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise TransientError("network drop")
        return {"results": [{"status": "applied", "checkpoint_id": "cp1", "operation_id": "op1"}]}

    res = execute_with_recovery("op1", failing_submit, lambda i, t: "x", timeout_seconds=1.0, base_delay=0.01)
    assert res.status == "applied"
    assert attempts == 3

def test_recovery_fatal_error_no_retry():
    def fatal_submit(t):
        raise ValueError("Auth Error 401")

    with pytest.raises(ValueError, match="Auth Error"):
        execute_with_recovery("op2", fatal_submit, lambda i, t: "x", timeout_seconds=1.0, base_delay=0.01)

def test_recovery_id_mismatch_rejected():
    def submit_wrong_id(t):
        return {"status": "applied", "operation_id": "wrong_op"}

    with pytest.raises(IdMismatchError):
        execute_with_recovery("expected_op", submit_wrong_id, lambda i, t: "x")

def test_recovery_timeout_passed_down():
    def submit(t):
        assert t > 0
        return {"status": "applied", "operation_id": "op"}

    res = execute_with_recovery("op", submit, lambda i, t: "x", timeout_seconds=5.0)
    assert res.status == "applied"

def test_recovery_late_completion():
    def late_submit(t):
        time.sleep(0.1) # Simulate delay
        return {"status": "applied", "operation_id": "op_late"}

    # We fake the clock so that after the first submit, deadline has passed
    fake_time = 0.0
    def clock():
        return fake_time

    def submit_and_advance(t):
        nonlocal fake_time
        fake_time = 2.0 # Jump past the 1.0 timeout
        return {"status": "applied", "operation_id": "op_late"}

    with pytest.raises(RecoveryBudgetExhausted) as exc:
        execute_with_recovery("op_late", submit_and_advance, lambda i, t: "x", timeout_seconds=1.0, base_delay=0.01, clock=clock)

    assert exc.value.late_result is not None
    assert exc.value.late_result.is_late is True
    assert exc.value.late_result.status == "applied"

def test_recovery_cancellation():
    event = threading.Event()
    event.set()

    with pytest.raises(RecoveryBudgetExhausted):
        execute_with_recovery("op", lambda t: {}, lambda i, t: "x", cancel_event=event)

def test_recovery_already_undone_is_terminal():
    def submit(t):
        return {"status": "already_undone", "operation_id": "op"}

    res = execute_with_recovery("op", submit, lambda i, t: "x")
    assert res.status == "already_undone"

def test_recovery_max_attempts():
    attempts = 0
    def submit(t):
        nonlocal attempts
        attempts += 1
        raise TransientError("x")

    with pytest.raises(RecoveryBudgetExhausted):
        execute_with_recovery("op", submit, lambda i, t: "x", max_attempts=3, base_delay=0.01)

    assert attempts == 3

def test_recovery_status_polling_after_known_id():
    submit_calls = 0
    status_calls = 0
    last_status_timeout = None

    def submit_fn(t):
        nonlocal submit_calls
        submit_calls += 1
        return {"status": "pending", "checkpoint_id": "known_id_123", "operation_id": "op"}

    def status_fn(resume_id, t):
        nonlocal status_calls, last_status_timeout
        status_calls += 1
        last_status_timeout = t
        assert resume_id == "known_id_123"
        if status_calls < 3:
            return "pending"
        return "applied"

    res = execute_with_recovery("op", submit_fn, status_fn, timeout_seconds=5.0, base_delay=0.1, max_delay=0.1)

    # submit should be called exactly once
    assert submit_calls == 1
    # status should be called exactly 3 times
    assert status_calls == 3
    # timeout must have decreased
    assert last_status_timeout < 5.0
    assert res.status == "applied"
    assert res.resume_id == "known_id_123"
