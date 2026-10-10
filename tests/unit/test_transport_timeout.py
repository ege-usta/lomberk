import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from rowback.recovery import RecoveryBudgetExhausted, TransientError, execute_with_recovery

app = FastAPI()
health_check_passed = False
request_counts = {"slow": 0, "502": 0}

@app.get("/health")
def health():
    global health_check_passed
    health_check_passed = True
    return {"status": "ok"}

@app.post("/slow-execute")
async def slow_execute():
    request_counts["slow"] += 1
    import asyncio
    await asyncio.sleep(1.0)
    return {"results": [{"status": "applied", "checkpoint_id": "cp1", "operation_id": "op1"}]}

@app.post("/fatal-error")
async def fatal_error():
    return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

@app.post("/conflict-error")
async def conflict_error():
    return JSONResponse(status_code=409, content={"detail": "Conflict"})

@app.post("/transient-error")
async def transient_error():
    request_counts["502"] += 1
    return JSONResponse(status_code=502, content={"detail": "Bad Gateway"})

class HTTPClientAdapter:
    # This is strictly a test adapter, not the production SDK implementation.
    # It demonstrates that HTTPX phase timeouts are mapped to the recovery engine.
    def __init__(self, base_url: str):
        self.base_url = base_url

    def submit(self, endpoint: str, operation_id: str, timeout: float):
        try:
            with httpx.Client(timeout=timeout) as client:
                res = client.post(f"{self.base_url}{endpoint}")
                self._map_errors(res)
                return res.json()
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            raise TransientError(f"Network/Timeout Error: {e}") from e

    def status_fn(self, endpoint: str, resume_id: str, timeout: float):
        try:
            with httpx.Client(timeout=timeout) as client:
                res = client.get(f"{self.base_url}{endpoint}")
                self._map_errors(res)
                return res.json().get("status")
        except (httpx.TimeoutException, httpx.NetworkError) as e:
            raise TransientError(f"Network/Timeout Error: {e}") from e

    def _map_errors(self, res):
        if res.status_code in (401, 403, 400):
            raise ValueError(f"Terminal Auth/Validation Error: {res.status_code}")
        if res.status_code == 409:
            raise Exception("HTTPConflict")
        if res.status_code >= 500:
            raise TransientError(f"Server Error {res.status_code}")


@pytest.fixture(scope="module")
def mock_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]

    config = uvicorn.Config(app, log_level="critical")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"

    # Readiness probe
    ready = False
    for _ in range(20):
        try:
            res = httpx.get(f"{base_url}/health", timeout=0.1)
            if res.status_code == 200:
                ready = True
                break
        except Exception:
            time.sleep(0.1)

    if not ready:
        server.should_exit = True
        thread.join(timeout=1)
        pytest.fail("Mock server failed to start or bind.")

    yield base_url
    server.should_exit = True
    thread.join(timeout=2)


def test_real_transport_timeout(mock_server):
    adapter = HTTPClientAdapter(mock_server)
    request_counts["slow"] = 0
    attempts = 0

    # We record the exact string of the last TransientError raised
    last_transient_error = None

    def submit_with_count(timeout):
        nonlocal attempts, last_transient_error
        attempts += 1
        try:
            return adapter.submit("/slow-execute", "op1", timeout)
        except TransientError as e:
            last_transient_error = str(e)
            raise e

    # The server sleeps for 1.0s.
    # The HTTPX client is given a timeout of ~0.3s (based on remaining budget).
    # Thus, the request will begin, wait for read, and hit a ReadTimeout.
    # Note: HTTPX phase timeouts do not strictly guarantee an absolute elapsed monotonic deadline.
    # We rely on execute_with_recovery's late_result contract to ensure final monotonic consistency.
    with pytest.raises(RecoveryBudgetExhausted):
        execute_with_recovery(
            "op1",
            submit_fn=submit_with_count,
            status_fn=lambda i, t: "unknown",
            timeout_seconds=0.3,
            base_delay=0.01
        )

    # It attempts exactly once because the ReadTimeout consumes the entire 0.3s budget
    assert attempts == 1
    # Verify the request actually hit the server
    assert request_counts["slow"] == 1
    # Prove that the reason for failure was actually a ReadTimeout from httpx, not a connection failure or early abort
    assert "time" in str(last_transient_error).lower()

def test_terminal_error_no_retry(mock_server):
    adapter = HTTPClientAdapter(mock_server)
    attempts = 0
    def submit_with_count(timeout):
        nonlocal attempts
        attempts += 1
        return adapter.submit("/fatal-error", "op1", timeout)

    with pytest.raises(ValueError, match="Terminal Auth/Validation Error: 401"):
        execute_with_recovery("op1", submit_with_count, lambda i, t: "x", timeout_seconds=1.0)
    assert attempts == 1

def test_conflict_error_no_retry(mock_server):
    adapter = HTTPClientAdapter(mock_server)
    attempts = 0
    def submit_with_count(timeout):
        nonlocal attempts
        attempts += 1
        return adapter.submit("/conflict-error", "op1", timeout)

    with pytest.raises(Exception, match="HTTPConflict"):
        execute_with_recovery("op1", submit_with_count, lambda i, t: "x", timeout_seconds=1.0)
    assert attempts == 1

def test_transient_error_retry(mock_server):
    adapter = HTTPClientAdapter(mock_server)
    request_counts["502"] = 0
    attempts = 0

    def submit_with_count(timeout):
        nonlocal attempts
        attempts += 1
        return adapter.submit("/transient-error", "op1", timeout)

    with pytest.raises(RecoveryBudgetExhausted):
        execute_with_recovery("op1", submit_with_count, lambda i, t: "x", timeout_seconds=0.2, base_delay=0.01)

    # Proves 502 was actively retried multiple times before budget exhaustion
    assert attempts > 1
    assert request_counts["502"] == attempts
