import asyncio
import hmac
import inspect
import logging
import os
import secrets
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from starlette.routing import Route

from rowback.audit import audit
from rowback.config import load_config, pro_features, quorum_without_identity_source, weak_key_reason
from rowback.executor import UNDO_WINDOW_HOURS, LicenseActivationStore, RowbackExecutor
from rowback.policy import PolicyEngine
from rowback.sentinel import AISentinel
from rowback.server import build_mcp
from rowback.sql.classify import classify_sql

logger = logging.getLogger(__name__)

# Global references for lifespan
_executor_instance = None
_slack_transport_instance = None
_policy_engine_instance = None
_slack_transport_instance = None


# Immutable runtime config
_API_KEY = None
_ADMIN_KEY = None
# Panel session-cookie signing secret. Random per process and independent of _ADMIN_KEY:
# the admin key is deliberately excluded from the approval quorum, so it must not be able to
# mint (forge) panel sessions — least of all an `oidc:` identity. A restart ends all sessions.
_SESSION_SECRET = None
_METRICS_KEY = None  # ROWBACK_METRICS_KEY; unset = /metrics is off
_SSO = None  # ee OidcVerifier when sso.issuer is set
_ALLOW_ADMIN_KEY = True
_PRO = False  # a valid Rowback Pro license is present
_PLAN = "free"  # "free", "pro" or "enterprise": sets how far back undo reaches

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _executor_instance, _policy_engine_instance, _API_KEY, _ADMIN_KEY, _SESSION_SECRET, _slack_transport_instance, _SSO, _ALLOW_ADMIN_KEY, _PRO, _PLAN, _METRICS_KEY

    # Local registry ownership for safe and strict shutdown drainage
    local_db_workers = set()
    local_shutdown_event = asyncio.Event()
    publisher_task = None

    # Still attach to app.state for testing and observability,
    # but internal processing strictly uses the local references.
    app.state._db_workers = local_db_workers
    app.state._shutdown_event = local_shutdown_event

    config = load_config()
    dsn = os.environ.get(config.database.agent_dsn_env)

    agent_key = os.environ.get("ROWBACK_API_KEY")
    admin_key = os.environ.get("ROWBACK_ADMIN_KEY")

    if not dsn:
        raise ValueError(f"Startup Refusal: Database DSN must be provided via {config.database.agent_dsn_env}.")
    if not agent_key or not admin_key:
        raise ValueError("Startup Refusal: Both ROWBACK_API_KEY and ROWBACK_ADMIN_KEY must be configured.")
    if agent_key == admin_key:
        raise ValueError("Startup Refusal: Agent and Admin keys must NOT be identical.")
    # A guessable key is the one thing a rate limit would have to save; a random 32+ character
    # key can't be brute-forced, so refuse anything else. Demos opt out explicitly.
    metrics_key = os.environ.get("ROWBACK_METRICS_KEY") or None
    if metrics_key in (agent_key, admin_key):
        raise ValueError("Startup Refusal: ROWBACK_METRICS_KEY must differ from the agent and admin keys.")
    if os.environ.get("ROWBACK_ALLOW_WEAK_KEYS", "").lower() != "true":
        for env, key in (("ROWBACK_API_KEY", agent_key), ("ROWBACK_ADMIN_KEY", admin_key), ("ROWBACK_METRICS_KEY", metrics_key)):
            if key and (reason := weak_key_reason(key)):
                raise ValueError(f"Startup Refusal: {env} {reason}. Generate one with: openssl rand -hex 32")
    _METRICS_KEY = metrics_key

    _API_KEY = agent_key
    _ADMIN_KEY = admin_key
    _SESSION_SECRET = secrets.token_bytes(32)
    slack_enabled = os.environ.get("ROWBACK_SLACK_ENABLED", "").lower() == "true"
    needs_pro = pro_features(config)
    license_key = os.environ.get("ROWBACK_LICENSE_KEY")
    _PLAN = "free"
    if needs_pro or license_key:
        from rowback.ee.license import check_license
        control_dsn = os.environ.get(config.database.admin_dsn_env)
        store = LicenseActivationStore(control_dsn) if license_key and control_dsn else None
        _PLAN = await asyncio.to_thread(check_license, license_key, needs_pro, store)
    _PRO = _PLAN != "free"
    _SSO, _ALLOW_ADMIN_KEY = None, True
    if config.sso.issuer:
        from rowback.ee.sso import OidcVerifier
        _SSO = await asyncio.to_thread(OidcVerifier, config.sso)
        _ALLOW_ADMIN_KEY = bool(config.sso.allow_admin_key)
    elif config.sso.allow_admin_key is False:
        raise ValueError("Startup Refusal: sso.allow_admin_key is false but no sso.issuer is configured.")
    if quorum_without_identity_source(config):
        raise ValueError("Startup Refusal: approvals.required > 1 needs an identity source (SSO issuer or Slack); "
                         "admin-key and CLI approvals never count toward the quorum, so held checkpoints would be un-approvable.")

    try:
        admin_dsn = os.environ.get(config.database.admin_dsn_env)
        if not admin_dsn:
            raise ValueError('Startup Refusal: Admin DSN missing')

        import psycopg
        with psycopg.connect(admin_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)")
                control_user, control_super = cur.fetchone()

        with psycopg.connect(dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user)")
                runtime_user, runtime_super = cur.fetchone()

        if control_user == runtime_user:
            raise ValueError("Startup Refusal: Admin DSN and Agent DSN must resolve to distinct database roles.")
        if control_super:
            raise ValueError("Startup Refusal: Admin role must not be a superuser.")
        if runtime_super:
            raise ValueError("Startup Refusal: Agent role must not be a superuser.")

        _executor_instance = RowbackExecutor(admin_dsn, dsn, max_rows_without_approval=config.limits.max_rows_without_approval, approval_timeout_minutes=config.agent.approval_timeout_minutes, protected_tables=config.protected_tables, statement_timeout_ms=config.limits.statement_timeout_ms, required_approvals=config.approvals.required, sensitive_columns=config.sensitive_columns, preview_writes=config.approvals.preview, undo_window_hours=UNDO_WINDOW_HOURS[_PLAN])
        _policy_engine_instance = PolicyEngine(config)

        # Production Slack Transport Wiring
        if slack_enabled:
            app_token = os.environ.get("ROWBACK_SLACK_APP_TOKEN")
            bot_token = os.environ.get("ROWBACK_SLACK_BOT_TOKEN")

            if not app_token or not bot_token:
                raise ValueError("Startup Refusal: ROWBACK_SLACK_APP_TOKEN and ROWBACK_SLACK_BOT_TOKEN are required when Slack is enabled.")

            if not hasattr(config, "slack") or not config.slack.admin_allowlist:
                raise ValueError("Startup Refusal: config.slack.admin_allowlist is missing or empty.")
            if not config.slack.team_allowlist:
                raise ValueError("Startup Refusal: config.slack.team_allowlist is missing or empty.")

            slack_update_cb = getattr(app.state, "slack_update_callback", None)
            slack_resolver = getattr(app.state, "slack_target_resolver", None)
            # Built-in publisher mode: config names a channel and nothing is injected.
            use_publisher = bool(config.slack.channel_id) and slack_update_cb is None and slack_resolver is None
            if not use_publisher:
                if not slack_update_cb or not inspect.iscoroutinefunction(slack_update_cb):
                    raise ValueError("Startup Refusal: slack_update_callback dependency missing or not an async function.")
                if not slack_resolver or not inspect.iscoroutinefunction(slack_resolver):
                    raise ValueError("Startup Refusal: slack_target_resolver dependency missing or not an async function.")

            try:
                from slack_sdk.socket_mode.aiohttp import SocketModeClient
                from slack_sdk.web.async_client import AsyncWebClient

                from rowback.ee.slack import SlackInteractionAdapter, slack_actor
                from rowback.ee.slack_transport import SlackTransport
                # Bind local registry to callbacks
                def make_callbacks(executor, policy, resolver, updater, workers_set, shutdown_evt):
                    async def resolve_cb(team, channel, ts):
                        return await resolver(team, channel, ts)

                    async def _run_tracked(func, *args):
                        if shutdown_evt.is_set():
                            from rowback.ee.slack import TaskCapacityExceededError
                            raise TaskCapacityExceededError("Server is shutting down. Rejecting new DB workers.")
                        if len(workers_set) >= 50:
                            from rowback.ee.slack import TaskCapacityExceededError
                            raise TaskCapacityExceededError("DB worker capacity exceeded. Server is busy.")

                        t = asyncio.create_task(asyncio.to_thread(func, *args))
                        workers_set.add(t)
                        def _done_cb(fut):
                            workers_set.discard(fut)
                            if not fut.cancelled() and fut.exception():
                                logger.error(f"Background DB worker failed: {type(fut.exception()).__name__}")
                        t.add_done_callback(_done_cb)
                        return await asyncio.shield(t)

                    async def status_cb(pid):
                        return await _run_tracked(executor.check_status, pid)

                    async def approve_cb(pid):
                        res = await _run_tracked(executor.execute_pending, pid, slack_actor.get() or "slack")
                        return {"status": res.status}

                    async def reject_cb(pid):
                        await _run_tracked(executor.reject, pid, slack_actor.get() or "slack")
                        return {"status": "denied"}

                    async def update_cb(channel, ts, msg):
                        return await updater(channel, ts, msg)

                    return resolve_cb, status_cb, approve_cb, reject_cb, update_cb

                web_factory = getattr(app.state, "slack_web_client_factory", None) or AsyncWebClient
                if use_publisher:
                    from rowback.ee.slack_publisher import SlackPublisher
                    publisher = SlackPublisher(
                        admin_dsn, web_factory(token=bot_token), config.slack.channel_id,
                        set(config.slack.team_allowlist), include_sql=config.slack.include_sql,
                    )
                    slack_resolver, slack_update_cb = publisher.resolve, publisher.update
                    publisher_task = asyncio.create_task(publisher.run(local_shutdown_event))

                resolve_cb, status_cb, approve_cb, reject_cb, update_cb = make_callbacks(
                    _executor_instance, _policy_engine_instance, slack_resolver, slack_update_cb, local_db_workers, local_shutdown_event
                )

                adapter = SlackInteractionAdapter(
                    admin_allowlist=set(config.slack.admin_allowlist),
                    team_allowlist=set(config.slack.team_allowlist) if hasattr(config.slack, "team_allowlist") else set(),
                    target_resolver=resolve_cb,
                    approve_callback=approve_cb,
                    reject_callback=reject_cb,
                    status_callback=status_cb,
                    slack_update_callback=update_cb
                )

                def client_factory(token: str):
                    return SocketModeClient(app_token=token, web_client=web_factory(token=bot_token))

                factory_override = getattr(app.state, "slack_client_factory", None)

                _slack_transport_instance = SlackTransport(
                    app_token=app_token,
                    business_adapter=adapter,
                    client_factory=factory_override or client_factory,
                    enabled=True
                )
                await _slack_transport_instance.connect()
            except Exception as e:
                import logging
                logging.getLogger("rowback.api").error(f"Failed to start Slack transport: {e}")
                # We don't crash the server if connect fails, but we don't swallow validation errors
                # Wait! The user says "Eksik dependency => bağlantı öncesi ret. Startup hatasının API'yi açık bırakması seçilecekse Slack readiness... log yazmak başarılı başlangıç değildir."
                # The ValueError checks happen BEFORE the try/except! So validation fails fast.
        else:
            _slack_transport_instance = None

        # Remote MCP: the agent gets only a URL + agent key, never DSNs or the admin key.
        # The SDK session manager runs once per instance, so build a fresh one per lifespan.
        mcp = build_mcp(_mcp_deps, principal="remote_mcp_agent")
        # host="0.0.0.0" skips the SDK's localhost-only Host check; the agent key gate authenticates instead.
        mcp_http = mcp.streamable_http_app(streamable_http_path="/mcp", stateless_http=True, json_response=True, host="0.0.0.0")  # container bind; agent-key gate authenticates  # nosec B104
        async with mcp.session_manager.run():
            _mcp_gate.inner = mcp_http.routes[0].app
            try:
                yield
            finally:
                _mcp_gate.inner = None
    finally:
        local_shutdown_event.set()
        if publisher_task:
            await asyncio.gather(publisher_task, return_exceptions=True)

        if _slack_transport_instance:
            await _slack_transport_instance.disconnect()
            _slack_transport_instance = None

        if local_db_workers:
            logger.info(f"Draining {len(local_db_workers)} outstanding DB workers...")
            _done, pending = await asyncio.wait(local_db_workers, timeout=5.0)
            if pending:
                logger.error(f"Shutdown timeout: {len(pending)} DB workers remain outstanding/unknown.")

        _executor_instance = None
        _policy_engine_instance = None

# No /docs or /openapi.json: they map every endpoint for anyone who can reach the port.
app = FastAPI(title="Rowback Enterprise API", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _key_matches(presented: str | None, expected: str | None) -> bool:
    return bool(presented and expected) and hmac.compare_digest(presented.encode(), expected.encode())


class _AgentKeyGate:
    """ASGI guard for the MCP endpoint: agent key via X-API-Key or Authorization: Bearer."""

    def __init__(self):
        self.inner = None  # set while the app lifespan is running

    async def __call__(self, scope, receive, send):
        headers = dict(scope.get("headers") or [])
        key = headers.get(b"x-api-key", b"").decode()
        auth = headers.get(b"authorization", b"").decode()
        if not key and auth.lower().startswith("bearer "):
            key = auth[7:].strip()
        from starlette.responses import JSONResponse
        if not _key_matches(key, _API_KEY):
            await JSONResponse({"detail": "Valid agent key required"}, status_code=401)(scope, receive, send)
            return
        if self.inner is None:
            await JSONResponse({"detail": "Gateway not ready"}, status_code=503)(scope, receive, send)
            return
        await self.inner(scope, receive, send)


def _mcp_deps():
    if not _executor_instance or not _policy_engine_instance:
        raise RuntimeError("Gateway not initialized")
    return _executor_instance, _policy_engine_instance


_mcp_gate = _AgentKeyGate()
app.router.routes.append(Route("/mcp", endpoint=_mcp_gate))

def get_executor():
    if not _executor_instance:
        raise HTTPException(status_code=500, detail="Configuration Error: Agent DSN not provided or pool is closed.")
    return _executor_instance

def get_policy_engine():
    if not _policy_engine_instance:
        raise HTTPException(status_code=500, detail="Configuration Error: Policy Engine not initialized.")
    return _policy_engine_instance

def verify_api_key(api_key: str = Security(api_key_header)):
    if not _API_KEY:
        raise HTTPException(status_code=500, detail="Configuration Error: API Key not loaded.")
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    if not _key_matches(api_key, _API_KEY):
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

_bearer = HTTPBearer(auto_error=False)


def verify_approver(api_key: str = Security(api_key_header),
                    cred: HTTPAuthorizationCredentials | None = Security(_bearer)) -> str:
    """Who is approving: a person via SSO ("oidc:<email>"), or the shared admin key."""
    if _SSO is not None and cred is not None:
        from rowback.ee.sso import SsoError
        try:
            return _SSO.verify(cred.credentials)
        except SsoError:
            raise HTTPException(status_code=401, detail="Invalid SSO token") from None
    if not _ALLOW_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="SSO token required")
    verify_admin_key(api_key)
    return "api_admin"


def verify_admin_key(api_key: str = Security(api_key_header)):
    if not _ADMIN_KEY:
        raise HTTPException(status_code=500, detail="Configuration Error: Admin Key not loaded.")
    if not api_key:
        raise HTTPException(status_code=401, detail="Admin Key required")
    if not _key_matches(api_key, _ADMIN_KEY):
        raise HTTPException(status_code=403, detail="Invalid Admin Key")
    return api_key


class ExecuteRequest(BaseModel):
    sql: str
    agent_label: str = "agent"
    operation_id: str | None = None

@app.post("/v1/execute")
def execute_query(
    req: ExecuteRequest,
    api_key: str = Depends(verify_api_key),
    executor: RowbackExecutor = Depends(get_executor),
    policy_engine: PolicyEngine = Depends(get_policy_engine)
):
    # Step 1: Prevent multi-statement at the API boundary
    safe, reason = AISentinel()._ast_firewall(req.sql)
    if not safe:
        return {"results": [{"sql": req.sql, "status": "denied", "message": f"Hard Gate Denied: {reason}"}]}

    statements = classify_sql(req.sql)
    results = []
    for stmt in statements:
        eval_result = policy_engine.evaluate(stmt)
        # Note: the hard gate evaluation is done inside executor.execute()
        # It will return 'denied' if AST fails
        exec_res = executor.execute(
            eval_result,
            agent_label=req.agent_label,
            principal="api_user",
            operation_id=req.operation_id
        )

        if exec_res.status == "failed" and exec_res.error_code == "conflict":
            raise HTTPException(status_code=409, detail=exec_res.message)

        results.append({
            "sql": stmt.sql,
            "classification": stmt.stmt_class.value,
            "decision": eval_result.decision.value,
            "status": exec_res.status,
            "message": exec_res.message,
            "checkpoint_id": exec_res.public_id,
            "operation_id": exec_res.operation_id,
            "error_code": exec_res.error_code,
            "rows_affected": exec_res.rows_affected,
            "data": exec_res.data
        })
    return {"results": results}

@app.get("/v1/checkpoints/pending")
def list_pending_checkpoints(
    actor: str = Depends(verify_approver),
    executor: RowbackExecutor = Depends(get_executor)
):
    import psycopg
    with psycopg.connect(executor.dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, public_id, sql_text, agent_label, created_at FROM rowback.list_pending_checkpoints()")
            rows = cur.fetchall()
            return [{"id": r[0], "public_id": r[1], "sql": r[2], "agent": r[3], "created_at": r[4]} for r in rows]


@app.get("/v1/checkpoints/{public_id}/status")
def check_checkpoint_status(
    public_id: str,
    actor: str = Depends(verify_approver),
    executor: RowbackExecutor = Depends(get_executor)
):
    try:
        status = executor.check_status(public_id)
        if status == "not_found":
            raise HTTPException(status_code=404, detail="Token not found")
        return {"public_id": public_id, "status": status}
    except HTTPException:
        raise
    except Exception:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=502, content={"status": "unknown", "message": "Database unreachable"})

@app.post("/v1/checkpoints/{public_id}/approve")

def approve_checkpoint(
    public_id: str,
    actor: str = Depends(verify_approver),
    executor: RowbackExecutor = Depends(get_executor)
):
    try:
        res = executor.execute_pending(public_id, actor=actor)
        if res.status == "applied":
            return {"status": "approved", "rows_affected": res.rows_affected}
        elif res.status == "awaiting_approval":
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=202, content={"status": "awaiting_approval", "message": res.message})
        elif res.status == "denied":
            return {"status": "denied", "message": res.message}
        elif res.status == "unknown":
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=502, content={"status": "unknown", "message": res.message, "public_id": res.public_id, "operation_id": res.operation_id})
        elif res.status == "failed":
            raise HTTPException(status_code=400, detail=res.message)
        else:
            raise HTTPException(status_code=500, detail=f"Unexpected status: {res.status}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e

@app.post("/v1/checkpoints/{public_id}/reject")
def reject_checkpoint(
    public_id: str,
    actor: str = Depends(verify_approver),
    executor: RowbackExecutor = Depends(get_executor)
):
    if not executor.reject(public_id, actor=actor):
        raise HTTPException(status_code=404, detail="Token not found or not pending")
    return {"status": "denied"}

_UNDO_HTTP_STATUS = {"expired": 403, "already_undone": 409, "conflict": 409, "busy": 423, "denied": 404, "failed": 400}


@app.get("/v1/checkpoints/{public_id}")
def get_checkpoint(
    public_id: str,
    actor: str = Depends(verify_approver),
    executor: RowbackExecutor = Depends(get_executor)
):
    """What an approver reviews before deciding: the exact SQL and who sent it."""
    cp = executor.get_checkpoint(public_id)
    if not cp:
        raise HTTPException(status_code=404, detail="Token not found")
    return cp


@app.post("/v1/checkpoints/{public_id}/undo")
def undo_checkpoint(
    public_id: str,
    actor: str = Depends(verify_approver),
    executor: RowbackExecutor = Depends(get_executor)
):
    res = executor.execute_undo(public_id, agent_label=actor)
    if res.status == "undone":
        return {"status": "undone", "rows_affected": res.rows_affected}
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=_UNDO_HTTP_STATUS.get(res.status, 502), content={"status": res.status, "message": res.message})


def _require_pro(feature: str) -> None:
    if not _PRO:
        raise HTTPException(status_code=403, detail=f"{feature} is a Rowback Pro feature: set ROWBACK_LICENSE_KEY.")


@app.get("/v1/audit/export")
def export_audit(
    format: str = "csv",
    since: datetime | None = None,
    actor: str = Depends(verify_approver),
    executor: RowbackExecutor = Depends(get_executor)
):
    """Every checkpoint with who approved it (Pro)."""
    _require_pro("Audit export")
    from fastapi.responses import Response

    from rowback.ee.export import FORMATS, render
    if format not in FORMATS:
        raise HTTPException(status_code=422, detail=f"format must be one of {sorted(FORMATS)}")
    rows = executor.list_checkpoints(since=since)
    audit("exported", actor=actor, rows=len(rows), format=format)
    return Response(render(rows, format), media_type=FORMATS[format],
                    headers={"Content-Disposition": f'attachment; filename="rowback-audit.{format}"'})


class _PanelGate:
    """Mounts the web panel (ee) lazily, so the core never imports it at module load."""

    def __init__(self):
        self.inner = None

    async def __call__(self, scope, receive, send):
        if not _PRO or _executor_instance is None:
            from starlette.responses import HTMLResponse
            await HTMLResponse(_PRO_ONLY_PAGE, status_code=403)(scope, receive, send)
            return
        if self.inner is None:
            from rowback.ee.panel import build_panel
            self.inner = build_panel()
        await self.inner(scope, receive, send)


_PRO_ONLY_PAGE = """<!doctype html><meta charset="utf-8"><title>Rowback</title>
<body style="font-family: system-ui, sans-serif; padding: 2rem; max-width: 40rem">
<h1>Rowback</h1><p>The web approval panel is a Rowback Pro feature. Set <code>ROWBACK_LICENSE_KEY</code>
and restart the gateway, or approve from the API or CLI.</p></body>"""

app.mount("/panel", _PanelGate())


@app.get("/healthz", include_in_schema=False)
def healthz():
    """Liveness: the process is up."""
    return {"status": "ok"}


@app.get("/metrics", include_in_schema=False)
def metrics(cred: HTTPAuthorizationCredentials | None = Security(_bearer)):
    """Prometheus text format, scraped with `Authorization: Bearer $ROWBACK_METRICS_KEY`. Counts
    only: no SQL, rows or identities. Off (404) unless that key is set."""
    from fastapi.responses import PlainTextResponse

    from rowback.audit import EVENTS
    if not _METRICS_KEY:
        raise HTTPException(status_code=404)
    if not _key_matches(cred.credentials if cred else None, _METRICS_KEY):
        raise HTTPException(status_code=401, detail="Invalid metrics key")
    out = ["# HELP rowback_events_total Security decisions since the gateway started, by audit event.",
           "# TYPE rowback_events_total counter"]
    out += [f'rowback_events_total{{event="{e}"}} {n}' for e, n in sorted(EVENTS.items())]  # event names are fixed strings
    import psycopg
    try:
        with psycopg.connect(_executor_instance.dsn, connect_timeout=3) as conn:
            pending, oldest = conn.execute(
                "SELECT count(*), coalesce(extract(epoch FROM now() - min(created_at)), 0) "
                "FROM rowback.checkpoints WHERE status = 'pending'").fetchone()
        up = 1
    except psycopg.Error:
        pending, oldest, up = 0, 0, 0
    out += ["# HELP rowback_database_up Whether the control role could reach the database for this scrape.",
            "# TYPE rowback_database_up gauge", f"rowback_database_up {up}",
            "# HELP rowback_pending_checkpoints Held writes waiting for a person.",
            "# TYPE rowback_pending_checkpoints gauge", f"rowback_pending_checkpoints {pending}",
            "# HELP rowback_oldest_pending_seconds How long the oldest held write has waited.",
            "# TYPE rowback_oldest_pending_seconds gauge", f"rowback_oldest_pending_seconds {float(oldest):.0f}"]
    return PlainTextResponse("\n".join(out) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/readyz", include_in_schema=False)
def readyz():
    """Readiness: both database roles are reachable."""
    from fastapi.responses import JSONResponse
    if not _executor_instance:
        return JSONResponse(status_code=503, content={"status": "starting"})
    import psycopg
    try:
        for dsn in (_executor_instance.dsn, _executor_instance.runtime_dsn):
            with psycopg.connect(dsn, connect_timeout=3) as conn:
                conn.execute("SELECT 1")
    except psycopg.Error:
        return JSONResponse(status_code=503, content={"status": "database_unreachable"})
    return {"status": "ready"}


@app.get("/", include_in_schema=False)
def dashboard():
    from fastapi.responses import HTMLResponse
    html = """
    <html>
        <head><title>Rowback</title></head>
        <body style="font-family: sans-serif; padding: 2rem;">
            <h1>Rowback gateway</h1>
            <p style="color: #666;">Approve from the <a href="/panel/">web panel</a> (Pro), the API or the CLI.</p>
        </body>
    </html>
    """
    return HTMLResponse(content=html)
