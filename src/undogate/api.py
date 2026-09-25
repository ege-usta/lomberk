import os
import sys

from fastapi import FastAPI, HTTPException, Request, Depends, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from contextlib import asynccontextmanager

from undogate.config import load_config
from undogate.executor import UndogateExecutor
from undogate.policy import PolicyEngine
from undogate.sql.classify import classify_sql
from undogate.sentinel import AISentinel

# Global references for lifespan
_executor_instance = None
_policy_engine_instance = None


# Immutable runtime config
_API_KEY = None
_ADMIN_KEY = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _executor_instance, _policy_engine_instance, _API_KEY, _ADMIN_KEY
    config = load_config()
    dsn = os.environ.get(config.database.agent_dsn_env)
    
    agent_key = os.environ.get("UNDOGATE_API_KEY")
    admin_key = os.environ.get("UNDOGATE_ADMIN_KEY")
    
    if not dsn:
        raise ValueError(f"Startup Refusal: Database DSN must be provided via {config.database.agent_dsn_env}.")
    if not agent_key or not admin_key:
        raise ValueError("Startup Refusal: Both UNDOGATE_API_KEY and UNDOGATE_ADMIN_KEY must be configured.")
    if agent_key == admin_key:
        raise ValueError("Startup Refusal: Agent and Admin keys must NOT be identical.")
        
    _API_KEY = agent_key
    _ADMIN_KEY = admin_key
        
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
            
        _executor_instance = UndogateExecutor(admin_dsn, dsn)
        _policy_engine_instance = PolicyEngine(config)
        yield
    finally:
        pass
        _executor_instance = None
        _policy_engine_instance = None

app = FastAPI(title="Undogate Enterprise API", lifespan=lifespan)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

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
    if api_key != _API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

def verify_admin_key(api_key: str = Security(api_key_header)):
    if not _ADMIN_KEY:
        raise HTTPException(status_code=500, detail="Configuration Error: Admin Key not loaded.")
    if not api_key:
        raise HTTPException(status_code=401, detail="Admin Key required")
    if api_key != _ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Invalid Admin Key")
    return api_key
from typing import Optional
class ExecuteRequest(BaseModel):
    sql: str
    agent_label: str = "agent"
    operation_id: Optional[str] = None

@app.post("/v1/execute")
def execute_query(
    req: ExecuteRequest, 
    api_key: str = Depends(verify_api_key),
    executor: UndogateExecutor = Depends(get_executor),
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
        exec_res = executor.execute(eval_result, req.agent_label)
        
        results.append({
            "sql": stmt.sql,
            "classification": stmt.stmt_class.value,
            "decision": eval_result.decision.value,
            "status": exec_res.status,
            "message": exec_res.message,
            "checkpoint_id": exec_res.public_id,
            "rows_affected": exec_res.rows_affected,
            "data": exec_res.data
        })
    return {"results": results}

@app.get("/v1/checkpoints/pending")
def list_pending_checkpoints(
    api_key: str = Depends(verify_admin_key),
    executor: UndogateExecutor = Depends(get_executor)
):
    import psycopg
    with psycopg.connect(executor.dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, public_id, sql_text, agent_label, created_at FROM undogate.list_pending_checkpoints()")
            rows = cur.fetchall()
            return [{"id": r[0], "public_id": r[1], "sql": r[2], "agent": r[3], "created_at": r[4]} for r in rows]


@app.get("/v1/checkpoints/{public_id}/status")
def check_checkpoint_status(
    public_id: str,
    api_key: str = Depends(verify_admin_key),
    executor: UndogateExecutor = Depends(get_executor)
):
    try:
        status = executor.check_status(public_id)
        if status == "not_found":
            raise HTTPException(status_code=404, detail="Token not found")
        return {"public_id": public_id, "status": status}
    except HTTPException:
        raise
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=502, content={"status": "outcome_unknown", "message": "Database unreachable"})

@app.post("/v1/checkpoints/{public_id}/approve")

def approve_checkpoint(
    public_id: str, 
    api_key: str = Depends(verify_admin_key),
    executor: UndogateExecutor = Depends(get_executor)
):
    try:
        res = executor.execute_pending(public_id)
        if res.status == "applied":
            return {"status": "approved", "rows_affected": res.rows_affected}
        elif res.status == "denied":
            return {"status": "denied", "message": res.message}
        elif res.status == "outcome_unknown":
            from fastapi.responses import JSONResponse
            return JSONResponse(status_code=502, content={"status": "outcome_unknown", "message": res.message, "public_id": res.public_id})
        elif res.status == "failed":
            raise HTTPException(status_code=400, detail=res.message)
        else:
            raise HTTPException(status_code=500, detail=f"Unexpected status: {res.status}")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/checkpoints/{public_id}/reject")
def reject_checkpoint(
    public_id: str, 
    api_key: str = Depends(verify_admin_key),
    executor: UndogateExecutor = Depends(get_executor)
):
    import psycopg
    with psycopg.connect(executor.dsn) as conn:
        with conn.cursor() as cur:
            try:
                cur.execute("SELECT undogate.reject_checkpoint(%s)", (public_id,))
            except Exception as e:
                raise HTTPException(status_code=404, detail="Token not found or not pending")
            conn.commit()

            return {"status": "denied"}
            
@app.get("/", include_in_schema=False)
def dashboard():
    from fastapi.responses import HTMLResponse
    html = """
    <html>
        <head><title>Undogate</title></head>
        <body style="font-family: sans-serif; padding: 2rem;">
            <h1>Undogate Enterprise Gateway</h1>
            <p style="color: #666;">UI Disabled for security. Please use the API or CLI.</p>
        </body>
    </html>
    """
    return HTMLResponse(content=html)
