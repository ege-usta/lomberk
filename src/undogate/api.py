import os
import sys
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn

from undogate.config import load_config
from undogate.sql.classify import classify_sql
from undogate.policy import PolicyEngine
from undogate.executor import UndogateExecutor

app = FastAPI(title="Undogate Enterprise API", description="Drop-in REST Gateway for AI Agents")

config = load_config()
agent_dsn_env = config.database.agent_dsn_env
agent_dsn = os.environ.get(agent_dsn_env, os.environ.get("UNDOGATE_ADMIN_DSN"))

if not agent_dsn:
    print(f"Error: Database DSN must be provided via {agent_dsn_env} or UNDOGATE_ADMIN_DSN env var.", file=sys.stderr)
    sys.exit(1)

executor = UndogateExecutor(agent_dsn)
policy_engine = PolicyEngine(config)

class ExecuteRequest(BaseModel):
    sql: str
    agent_label: str = "http_agent"

@app.post("/v1/execute")
def execute_query(req: ExecuteRequest):
    """Universal execution endpoint for agents without MCP support."""
    try:
        statements = classify_sql(req.sql)
        if not statements:
             return {"status": "success", "message": "No statements executed"}
             
        results = []
        for stmt in statements:
            eval_result = policy_engine.evaluate(stmt)
            res = executor.execute(eval_result, agent_label=req.agent_label)
            
            results.append({
                "status": res.status,
                "checkpoint": res.public_id,
                "rows_affected": res.rows_affected,
                "message": res.message
            })
            
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/slack/interactive")
async def slack_interactive(request: Request):
    """Webhook for Slack Interactive buttons (Approve/Reject)"""
    form_data = await request.form()
    payload_str = form_data.get("payload")
    if not payload_str:
        return {"status": "ignored"}
        
    import json
    payload = json.loads(payload_str)
    
    actions = payload.get("actions", [])
    if not actions:
        return {"status": "no actions"}
        
    action_val = actions[0].get("value", "")
    if action_val.startswith("approve_"):
        token = action_val.replace("approve_", "")
        res = executor.execute_pending(token)
        return {"text": f"✅ Approved checkpoint {token}. Rows affected: {res.rows_affected}"}
    elif action_val.startswith("reject_"):
        token = action_val.replace("reject_", "")
        import psycopg
        with psycopg.connect(agent_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE undogate.checkpoints SET status = 'denied' WHERE public_id = %s", (token,))
        return {"text": f"❌ Rejected checkpoint {token}."}
        
    return {"status": "unknown"}

class JITRequest(BaseModel):
    agent_name: str
    tables: list[str]

@app.post("/v1/auth/jit")
def request_jit_credential(req: JITRequest):
    """(Enterprise) Request Ephemeral JIT credentials for the agent."""
    import psycopg
    import secrets
    
    password = secrets.token_urlsafe(16)
    role_name = f"jit_{req.agent_name}_{secrets.token_hex(4)}"
    
    try:
        with psycopg.connect(agent_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                # Create role valid for 5 minutes
                cur.execute(f"CREATE ROLE {role_name} WITH LOGIN PASSWORD '{password}' VALID UNTIL 'now + 5 minutes'")
                
                # Grant access to specific tables
                for table in req.tables:
                    # Very basic injection protection for table names
                    if not table.replace("_", "").isalnum():
                        continue
                    cur.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON public.{table} TO {role_name}")
                    
        return {
            "status": "success",
            "role": role_name,
            "password": password,
            "expires_in": "5 minutes",
            "message": "Use these credentials to connect. They will self-destruct in 5 minutes."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
