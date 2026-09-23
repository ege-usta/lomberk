import os
import sys

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from undogate.config import load_config
from undogate.executor import UndogateExecutor
from undogate.policy import PolicyEngine
from undogate.sql.classify import classify_sql

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
    import secrets

    import psycopg
    
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

import psycopg
from fastapi.responses import HTMLResponse


@app.get("/v1/checkpoints")
def get_checkpoints():
    """Get all checkpoints for the dashboard."""
    try:
        with psycopg.connect(agent_dsn) as conn:
            with conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
                cur.execute("SELECT id, public_id, created_at, agent_label, sql_text, classification, decision, status, rows_affected, hash FROM undogate.checkpoints ORDER BY id DESC LIMIT 50")
                return {"checkpoints": cur.fetchall()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/v1/checkpoints/{public_id}/approve")
def approve_checkpoint(public_id: str):
    res = executor.execute_pending(public_id)
    return {"status": res.status, "message": res.message, "rows_affected": res.rows_affected}

@app.post("/v1/checkpoints/{public_id}/reject")
def reject_checkpoint(public_id: str):
    try:
        with psycopg.connect(agent_dsn, autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE undogate.checkpoints SET status = 'denied' WHERE public_id = %s", (public_id,))
        return {"status": "denied", "message": "Checkpoint rejected."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Undogate Control Plane</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-slate-900 text-slate-200 font-sans p-8">
        <div class="max-w-6xl mx-auto">
            <h1 class="text-3xl font-bold text-white mb-2">Undogate Control Plane</h1>
            <p class="text-slate-400 mb-8">Enterprise AI Agent Security Gateway</p>
            
            <div class="bg-slate-800 rounded-lg shadow-xl overflow-hidden border border-slate-700">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr class="bg-slate-950 border-b border-slate-700 text-sm">
                            <th class="p-4 font-semibold text-slate-300">Status</th>
                            <th class="p-4 font-semibold text-slate-300">Token</th>
                            <th class="p-4 font-semibold text-slate-300">Agent</th>
                            <th class="p-4 font-semibold text-slate-300">SQL / Intent</th>
                            <th class="p-4 font-semibold text-slate-300">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="checkpoints-body">
                        <tr><td colspan="5" class="p-4 text-center">Loading...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <script>
            async function fetchCheckpoints() {
                const res = await fetch('/v1/checkpoints');
                const data = await res.json();
                const tbody = document.getElementById('checkpoints-body');
                tbody.innerHTML = '';
                
                data.checkpoints.forEach(cp => {
                    const tr = document.createElement('tr');
                    tr.className = 'border-b border-slate-700 hover:bg-slate-750 transition';
                    
                    let statusBadge = '';
                    if (cp.status === 'pending') statusBadge = '<span class="px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded text-xs font-bold uppercase tracking-wider">Pending</span>';
                    else if (cp.status === 'applied') statusBadge = '<span class="px-2 py-1 bg-green-500/20 text-green-400 rounded text-xs font-bold uppercase tracking-wider">Applied</span>';
                    else if (cp.status === 'denied') statusBadge = '<span class="px-2 py-1 bg-red-500/20 text-red-400 rounded text-xs font-bold uppercase tracking-wider">Denied</span>';
                    else statusBadge = `<span class="px-2 py-1 bg-slate-500/20 text-slate-400 rounded text-xs font-bold uppercase tracking-wider">${cp.status}</span>`;

                    let actions = '';
                    if (cp.status === 'pending') {
                        actions = `
                            <button onclick="approve('${cp.public_id}')" class="px-3 py-1 bg-green-600 hover:bg-green-500 text-white rounded text-sm font-medium transition mr-2">Approve</button>
                            <button onclick="reject('${cp.public_id}')" class="px-3 py-1 bg-red-600 hover:bg-red-500 text-white rounded text-sm font-medium transition">Reject</button>
                        `;
                    }
                    
                    tr.innerHTML = `
                        <td class="p-4 align-top">${statusBadge}</td>
                        <td class="p-4 align-top font-mono text-sm text-slate-400">${cp.public_id}</td>
                        <td class="p-4 align-top">${cp.agent_label || 'unknown'}</td>
                        <td class="p-4 align-top">
                            <div class="font-mono text-sm bg-slate-950 p-2 rounded text-emerald-400 mb-2 whitespace-pre-wrap">${cp.sql_text}</div>
                            <div class="text-xs text-slate-400">Class: ${cp.classification} | Hash: ${cp.hash ? cp.hash.substring(0,8) + '...' : '-'}</div>
                        </td>
                        <td class="p-4 align-top">${actions}</td>
                    `;
                    tbody.appendChild(tr);
                });
            }

            async function approve(token) {
                await fetch(`/v1/checkpoints/${token}/approve`, { method: 'POST' });
                fetchCheckpoints();
            }
            
            async function reject(token) {
                await fetch(`/v1/checkpoints/${token}/reject`, { method: 'POST' });
                fetchCheckpoints();
            }

            fetchCheckpoints();
            setInterval(fetchCheckpoints, 5000);
        </script>
    </body>
    </html>
    """
    return html_content
