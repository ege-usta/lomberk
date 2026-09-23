import dotenv; dotenv.load_dotenv()
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
<html lang="en" class="antialiased">
<head>
    <meta charset="UTF-8">
    <title>Undogate Sentinel | Control Plane</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        dark: '#0a0a0b',
                        surface: '#121214',
                        surfaceElevated: '#1c1c1f',
                        border: '#27272a',
                        primary: '#3b82f6',
                        danger: '#ef4444',
                        success: '#22c55e',
                    },
                    fontFamily: {
                        sans: ['Inter', 'system-ui', 'sans-serif'],
                        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
                    },
                    animation: {
                        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                    }
                }
            }
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap');
        body { background-color: #0a0a0b; color: #e4e4e7; }
        .glass { background: rgba(28, 28, 31, 0.6); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); border-bottom: 1px solid rgba(255,255,255,0.05); }
        .row-enter { animation: slideIn 0.3s ease-out forwards; }
        @keyframes slideIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        /* Custom Scrollbar */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0a0a0b; }
        ::-webkit-scrollbar-thumb { background: #3f3f46; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #52525b; }
    </style>
</head>
<body class="min-h-screen flex flex-col font-sans selection:bg-primary selection:text-white">

    <!-- Header -->
    <header class="glass sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="relative flex h-3 w-3">
              <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
              <span class="relative inline-flex rounded-full h-3 w-3 bg-blue-500"></span>
            </div>
            <h1 class="text-xl font-semibold tracking-tight text-white flex items-center gap-2">
                Undogate <span class="text-xs px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">SENTINEL</span>
            </h1>
        </div>
        <div class="flex items-center gap-4 text-sm text-zinc-400">
            <div class="flex items-center gap-1.5">
                <div class="w-1.5 h-1.5 rounded-full bg-green-500"></div> System Online
            </div>
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1 p-6 md:p-8 max-w-[1400px] mx-auto w-full">
        
        <div class="mb-8 flex justify-between items-end">
            <div>
                <h2 class="text-2xl font-semibold text-white mb-1">Transaction Ledger</h2>
                <p class="text-zinc-400 text-sm">Real-time audit of agent database operations.</p>
            </div>
        </div>

        <div class="bg-surfaceElevated rounded-xl border border-border shadow-2xl overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm whitespace-nowrap">
                    <thead>
                        <tr class="border-b border-border bg-surface text-zinc-400">
                            <th class="px-6 py-4 font-medium">Status</th>
                            <th class="px-6 py-4 font-medium">Agent ID</th>
                            <th class="px-6 py-4 font-medium w-1/2">SQL Signature & Intent</th>
                            <th class="px-6 py-4 font-medium text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody id="checkpoints-body" class="divide-y divide-border">
                        <!-- Loading State -->
                        <tr><td colspan="4" class="px-6 py-12 text-center text-zinc-500">Initiating neural link...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </main>

    <script>
        async function fetchCheckpoints() {
            try {
                const res = await fetch('/v1/checkpoints');
                const data = await res.json();
                const tbody = document.getElementById('checkpoints-body');
                
                if (data.checkpoints.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="px-6 py-12 text-center text-zinc-500">No active transactions detected.</td></tr>';
                    return;
                }

                let newHtml = '';
                data.checkpoints.forEach(cp => {
                    let statusBadge = '';
                    let actionButtons = '';
                    
                    if (cp.status === 'pending') {
                        statusBadge = `<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 text-xs font-medium"><span class="w-1 h-1 rounded-full bg-yellow-400 animate-pulse"></span>PENDING</span>`;
                        actionButtons = `
                            <button onclick="approve('${cp.public_id}')" class="px-4 py-1.5 bg-zinc-100 hover:bg-white text-zinc-900 rounded-lg text-sm font-medium transition-all shadow-sm focus:ring-2 focus:ring-white/20 active:scale-95">Approve</button>
                            <button onclick="reject('${cp.public_id}')" class="px-4 py-1.5 bg-danger/10 hover:bg-danger/20 text-danger border border-danger/20 rounded-lg text-sm font-medium transition-all focus:ring-2 focus:ring-danger/20 active:scale-95">Reject</button>
                        `;
                    } else if (cp.status === 'applied') {
                        statusBadge = `<span class="inline-flex items-center px-2.5 py-1 rounded-md bg-green-500/10 text-green-400 border border-green-500/20 text-xs font-medium">APPLIED</span>`;
                        actionButtons = `<span class="text-zinc-500 text-sm">Committed</span>`;
                    } else if (cp.status === 'denied') {
                        statusBadge = `<span class="inline-flex items-center px-2.5 py-1 rounded-md bg-red-500/10 text-red-400 border border-red-500/20 text-xs font-medium">DENIED</span>`;
                        actionButtons = `<span class="text-zinc-500 text-sm">Rejected</span>`;
                    } else {
                        statusBadge = `<span class="inline-flex items-center px-2.5 py-1 rounded-md bg-zinc-500/10 text-zinc-400 border border-zinc-500/20 text-xs font-medium uppercase">${cp.status}</span>`;
                        actionButtons = `<span class="text-zinc-500 text-sm">-</span>`;
                    }

                    // Parse the reason/decision if available in the decision field, normally it's an enum, so we show hash instead
                    const hashDisplay = cp.hash ? `<div class="mt-2 flex items-center gap-1.5 text-xs text-zinc-500"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg> ${cp.hash.substring(0,12)}...</div>` : '';

                    newHtml += `
                        <tr class="hover:bg-surface transition-colors group">
                            <td class="px-6 py-5 align-top">
                                ${statusBadge}
                                <div class="text-[10px] text-zinc-500 mt-2 font-mono uppercase tracking-wider">${new Date(cp.created_at).toLocaleTimeString()}</div>
                            </td>
                            <td class="px-6 py-5 align-top">
                                <div class="text-sm text-zinc-300 font-medium">${cp.agent_label || 'Anonymous'}</div>
                                <div class="text-xs text-zinc-500 font-mono mt-1">${cp.public_id}</div>
                            </td>
                            <td class="px-6 py-5 align-top whitespace-normal">
                                <div class="bg-dark/50 border border-border rounded-lg p-3 font-mono text-[13px] text-emerald-400/90 leading-relaxed overflow-x-auto shadow-inner">
                                    ${cp.sql_text}
                                </div>
                                <div class="mt-2 text-xs font-medium text-yellow-500/80 flex items-center gap-1.5">
                                    <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
                                    Risk Class: ${cp.classification}
                                </div>
                                ${hashDisplay}
                            </td>
                            <td class="px-6 py-5 align-top text-right">
                                <div class="flex items-center justify-end gap-2">
                                    ${actionButtons}
                                </div>
                            </td>
                        </tr>
                    `;
                });
                
                tbody.innerHTML = newHtml;
            } catch (err) {
                console.error("Link severed:", err);
            }
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
        setInterval(fetchCheckpoints, 3000);
    </script>
</body>
</html>

"""
    return html_content
