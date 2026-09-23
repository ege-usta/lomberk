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
    <title>Undogate | Executive Control Plane</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    colors: {
                        brand: {
                            50: '#f0fdf4',
                            100: '#dcfce7',
                            500: '#22c55e',
                            700: '#15803d',
                            800: '#166534',
                            900: '#14532d', // Swiss Bank Green
                            950: '#052e16',
                        },
                        surface: '#ffffff',
                        background: '#f8faf9',
                    },
                    fontFamily: {
                        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
                        mono: ['JetBrains Mono', 'Menlo', 'monospace'],
                    },
                    boxShadow: {
                        'lux': '0 4px 20px -2px rgba(21, 128, 61, 0.05), 0 0 3px rgba(0,0,0,0.02)',
                        'inner-lux': 'inset 0 2px 4px 0 rgba(0, 0, 0, 0.02)',
                    }
                }
            }
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        body { background-color: #f8faf9; color: #18181b; }
        
        /* Subtle noise texture for premium feel */
        .texture-overlay {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.02'/%3E%3C/svg%3E");
            pointer-events: none;
            z-index: 50;
        }

        .glass-header { 
            background: rgba(255, 255, 255, 0.9); 
            backdrop-filter: blur(12px); 
            -webkit-backdrop-filter: blur(12px); 
            border-bottom: 1px solid rgba(21, 128, 61, 0.08); 
        }

        /* Custom Scrollbar - Light */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #d1d5db; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #9ca3af; }
    </style>
</head>
<body class="min-h-screen flex flex-col font-sans selection:bg-brand-100 selection:text-brand-900">
    <div class="texture-overlay"></div>

    <!-- Header -->
    <header class="glass-header sticky top-0 z-40 px-8 py-5 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg bg-brand-900 flex items-center justify-center shadow-sm">
                <svg class="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
            </div>
            <h1 class="text-xl font-bold tracking-tight text-brand-950 flex items-center gap-2">
                Undogate <span class="text-[10px] uppercase font-bold tracking-widest text-brand-700 ml-1">Control Plane</span>
            </h1>
        </div>
        <div class="flex items-center gap-2 text-xs font-semibold tracking-wide uppercase text-brand-800 bg-brand-50 px-3 py-1.5 rounded-full border border-brand-100">
            <div class="w-2 h-2 rounded-full bg-brand-500 animate-pulse"></div> Secure Session
        </div>
    </header>

    <!-- Main Content -->
    <main class="flex-1 p-6 md:p-10 max-w-[1200px] mx-auto w-full z-10 relative">
        
        <div class="mb-8 flex justify-between items-end">
            <div>
                <h2 class="text-3xl font-bold text-brand-950 tracking-tight mb-2">Immutable Ledger</h2>
                <p class="text-zinc-500 text-sm font-medium">Authoritative log of all intercepted autonomous operations.</p>
            </div>
        </div>

        <div class="bg-surface rounded-2xl border border-zinc-200 shadow-lux overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm whitespace-nowrap">
                    <thead>
                        <tr class="border-b border-zinc-100 bg-zinc-50/50 text-zinc-500">
                            <th class="px-8 py-5 font-semibold text-xs uppercase tracking-wider">Status</th>
                            <th class="px-8 py-5 font-semibold text-xs uppercase tracking-wider">Agent Identity</th>
                            <th class="px-8 py-5 font-semibold text-xs uppercase tracking-wider w-1/2">Operation Signature</th>
                            <th class="px-8 py-5 font-semibold text-xs uppercase tracking-wider text-right">Authorization</th>
                        </tr>
                    </thead>
                    <tbody id="checkpoints-body" class="divide-y divide-zinc-100">
                        <!-- Loading State -->
                        <tr><td colspan="4" class="px-8 py-16 text-center text-zinc-400 font-medium">Verifying ledger integrity...</td></tr>
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
                    tbody.innerHTML = '<tr><td colspan="4" class="px-8 py-16 text-center text-zinc-400">No records found in the ledger.</td></tr>';
                    return;
                }

                let newHtml = '';
                data.checkpoints.forEach(cp => {
                    let statusBadge = '';
                    let actionButtons = '';
                    
                    if (cp.status === 'pending') {
                        statusBadge = `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-amber-50 text-amber-700 border border-amber-200 text-xs font-bold uppercase tracking-widest shadow-sm"><span class="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse"></span>REQUIRES APPROVAL</span>`;
                        actionButtons = `
                            <button onclick="approve('${cp.public_id}')" class="px-5 py-2 bg-brand-900 hover:bg-brand-800 text-white rounded-lg text-sm font-semibold transition-all shadow-md focus:ring-2 focus:ring-brand-900/20 active:scale-95">Authorize</button>
                            <button onclick="reject('${cp.public_id}')" class="px-5 py-2 bg-white hover:bg-zinc-50 text-zinc-700 border border-zinc-200 rounded-lg text-sm font-semibold transition-all shadow-sm focus:ring-2 focus:ring-zinc-200 active:scale-95">Deny</button>
                        `;
                    } else if (cp.status === 'applied') {
                        statusBadge = `<span class="inline-flex items-center px-3 py-1 rounded-full bg-brand-50 text-brand-700 border border-brand-200 text-xs font-bold uppercase tracking-widest">AUTHORIZED</span>`;
                        actionButtons = `<span class="text-zinc-400 text-sm font-medium flex items-center justify-end gap-1.5"><svg class="w-4 h-4 text-brand-500" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg> Executed</span>`;
                    } else if (cp.status === 'denied') {
                        statusBadge = `<span class="inline-flex items-center px-3 py-1 rounded-full bg-red-50 text-red-700 border border-red-200 text-xs font-bold uppercase tracking-widest">DENIED</span>`;
                        actionButtons = `<span class="text-zinc-400 text-sm font-medium flex items-center justify-end gap-1.5"><svg class="w-4 h-4 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg> Blocked</span>`;
                    } else {
                        statusBadge = `<span class="inline-flex items-center px-3 py-1 rounded-full bg-zinc-100 text-zinc-600 border border-zinc-200 text-xs font-bold uppercase tracking-widest">${cp.status}</span>`;
                        actionButtons = `<span class="text-zinc-400 text-sm">-</span>`;
                    }

                    const hashDisplay = cp.hash ? `<div class="mt-3 flex items-center gap-1.5 text-[11px] font-mono text-zinc-400"><svg class="w-3.5 h-3.5 text-brand-700" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg> SHA-256: ${cp.hash.substring(0,16)}...</div>` : '';

                    newHtml += `
                        <tr class="hover:bg-zinc-50/80 transition-colors group">
                            <td class="px-8 py-6 align-top">
                                ${statusBadge}
                                <div class="text-[11px] text-zinc-400 mt-3 font-semibold uppercase tracking-wider">${new Date(cp.created_at).toLocaleTimeString([], {hour: '2-digit', minute:'2-digit', second:'2-digit'})}</div>
                            </td>
                            <td class="px-8 py-6 align-top">
                                <div class="text-sm text-brand-950 font-bold">${cp.agent_label || 'Anonymous Engine'}</div>
                                <div class="text-xs text-zinc-500 font-mono mt-1">${cp.public_id}</div>
                            </td>
                            <td class="px-8 py-6 align-top whitespace-normal">
                                <div class="bg-zinc-50 border border-zinc-200 rounded-lg p-3.5 font-mono text-[13px] text-brand-900 leading-relaxed overflow-x-auto shadow-inner-lux">
                                    ${cp.sql_text}
                                </div>
                                <div class="mt-3 text-xs font-semibold ${cp.classification === 'DDL_DANGEROUS' || cp.decision === 'REQUIRE_APPROVAL' ? 'text-amber-600' : 'text-brand-700'} flex items-center gap-1.5 uppercase tracking-wide">
                                    <svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
                                    Risk Policy: ${cp.classification}
                                </div>
                                ${hashDisplay}
                            </td>
                            <td class="px-8 py-6 align-top text-right">
                                <div class="flex items-center justify-end gap-2.5">
                                    ${actionButtons}
                                </div>
                            </td>
                        </tr>
                    `;
                });
                
                tbody.innerHTML = newHtml;
            } catch (err) {
                console.error("Ledger sync failed:", err);
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
