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
                        brand: { 50: '#f0fdf4', 100: '#dcfce7', 500: '#22c55e', 700: '#15803d', 800: '#166534', 900: '#14532d', 950: '#052e16' },
                        surface: '#ffffff', background: '#f4f4f5',
                    },
                    fontFamily: { sans: ['Inter', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] },
                    boxShadow: { 'lux': '0 10px 30px -5px rgba(0, 0, 0, 0.08), 0 4px 6px -2px rgba(0, 0, 0, 0.04)' }
                }
            }
        }
    </script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
        body { background-color: #f4f4f5; color: #18181b; }
        .texture-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noiseFilter'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.85' numOctaves='3' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noiseFilter)' opacity='0.02'/%3E%3C/svg%3E"); pointer-events: none; z-index: 50; }
        .glass-header { background: rgba(255, 255, 255, 0.9); backdrop-filter: blur(12px); border-bottom: 1px solid rgba(21, 128, 61, 0.08); }
        .line-clamp-3 { display: -webkit-box; -webkit-line-clamp: 3; -webkit-box-orient: vertical; overflow: hidden; }
        /* Modal fade in */
        #modal-backdrop.hidden { opacity: 0; pointer-events: none; }
        #modal-backdrop { transition: opacity 0.2s ease-out; }
        #modal-content { transition: transform 0.2s ease-out; transform: scale(0.95); }
        #modal-backdrop:not(.hidden) #modal-content { transform: scale(1); }
    </style>
</head>
<body class="min-h-screen flex flex-col font-sans">
    <div class="texture-overlay"></div>

    <header class="glass-header sticky top-0 z-40 px-8 py-5 flex items-center justify-between">
        <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg bg-brand-900 flex items-center justify-center shadow-sm">
                <svg class="w-4 h-4 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
            </div>
            <h1 class="text-xl font-bold tracking-tight text-brand-950 flex items-center gap-2">Undogate <span class="text-[10px] uppercase font-bold tracking-widest text-brand-700 ml-1">Control Plane</span></h1>
        </div>
    </header>

    <main class="flex-1 p-6 md:p-10 max-w-[1400px] mx-auto w-full z-10 relative">
        <div class="mb-8">
            <h2 class="text-3xl font-bold text-brand-950 tracking-tight mb-2">Operation Grid</h2>
            <p class="text-zinc-500 text-sm font-medium">Bento-style inspection grid. Click any card for detailed execution context.</p>
        </div>

        <div id="grid-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            <!-- Cards injected here -->
            <div class="col-span-full text-center py-20 text-zinc-400 font-medium">Loading network traffic...</div>
        </div>
    </main>

    <!-- Detailed Modal -->
    <div id="modal-backdrop" class="hidden fixed inset-0 z-50 flex items-center justify-center bg-zinc-900/40 backdrop-blur-sm">
        <div id="modal-content" class="bg-surface w-full max-w-2xl rounded-2xl shadow-2xl border-2 border-zinc-200 overflow-hidden relative">
            <div class="px-6 py-5 border-b border-zinc-100 flex justify-between items-center bg-zinc-50/50">
                <h3 class="font-bold text-lg text-brand-950">Execution Details</h3>
                <button onclick="closeModal()" class="text-zinc-400 hover:text-zinc-600 bg-white p-1.5 rounded-md border border-zinc-200"><svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/></svg></button>
            </div>
            <div class="p-6" id="modal-body">
                <!-- Injected via JS -->
            </div>
        </div>
    </div>

    <script>
        let checkpointsData = [];

        async function fetchCheckpoints() {
            try {
                const res = await fetch('/v1/checkpoints');
                const data = await res.json();
                checkpointsData = data.checkpoints;
                renderGrid();
            } catch (err) {
                console.error("Failed to fetch:", err);
            }
        }

        function renderGrid() {
            const container = document.getElementById('grid-container');
            if (checkpointsData.length === 0) {
                container.innerHTML = '<div class="col-span-full text-center py-20 text-zinc-400">No active operations.</div>';
                return;
            }

            let html = '';
            checkpointsData.forEach((cp, index) => {
                let badge = '';
                if (cp.status === 'pending') badge = `<span class="px-2.5 py-1 rounded-md bg-amber-50 text-amber-700 border border-amber-200 text-[10px] font-bold uppercase tracking-widest"><span class="inline-block w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse mr-1"></span>PENDING</span>`;
                else if (cp.status === 'applied') badge = `<span class="px-2.5 py-1 rounded-md bg-brand-50 text-brand-700 border border-brand-200 text-[10px] font-bold uppercase tracking-widest">AUTHORIZED</span>`;
                else if (cp.status === 'denied' || cp.status === 'failed') badge = `<span class="px-2.5 py-1 rounded-md bg-red-50 text-red-700 border border-red-200 text-[10px] font-bold uppercase tracking-widest">DENIED</span>`;
                else badge = `<span class="px-2.5 py-1 rounded-md bg-zinc-100 text-zinc-600 border border-zinc-200 text-[10px] font-bold uppercase tracking-widest">${cp.status}</span>`;

                // Square-ish aspect ratio container
                html += `
                    <div onclick="openModal(${index})" class="group bg-surface rounded-2xl border-2 border-zinc-200 hover:border-brand-500 hover:shadow-lux transition-all cursor-pointer p-6 flex flex-col h-64 relative overflow-hidden">
                        
                        <div class="flex justify-between items-start mb-4">
                            <div>
                                <div class="text-sm font-bold text-brand-950">${cp.agent_label || 'Agent'}</div>
                                <div class="text-[10px] text-zinc-400 font-mono mt-0.5">${new Date(cp.created_at).toLocaleTimeString()}</div>
                            </div>
                            ${badge}
                        </div>

                        <div class="flex-1 bg-zinc-50 border border-zinc-100 rounded-lg p-3 font-mono text-[11px] text-brand-900 leading-relaxed line-clamp-3 mb-4">
                            ${cp.sql_text}
                        </div>

                        <div class="mt-auto flex items-center justify-between text-xs font-semibold ${cp.classification === 'DDL_DANGEROUS' || cp.decision === 'REQUIRE_APPROVAL' ? 'text-amber-600' : 'text-zinc-500'} uppercase tracking-wide">
                            <span class="flex items-center gap-1.5"><svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> ${cp.classification}</span>
                            <span class="text-zinc-300 group-hover:text-brand-500 transition-colors">Details &rarr;</span>
                        </div>
                    </div>
                `;
            });
            container.innerHTML = html;
        }

        function openModal(index) {
            const cp = checkpointsData[index];
            const body = document.getElementById('modal-body');
            
            let actions = '';
            if (cp.status === 'pending') {
                actions = `
                    <div class="flex gap-3 pt-4 border-t border-zinc-100 mt-6">
                        <button onclick="approve('${cp.public_id}')" class="flex-1 py-2.5 bg-brand-900 hover:bg-brand-800 text-white rounded-xl text-sm font-semibold transition-all shadow-md active:scale-95">Authorize Operation</button>
                        <button onclick="reject('${cp.public_id}')" class="flex-1 py-2.5 bg-white hover:bg-zinc-50 text-red-600 border border-zinc-200 rounded-xl text-sm font-semibold transition-all shadow-sm active:scale-95">Deny & Block</button>
                    </div>
                `;
            } else {
                actions = `<div class="pt-4 border-t border-zinc-100 mt-6 text-center text-sm font-semibold text-zinc-400 uppercase tracking-widest">Transaction closed</div>`;
            }

            body.innerHTML = `
                <div class="grid grid-cols-2 gap-4 mb-6">
                    <div class="bg-zinc-50 p-4 rounded-xl border border-zinc-100">
                        <div class="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-1">Agent</div>
                        <div class="text-sm font-bold text-brand-950">${cp.agent_label || 'Unknown'}</div>
                    </div>
                    <div class="bg-zinc-50 p-4 rounded-xl border border-zinc-100">
                        <div class="text-[10px] font-bold text-zinc-400 uppercase tracking-widest mb-1">Status</div>
                        <div class="text-sm font-bold text-brand-950 uppercase">${cp.status}</div>
                    </div>
                </div>
                
                <div class="mb-2 text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Query Payload</div>
                <div class="bg-brand-950 border border-brand-900 rounded-xl p-4 font-mono text-[13px] text-emerald-400 leading-relaxed overflow-x-auto shadow-inner mb-6">
                    ${cp.sql_text}
                </div>

                <div class="flex items-center justify-between text-xs font-mono text-zinc-500 bg-zinc-50 p-3 rounded-lg border border-zinc-100">
                    <span>ID: ${cp.public_id}</span>
                    <span>HASH: ${cp.hash ? cp.hash.substring(0,16) + '...' : 'pending'}</span>
                </div>

                ${actions}
            `;

            document.getElementById('modal-backdrop').classList.remove('hidden');
        }

        function closeModal() {
            document.getElementById('modal-backdrop').classList.add('hidden');
        }

        async function approve(token) {
            closeModal();
            await fetch(`/v1/checkpoints/${token}/approve`, { method: 'POST' });
            fetchCheckpoints();
        }
        
        async function reject(token) {
            closeModal();
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
