# Undogate

**Ctrl+Z for AI agents.**
Undogate is an MCP gateway for PostgreSQL. AI agents send SQL through it instead of holding database credentials. It blocks destructive commands, holds large or sensitive writes for a human, records every changed row, and can undo any applied write, including foreign-key cascades.

## 9-second database deletion demo

In April 2026 an autonomous coding agent deleted a production database in 9 seconds. Here is the same scenario behind Undogate.

### 1. Start the stack
```bash
docker compose up -d --build
curl localhost:8000/readyz          # {"status":"ready"}
```
This starts a demo `pocketos` database (`users` ← `payments` with `ON DELETE CASCADE`), installs Undogate with two least-privilege roles, registers both tables, and starts the gateway.

### 2. Connect your agent (it gets a URL and a key, nothing else)
```bash
claude mcp add --transport http undogate http://localhost:8000/mcp \
  --header "Authorization: Bearer demo-agent-key"
```
Any MCP client that speaks Streamable HTTP works the same way.

### 3. The agent goes rogue
| Agent sends | Undogate |
|---|---|
| `DROP TABLE public.users` | **Denied**: DDL is structurally banned |
| `DELETE FROM public.users` | **Denied**: write without `WHERE` |
| `DELETE FROM public.users WHERE id > 0` | **Held**: `public.users` is protected → `APPROVAL REQUIRED. Token: cp_…` |
| `UPDATE public.orders SET total = 0 WHERE 1=1` on a large table | **Held**: touched more rows than `max_rows_without_approval`, so it was rolled back |

### 4. A human decides (admin key, never given to the agent)
```bash
H="X-API-Key: demo-admin-key"
curl -H "$H" localhost:8000/v1/checkpoints/pending
curl -H "$H" -X POST localhost:8000/v1/checkpoints/cp_…/approve    # or /reject
curl -H "$H" -X POST localhost:8000/v1/checkpoints/cp_…/undo       # users AND cascaded payments come back
```
Pending requests expire after `agent.approval_timeout_minutes`. Slack approvals via Socket Mode are available (`UNDOGATE_SLACK_ENABLED=true`).

## Configuration (`undogate.yaml`)
```yaml
limits:
  max_rows_without_approval: 10   # larger writes are rolled back and held
  statement_timeout_ms: 15000
protected_tables:                 # any write, or FK cascade, reaching these is held
  - public.users
agent:
  approval_timeout_minutes: 30
```
Unknown keys fail startup, so a typo can never silently turn protection off.

Environment: `UNDOGATE_ADMIN_DSN` (control role), `UNDOGATE_AGENT_DSN` (agent role), `UNDOGATE_API_KEY` (agent), `UNDOGATE_ADMIN_KEY` (approvers), `UNDOGATE_AUDIT_LOG` (JSONL path).

## Installing on your own database
```bash
export UNDOGATE_INSTALL_DSN=postgresql://owner@db/app       # used only for install
undogate init --control-role undogate_control --agent-role undogate_agent
undogate register public.orders --agent-role undogate_agent  # repeat per table (and FK children)
undogate verify-ledger                                       # tamper-evidence check
```
Local, single-user development without the service: `undogate serve` (stdio MCP). Do not use this mode with agents that have shell access. See [SECURITY.md](SECURITY.md).

## How it works
1. **AST hard gate**: PostgreSQL's own parser (`pglast`) allows one `SELECT/INSERT/UPDATE/DELETE`, schema-qualified writes with `WHERE`, and an allowlist of pure built-in functions.
2. **Policy**: protected tables, FK-cascade reach, and a row limit enforced by executing inside a transaction and rolling back.
3. **Capture**: a `SECURITY DEFINER` row trigger records every change (cascades included), bound to a single-use capability token.
4. **Undo**: an order that respects foreign keys (parents are restored before children), with conflict and schema-drift checks. It refuses rather than touching rows written later.
5. **Ledger**: append-only, SHA-256 hash-chained checkpoints.

**Current limits:** single-column primary keys; no undo for tables with rules, inheritance, user triggers, or identity/generated columns; DDL is blocked, not reversible. Full list in [SECURITY.md](SECURITY.md).

## Overhead
Measured against Postgres 16 on localhost (200 runs, p50 / p95):

| Path | Latency |
|---|---|
| Hard gate + policy (no DB) | 0.1 / 0.1 ms |
| Read through Undogate | 5.4 / 6.2 ms |
| Captured, undoable write through Undogate | 18.3 / 23.9 ms |
| Plain write on a new connection (baseline) | 4.8 / 6.0 ms |

Agent turns take seconds, so this is negligible in practice. Most of the cost is opening new connections; connection pooling is on the roadmap for remote/TLS databases.

## Development
```bash
uv sync --all-groups
PYTHONPATH=src uv run pytest tests/    # needs Docker (testcontainers)
```

## License
Apache-2.0
