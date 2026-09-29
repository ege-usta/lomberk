# Rowback

**Every agent write, reversible.**
Rowback is an MCP gateway for PostgreSQL. AI agents send SQL through it instead of holding database credentials. It blocks destructive commands, holds large or sensitive writes for a human, records every changed row, and can undo any applied write, including foreign-key cascades.

**Just want a seatbelt for Claude Code?** [Rowback Seatbelt](seatbelt/) is a free plugin that makes your agent ask before `DROP`, `TRUNCATE`, `DELETE` without `WHERE`, `prisma migrate reset`, `dropdb` and friends. Install it in two commands.

## 9-second database deletion demo

In April 2026 an autonomous coding agent deleted a production database in 9 seconds (through an over-privileged infrastructure token). Rowback closes the other door: an agent's own database access. Here is what a rogue agent can and can't do when its SQL goes through Rowback.

![Rowback demo: destructive SQL denied, a protected DELETE held, approved, then undone](site/demo.gif)

### 1. Start the stack
```bash
docker compose up -d --build
curl localhost:8000/readyz          # {"status":"ready"}
```
This starts a demo `pocketos` database (`users` ← `payments` with `ON DELETE CASCADE`), installs Rowback with two least-privilege roles, registers both tables, and starts the gateway.

### 2. Connect your agent (it gets a URL and a key, nothing else)
```bash
claude mcp add --transport http rowback http://localhost:8000/mcp \
  --header "Authorization: Bearer demo-agent-key"
```
Any MCP client that speaks Streamable HTTP works the same way.

### 3. The agent goes rogue
| Agent sends | Rowback |
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
Pending requests expire after `agent.approval_timeout_minutes`. Review the exact SQL first with `GET /v1/checkpoints/cp_…` or `rowback show cp_…`.

### Or approve in Slack (Enterprise)
Create the app from [`slack/app-manifest.json`](slack/app-manifest.json) (bot scope `chat:write` only, Socket Mode, so no public URL is needed), invite the bot to your approvals channel, then:
```yaml
slack:
  channel_id: C0123APPROVALS
  team_allowlist: [T0123]
  admin_allowlist: [U0ALICE, U0BOB]   # only these users' clicks count
  include_sql: false                  # default: SQL never leaves for Slack
```
```bash
ROWBACK_SLACK_ENABLED=true ROWBACK_SLACK_APP_TOKEN=xapp-… ROWBACK_SLACK_BOT_TOKEN=xoxb-…
```
Every held request is posted with Approve/Reject buttons, and the message updates to the final state. The approver's Slack ID is written to the audit log.

### Approver SSO (Enterprise)
Approvers sign in with the company identity provider (Okta, Microsoft Entra ID, Google, Keycloak, any OIDC issuer) and send their ID token. The audit log then records the person (`oidc:alice@corp.com`), not a shared key.
```yaml
sso:
  issuer: https://corp.okta.com          # keys are discovered from the issuer
  audience: rowback-approvals           # the client ID registered for Rowback
  allowed_groups: [db-approvers]         # and/or allowed_identities: [alice@corp.com]
  # allow_admin_key: true                # the shared key is OFF once SSO is on; CLI stays as break-glass
```
```bash
curl -H "Authorization: Bearer $ID_TOKEN" -X POST localhost:8000/v1/checkpoints/cp_…/approve
```
Only asymmetrically signed tokens (RS/PS/ES) for this issuer and audience are accepted, and they must be unexpired. With the default `identity_claim: email`, the token must mark the email as verified. Entra ID does not send that flag, so set `identity_claim` to `upn` or `oid` there.

## Configuration (`rowback.yaml`)
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

Environment: `ROWBACK_ADMIN_DSN` (control role), `ROWBACK_AGENT_DSN` (agent role), `ROWBACK_API_KEY` (agent), `ROWBACK_ADMIN_KEY` (approvers), `ROWBACK_AUDIT_LOG` (JSONL path).

## Installing on your own database
```bash
pip install "rowback @ git+https://github.com/ege-usta/rowback"   # or: docker build -t rowback .
export ROWBACK_INSTALL_DSN=postgresql://owner@db/app       # used only for install
rowback init --control-role rowback_control --agent-role rowback_agent
rowback register public.orders --agent-role rowback_agent  # repeat per table (and FK children)
rowback verify-ledger                                       # tamper-evidence check
```
Local, single-user development without the service: `rowback serve` (stdio MCP). Do not use this mode with agents that have shell access. See [SECURITY.md](SECURITY.md).

## How it works
1. **AST hard gate**: PostgreSQL's own parser (`pglast`) allows one `SELECT/INSERT/UPDATE/DELETE`, schema-qualified writes with `WHERE`, and an allowlist of pure built-in functions.
2. **Policy**: protected tables, FK-cascade reach, and a row limit enforced by executing inside a transaction and rolling back.
3. **Capture**: a `SECURITY DEFINER` row trigger records every change (cascades included), bound to a single-use capability token.
4. **Undo**: an order that respects foreign keys (parents are restored before children), with conflict and schema-drift checks. It refuses rather than touching rows written later.
5. **Ledger**: append-only, SHA-256 hash-chained checkpoints.

**Current limits:** single-column primary keys; no undo for tables with rules, inheritance, or user triggers; DDL is blocked, not reversible. Full list in [SECURITY.md](SECURITY.md).

## Overhead
Measured against Postgres 16 on localhost (200 runs, p50 / p95):

| Path | Latency |
|---|---|
| Hard gate + policy (no DB) | 0.1 / 0.1 ms |
| Read through Rowback | 5.4 / 6.2 ms |
| Captured, undoable write through Rowback | 18.3 / 23.9 ms |
| Plain write on a new connection (baseline) | 4.8 / 6.0 ms |

Agent turns take seconds, so this is negligible in practice. Most of the cost is opening new connections; connection pooling is on the roadmap for remote/TLS databases.

## Development
```bash
uv sync --all-groups
PYTHONPATH=src uv run pytest tests/    # needs Docker (testcontainers)
```

## License
Open core. Everything outside `src/rowback/ee/` is Apache-2.0: the hard gate, policy, capture, undo, ledger, remote MCP, and API/CLI approvals. You can run the whole safety path for free.

`src/rowback/ee/` (Slack approvals, and upcoming SSO for approvers) is source-available under the [Rowback Enterprise License](src/rowback/ee/LICENSE). It is free for development and evaluation, and production use needs a subscription.
