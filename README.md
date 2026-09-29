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

### Or approve in Slack (Pro)
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

### Approver SSO (Pro)
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

### Web approval panel (Pro)
Open `https://<gateway>/panel/` for writes waiting for approval, the history with who approved each one, one-click undo, and exports. Approvers sign in with SSO or the admin key. To offer "Sign in with SSO", register `<panel_url>/panel/sso/callback` as a redirect URI at your IdP:
```yaml
sso:
  # ...the SSO settings above, with audience = the panel's client ID
  panel_url: https://rowback.corp.com    # public https URL of this gateway
```
Set `ROWBACK_SSO_CLIENT_SECRET` if your IdP requires a client secret for that client.

### Two-person rule (Pro)
```yaml
approvals:
  required: 2      # a held write runs only after two different people approve it
```
Only verified identities count: the N people must all approve through SSO (panel or API), or all through Slack. Mixing systems doesn't add up, because one person can hold both. Admin-key and CLI approvals are recorded but don't count, since they prove no identity. One reject cancels the write. Every approval is stored in the append-only `rowback.approvals` table.

### Audit export (Pro)
```bash
curl -H "X-API-Key: $ADMIN_KEY" "localhost:8000/v1/audit/export?format=csv&since=2026-01-01" > audit.csv   # or format=jsonl
```
Each checkpoint comes with its SQL, agent, status, rows, who approved it and its ledger hash. The panel has the same export as buttons.

### Pro license
Slack approvals, SSO, the two-person rule, the web panel and audit export need `ROWBACK_LICENSE_KEY`. Buy a key on the [pricing page](#pricing): it arrives by email right away and renews with your subscription. The gateway checks the key with Polar (`api.polar.sh`) once at startup. That call sends only the key. If Polar can't be reached, Pro stays on. If the key is invalid or cancelled, the gateway refuses to start with Pro features configured and tells you why.

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

Environment: `ROWBACK_ADMIN_DSN` (control role), `ROWBACK_AGENT_DSN` (agent role), `ROWBACK_API_KEY` (agent), `ROWBACK_ADMIN_KEY` (approvers), `ROWBACK_AUDIT_LOG` (JSONL path), `ROWBACK_LICENSE_KEY` (Pro).

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

**Current limits:** single-column primary keys. Writes to tables with rules or inheritance are refused. Writes to tables with their own triggers can't be undone, so they wait for a person. DDL is blocked, not reversible. Full list in [SECURITY.md](SECURITY.md).

## Overhead
Measured against Postgres 16 on localhost (200 runs, p50 / p95):

| Path | Latency |
|---|---|
| Hard gate + policy (no DB) | 0.1 / 0.1 ms |
| Read through Rowback | 5.4 / 6.2 ms |
| Captured, undoable write through Rowback | 18.3 / 23.9 ms |
| Plain write on a new connection (baseline) | 4.8 / 6.0 ms |

Agent turns take seconds, so this is negligible in practice. Most of the cost is opening new connections; connection pooling is on the roadmap for remote/TLS databases.

## Pricing
| | Free | Pro | Enterprise |
|---|---|---|---|
| Price | $0 | **$99/month** or $990/year | from **$3,000/year** |
| Hard gate, holds, capture, undo, ledger, remote MCP, API/CLI approvals | ✓ | ✓ | ✓ |
| Slack approvals, approver SSO, web panel, two-person rule, audit export | | ✓ | ✓ |
| Production databases | unlimited | up to 3 | unlimited |
| Billing | | card, self-serve | annual invoice |
| Help | GitHub issues | GitHub issues | email, answered within 2 business days; help with your security questionnaire |

**[Buy Pro](REPLACE_WITH_POLAR_CHECKOUT_URL)**: the key arrives by email right away. For Enterprise, write to REPLACE_WITH_CONTACT_EMAIL. Payments, invoices and sales tax are handled by [Polar](https://polar.sh), the merchant of record.

Rowback is self-hosted and your data never reaches us. There is no phone support or on-call; the docs and `rowback doctor` are built so you can set it up alone.

## Development
```bash
uv sync --all-groups
PYTHONPATH=src uv run pytest tests/    # needs Docker (testcontainers)
```

## License
Open core. Everything outside `src/rowback/ee/` is Apache-2.0: the hard gate, policy, capture, undo, ledger, remote MCP, and API/CLI approvals. You can run the whole safety path for free.

`src/rowback/ee/` (Slack approvals, approver SSO, the web panel, audit export and the license check) is source-available under the [Rowback Enterprise License](src/rowback/ee/LICENSE). It is free for development and evaluation. Production use needs a Pro or Enterprise subscription. The two-person rule is core code, but turning it on needs a key.
