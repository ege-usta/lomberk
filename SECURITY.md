# Security Model

Rowback sits between AI agents and PostgreSQL. This document states what it defends against, how, and what it does **not** cover, so a security team can evaluate it honestly.

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** ("Security" tab → "Report a vulnerability") on this repository. Do not open public issues for security problems.

## Trust boundaries

| Actor | Holds | Can |
|---|---|---|
| AI agent | gateway URL + **agent key** only | submit SQL to `/mcp` or `/v1/execute` |
| Gateway service | control DSN, agent DSN, both keys | classify, hold, execute, undo |
| Human approver | **admin key**, SSO identity or Slack allowlist | list, approve, reject, undo (API, CLI, Slack, web panel) |
| DB owner / installer | install DSN (used once) | install schema, register tables |

The agent never receives a database credential or the admin key. **Deploy the gateway as its own service** (see `Dockerfile` / `docker-compose.yml`). The stdio mode (`rowback serve`) puts DSNs on the agent's machine and is meant for local development only: an agent with shell access there can approve its own requests.

## Defenses

1. **AST hard gate** (PostgreSQL's own parser via `pglast`): exactly one statement; only `SELECT/INSERT/UPDATE/DELETE`; writes must be schema-qualified and have a `WHERE`; functions limited to an allowlist of pure built-ins. Blocks DDL, `SET`/`RESET`, `COPY`, `DO`, `PREPARE`, `CALL`, `LOCK`, `SELECT INTO`, `set_config`/`current_setting`, `pg_*`, `dblink`, `lo_*`, `nextval`, and stacked statements. See `tests/unit/test_firewall_attacks.py`.
2. **Policy**: protected tables and a per-statement row limit. Writes are executed inside a transaction; if they exceed `limits.max_rows_without_approval` **or can cascade (via foreign keys) into a protected table**, they are rolled back and queued for approval. `WHERE 1=1` tricks are caught by the row count, not by pattern matching.
3. **Database-enforced capture**: a `SECURITY DEFINER` trigger records every changed row, including FK cascades. It refuses agent-role writes that are not bound to a live, single-use capability token for the current transaction. Writes whose cascade would reach an unregistered table are refused, because those rows could not be undone.
4. **Least privilege**: startup refuses superuser roles and refuses when the control and agent DSNs resolve to the same role. The agent role only gets DML on registered tables.
5. **Approvals**: human-only (OIDC SSO, admin key, CLI, or Slack allowlist), constant-time key comparison, expiry after `agent.approval_timeout_minutes`, with the hard gate re-checked at approval time.
   Every approval is recorded in the append-only `rowback.approvals` table, which only a `SECURITY DEFINER` function can write. With `approvals.required: N`, a held write runs only after N distinct identities from one verified system (OIDC or Slack) approve it, under a row lock so concurrent approvers can't race it through. The shared admin key and CLI users can't make up a quorum, and neither can one person's SSO plus Slack identities. One reject cancels the write.
   Slack: the bot has only the `chat:write` scope and uses Socket Mode (no inbound URL). A click counts only when the team and user are allowlisted **and** the `(team, channel, message_ts)` matches the durable binding the gateway recorded when it posted. The checkpoint ID in the button is never trusted on its own. A post whose outcome is unknown is never re-sent, and SQL is not sent to Slack unless `slack.include_sql` is set.
6. **Undo**: undoes rows in an order that respects foreign keys. It refuses when a row changed after the checkpoint, when the schema drifted, or when the undo would cascade into rows it did not create.
7. **Tamper-evident ledger**: checkpoints are append-only (UPDATE/DELETE of recorded fields is blocked) and SHA-256 hash-chained. `rowback verify-ledger` finds the first altered entry and prints the head hash.
8. **Web panel** (Pro, `/panel`): the session is an HMAC-signed, HttpOnly, SameSite=Strict cookie that expires after 8 hours, keyed from the admin key, so rotating the key signs everyone out. Every state change also needs a custom header that a cross-site form can't send. The panel uses a strict CSP (no inline or third-party script, no framing) and renders agent SQL as text only. SSO sign-in uses the OIDC authorization code flow with PKCE, `state` and `nonce`, done server side, and the resulting ID token passes the same checks as API approvals.
9. **License check** (Pro only): one HTTPS call to `api.polar.sh` at startup that sends the license key and nothing else. No SQL, rows or usage data leave. If the call fails, Pro stays on, so blocking that host doesn't break the gateway.
10. **Data minimisation**: columns whose names contain `password`, `passwd`, `pwd`, `token`, `secret`, `ssn`, `hash`, `credit_card`, `api_key`, `apikey`, `private_key` or `credential` can't be referenced, renamed, read as part of a whole row (`u`, `u::text`, `jsonb_build_object('r', u)`), or reached through `*` inside a subquery, CTE, `UNION` or `INSERT ... SELECT`. A top-level `*` masks them in results. See `tests/unit/test_sensitive_columns.py`. The audit log is owner-only (`0600`) and never written to `/tmp`.

## Residual risks (known, documented)

- **Database superusers** can disable triggers and rewrite the whole hash chain. Export the `verify-ledger` head hash to an external system (SIEM, WORM storage) to detect this.
- **Read access** is governed by the agent role's grants. Rowback masks secret-looking columns by name only; use PostgreSQL column privileges or RLS for real data classification.
- **Sequences are not rewound** by undo, which is intentional (ADR-005).
- **Undo scope**: single-column primary keys only. Agent writes to tables with rewrite rules or inheritance are refused before they run, because some rows would bypass capture. A write to a table with its own triggers (e.g. `updated_at`) can't be undone, so it waits for a person, who sees why. Identity and generated columns are supported. DDL is blocked, not reversible.
- **TLS** is not terminated by the gateway. Run it behind a TLS reverse proxy or service mesh.
- **Optional LLM sentinel** (`OPENAI_API_KEY`) sends SQL text to a third party and is advisory only. Leave it unset if SQL may contain regulated data.
- **Throughput**: checkpoint creation is serialized by one ledger lock.
- **Panel sessions** last up to 8 hours: removing someone from the IdP group takes effect at their next sign-in. The gateway doesn't rate-limit admin-key attempts, so put the rate limit on your reverse proxy.
- **Approver identity**: with `sso` configured (Pro), API approvals carry the person from a verified OIDC ID token, and the shared key is off unless `sso.allow_admin_key: true`. An approver allowlist (groups or identities) is mandatory. Without it, API approvals are the shared admin key and CLI approvals are the OS user. Slack approvals always carry the Slack user ID.

## Hardening checklist

- [ ] Gateway runs as a separate service; agents get only the URL + agent key.
- [ ] Keys are 32+ random bytes, distinct, and rotated; held in a secret manager.
- [ ] TLS in front of the gateway; `/v1/checkpoints/*`, `/v1/audit/*` and `/panel` reachable only from approver networks, rate-limited at the proxy.
- [ ] Every table the agent may write is registered (`rowback register`), including FK children.
- [ ] `protected_tables` and `limits.max_rows_without_approval` reviewed. Config typos fail startup by design.
- [ ] `verify-ledger` head hash exported on a schedule; audit log shipped to your SIEM.
