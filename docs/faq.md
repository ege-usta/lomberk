# Rowback FAQ

## What is Rowback and what problem does it solve?
Rowback is an MCP gateway for PostgreSQL that lets AI agents write to your database safely. It sits between the agent and the database, blocking destructive commands, holding large or sensitive writes for human approval, and recording every changed row so any applied write can be undone. It is for teams that give agents real write access and want a way back when one makes a bad write.

## Who should NOT use Rowback?
Don't reach for Rowback if what you need is a general database backup, or protection against someone who already holds your database owner credentials. It cannot stop an agent that holds cloud infrastructure tokens from deleting the server itself. Every table Rowback protects needs a primary key (multi-column keys and partitioned tables are fine).

## How does the AI agent connect to the database?
The agent never connects to the database directly and is never given database credentials. It connects to Rowback over the Model Context Protocol (MCP) with a gateway URL and an agent API key. Rowback runs the agent's SQL as its own least-privilege role, against only the tables you registered.

## What types of SQL does Rowback block entirely?
Rowback parses every statement with PostgreSQL's own parser and structurally bans destructive commands such as `DROP` and `TRUNCATE`, all DDL, writes without a `WHERE` clause, stacked statements, and session/configuration commands. It also refuses queries that read system catalogs or call functions outside a small allowlist of pure built-ins. The [attack gallery](attack-gallery.md) lists concrete attempts and the exact refusal for each.

## What SQL is allowed?
Rowback allows exactly one `SELECT`, `INSERT`, `UPDATE`, or `DELETE` per request. Writes must be schema-qualified and carry a `WHERE` clause, and they can only touch tables you have explicitly registered. Anything else is refused with a reason the agent can read.

## How does "undo" work?
A `SECURITY DEFINER` trigger records every row a write changes, including rows reached by a foreign-key `ON DELETE CASCADE`, and binds them to a single-use token for that transaction. To reverse an applied write, Rowback puts those exact rows back in an order that respects foreign keys — parents before children — without touching anyone else's later writes.

## What are the limits of undo?
Undo needs a primary key on every protected table (one or more columns). DDL is blocked outright rather than reversed, and sequences are intentionally not rewound. Undo also refuses — rather than overwrite — if the schema has drifted, if a row changed after the checkpoint, or if reversing would reach rows it did not originally capture.

## When does a write wait for human approval?
A write is held when it touches a table you marked protected (or its foreign-key cascade reaches one), or when it changes more rows than your `max_rows_without_approval` limit. Writes to tables that carry their own triggers also wait for a person, unless that table was registered with `--allow-triggers`.

## How do people approve held writes?
Pending writes can be reviewed and approved from the Rowback CLI, or through the REST API with an admin key. On the Pro tier, approvers can use a web panel with Single Sign-On, or approve from Slack with interactive buttons. If you enable the two-person rule, two distinct verified identities must approve before the write runs.

## Can I use Rowback with hosted PostgreSQL (Supabase, Neon, RDS)?
Yes. The setup is the same shape everywhere: create a control role and an agent role, run the one-time install as the database owner, then register your tables. Provider-specific notes — Supabase Row Level Security, Neon connection strings, RDS roles — are in [docs/hosted-postgres.md](hosted-postgres.md).

## How does Rowback keep sensitive data away from the agent?
Columns you list in `sensitive_columns`, and columns whose names look secret (such as `password`, `api_key`, `token`), are protected two ways. Rowback refuses queries that could reveal them — including casting whole rows to text, pulling them out of JSON, or using `NATURAL JOIN` — and at registration it revokes the agent role's `SELECT` on those columns, so the database itself blocks access even if a query slips past the gate.

## Is Rowback a replacement for database security or backups?
No. Rowback restricts what an AI agent can do; it is not a backup and not a substitute for your normal database security. It cannot stop a person or tool that holds owner credentials, and it cannot help if an agent was handed over-privileged cloud infrastructure tokens.

## What is the licensing model?
Rowback is open core. The core safety path — the parser gate, policy, capture, undo, the tamper-evident ledger, and approvals over CLI and API — is free and open source under Apache-2.0. The team features under `src/rowback/ee/` are source-available under the Elastic License 2.0 (ELv2).

## What do Pro and Enterprise cost, and what's in them?
The core is free. Pro is $99/month or $990/year and covers up to 3 production databases, adding the web approval panel, the two-person rule, Slack approvals, approver SSO, and audit export (CSV or JSONL). Enterprise starts at $3,000/year for unlimited databases with an annual invoice and email support. Pro features need a license key, checked once at startup against Polar; if the key is invalid or cancelled, the gateway refuses to start with those features enabled.

## Which versions of PostgreSQL does Rowback support?
PostgreSQL 14 through 18. The full test suite runs against every one of these versions in CI, so each is verified, not just assumed. Rowback relies only on standard PostgreSQL features — the pglast parser, `SECURITY DEFINER` triggers, roles, and column privileges — so there are no version-specific internals to break. (The published overhead benchmark was measured on 16.)
