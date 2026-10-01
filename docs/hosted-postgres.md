# Rowback on Supabase, Neon and Amazon RDS

Every setup has the same three steps:

1. Create two login roles.
2. Run `rowback init` as the role that owns your tables.
3. Register the tables your agent may write to.

The differences are which role owns your tables and which connection string to use.

## 1. Create the two roles (any provider)
Run this as the owner role (see below for each provider), with two different random passwords:
```sql
CREATE ROLE rowback_control LOGIN PASSWORD '<random 32+ chars>';
CREATE ROLE rowback_agent   LOGIN PASSWORD '<another random 32+ chars>';
```
- `rowback_control` is the gateway's own role. It approves, captures and undoes writes.
- `rowback_agent` is the only role the agent's SQL ever runs as.
- Neither may be a superuser. `rowback doctor` checks this.

## 2. Install and register
```bash
export ROWBACK_INSTALL_DSN='postgresql://<owner>:<password>@<host>:5432/<db>?sslmode=require'
rowback init --control-role rowback_control --agent-role rowback_agent
rowback register public.orders --agent-role rowback_agent
```
For the gateway, set:
- `ROWBACK_ADMIN_DSN` to `rowback_control`'s connection string;
- `ROWBACK_AGENT_DSN` to `rowback_agent`'s.

Keep `ROWBACK_INSTALL_DSN` out of the gateway. It is only needed for `init` and `register`.

Then run `rowback doctor`. It flags anything that is set up in an unsafe way.

## Supabase
- **Owner role:** `postgres`. Tables you created in the dashboard or with migrations belong to it.
- **Connection:** the *direct connection* or the *session pooler* (port 5432), from Project Settings → Database. Don't use the transaction pooler (port 6543) for Rowback.
- **Row Level Security:** if a table has RLS on, `rowback_agent` sees no rows until it has a policy. Give it one per table:
  ```sql
  CREATE POLICY rowback_agent_all ON public.orders TO rowback_agent USING (true) WITH CHECK (true);
  ```
  Rowback's gate, approvals and undo replace RLS for the agent. Your app's own policies for `anon` and `authenticated` stay as they are.
- **`updated_at` triggers:** many Supabase tables have one. Without help, writes to those tables wait for a person, because undo can't restore them exactly. If the triggers only change the row itself, register the table with `--allow-triggers`:
  ```bash
  rowback register public.orders --agent-role rowback_agent --allow-triggers
  ```
- **Schemas:** register only your own schemas, such as `public`. Never register Supabase's `auth` or `storage` schemas.

## Neon
- **Owner role:** the role that owns the database, usually `neondb_owner`.
- **Connection:** the *direct* connection string. Its host has no `-pooler` in it. Rowback's connections use prepared statements, which transaction-mode poolers can break.
- **Branches:** run `init` and `register` once on each branch the agent uses. A branch made *after* setup already has everything.

## Amazon RDS / Aurora PostgreSQL
- **Owner role:** the master user you created with the instance, or the role that owns your tables. It is a member of `rds_superuser`, so it can create the two roles.
- **Connection:** the instance or cluster *writer* endpoint, with `sslmode=require` (or `verify-full` with the RDS CA bundle). Not RDS Proxy.
- **Network:** the gateway needs to reach the database on port 5432. Put it in the same VPC, and keep the database itself off the public internet.

## Common errors
| Message | Fix |
|---|---|
| `Installation cannot be performed by the runtime or control role itself` | `ROWBACK_INSTALL_DSN` must be the owner role, not `rowback_control` or `rowback_agent`. |
| `Role rowback_agent must not be a superuser` | Create the role without `SUPERUSER` (step 1). |
| `... has its own triggers, so this write can't be undone` | See `--allow-triggers` above, or approve those writes by hand. |
| `... cascades into X which is not registered` | Register the FK child table X too. |
| `Undo can switch off triggers on ... only if the role that installed Rowback owns the table` | Run `register` as the table's owner, or leave out `--allow-triggers`. |

None of the provider-specific steps above need a paid plan.
