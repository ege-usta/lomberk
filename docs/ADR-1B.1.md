# ADR 1B.1: Runtime Identity & Narrow Capture Boundaries

## 1. Context
Rowback's runtime agent currently executes SQL using a connection string (`ROWBACK_AGENT_DSN`). If this DSN is a superuser or the database owner, a compromised LLM could manipulate the ledger (`rowback.checkpoints`), drop capture triggers, or perform arbitrary DDL. Furthermore, DML capture relied purely on `search_path` and `trigger` presence evaluated optimistically.

## 2. Decision: Database Role Matrix
We will strictly separate the **Install (Admin)** identity from the **Runtime (Agent)** identity.

**Role `rowback_admin` (or DB Owner):**
- Used only for `rowback init`, migrations, and tests.
- Creates schemas, tables, and functions. Owns `rowback` schema.

**Role `rowback_agent` (Runtime):**
- `NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`.
- Cannot SET ROLE to admin.
- Has `USAGE` on schema `rowback`.
- Has `EXECUTE` on specific control functions (`begin_checkpoint`, `finish_checkpoint`).
- Does **NOT** have direct `INSERT/UPDATE/DELETE` on `rowback.checkpoints` or `rowback_trash.trashed_rows`. Ledger manipulation is strictly via `SECURITY DEFINER` functions.
- Has NO global privileges on application tables. Privileges are explicitly `GRANT`ed per registered table.

**Function Security:**
- All `rowback.*` functions will use `SECURITY DEFINER` with `SET search_path = rowback, pg_temp`.
- `REVOKE ALL ON FUNCTION ... FROM PUBLIC; GRANT EXECUTE ON FUNCTION ... TO rowback_agent;`

## 3. Decision: Narrow Capture & Registration
A new metadata table `rowback.registered_tables (table_oid OID PRIMARY KEY, schema_name TEXT, table_name TEXT, pk_column TEXT)` will be created.

1. **Registration:** `rowback.register_table('public', 'users', 'id')` (Run by Admin). Validates PK is supported, creates trigger, and `GRANT SELECT, INSERT, UPDATE, DELETE ON public.users TO rowback_agent`.
2. **Execution Hard Gate:** Before executing pending DML, `executor.py` or the policy engine will resolve the target table's `OID` from `pg_class`. It will verify this `OID` exists in `rowback.registered_tables`.
3. **Protection against DDL Races (TOCTOU):** 
   - `SELECT table_oid FROM rowback.registered_tables WHERE schema_name = %s AND table_name = %s`
   - Lock the relation in PostgreSQL: `LOCK TABLE public.users IN ROW EXCLUSIVE MODE;`
   - Execute the statement. If the table was dropped and recreated with the same name, its OID would change, breaking the registration bond or lock. But wait, `executor.py` runs Python. The actual safe way is to enforce it in the DB or via strict explicit OID casting, but PostgreSQL syntax `UPDATE public.users` uses names.
   - For this MVP pilot, we will explicitly verify `pg_class.oid` inside the transaction *after* acquiring a lock, OR we will rely on the `rowback_capture` trigger itself to strictly `DENY` if it detects it's firing outside of an explicitly trusted `rowback.checkpoint_id` context.

## 4. Decision: Trusted Checkpoint Context
- Checkpoint context will be set via `SELECT set_config('rowback.checkpoint_id', cp_id, true)`.
- The `rowback_capture` trigger will read this GUC. If missing, and the current user is `rowback_agent`, it MUST raise an exception (Agent cannot bypass gateway). If the user is NOT `rowback_agent` (e.g. a normal app backend), it will allow the write but will NOT record undo (or will record it as an external transaction).
- To prevent Forge attacks, `set_config` is not enough if the agent can execute arbitrary SQL. BUT the AST Firewall hard-denies `set_config` and `FuncCall`! Therefore, the agent *cannot* manually `set_config` via SQL injection. Only the Python `executor.py` can set it.

## 5. Decision: Read-Only Path
- Read operations (`SELECT`) will be executed using `SET TRANSACTION READ ONLY`.
- No `begin_checkpoint` will be created for `SELECT`.

## 6. Scope Limits
- Only single DB, single tenant.
- Only simple `id` primary keys. No composite keys yet.
- Cascading FKs are out of scope (pilot will just DENY or not capture cascading effects).
