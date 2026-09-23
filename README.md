# Undogate

**Ctrl+Z for AI Agents.** 
Undogate is an open-source, developer-first MCP gateway for PostgreSQL. It intercepts AI agent SQL queries, transparently logs changes (DML row captures + DDL soft drops), and holds destructive operations (like `TRUNCATE` or massive `DELETE`) for human approval via CLI.

## 🚀 9-Second Database Deletion Demo

In April 2026, an autonomous coding agent famously deleted a production database in 9 seconds. Let's recreate that scenario and see how Undogate saves the day.

### 1. Start the Production Database
```bash
docker-compose up -d
```
This spins up a mock `pocketos` database with `users` and `payments` tables.

### 2. Install Undogate
```bash
export UNDOGATE_ADMIN_DSN="postgresql://test:test@localhost:5432/pocketos"
uv run python src/undogate/cli.py init
```

### 3. Start the MCP Server
Connect your AI agent (Claude Desktop, Cursor, etc.) to this MCP server:
```bash
uv run python src/undogate/cli.py serve
```

### 4. The Agent Goes Rogue
Ask your agent: *"Delete all users."*
The agent will execute: `DELETE FROM public.users;`
Instead of wiping the database immediately, Undogate's `PolicyEngine` detects a massive row deletion or a protected table access.
The MCP tool returns:
`APPROVAL REQUIRED. Token: cp_8a7f9b2. Ask human to run undogate approve cp_8a7f9b2`

### 5. You Decide
In your terminal, you review the pending checkpoint:
```bash
uv run python src/undogate/cli.py approve cp_8a7f9b2
```
If you accidentally approved it and the data is gone, just hit undo:
```bash
uv run python src/undogate/cli.py undo cp_8a7f9b2
```
Instantly, all users and their cascading payments are restored flawlessly via `session_replication_role` magic.

## How It Works
1. **Parser:** Uses native `pglast` (PostgreSQL C parser) to detect AST intent (e.g., `DropStmt`, `TruncateStmt`, `DeleteStmt`).
2. **Policy Engine:** Rejects or holds queries based on `undogate.yaml` configurations.
3. **Capture Katmanı:** Injects `SECURITY DEFINER` `AFTER ROW` triggers that capture state *after* cascading rules apply, storing it in `undogate.row_changes`.
4. **Soft Drop:** DDLs like `DROP TABLE` are rewritten mid-flight to `ALTER TABLE ... SET SCHEMA undogate_trash`.
5. **Undo Engine:** LIFO traversal of changes disables FK constraints temporarily to perfectly reverse the timeline.

## License
Apache-2.0
