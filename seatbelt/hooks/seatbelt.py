#!/usr/bin/env python3
"""Rowback Seatbelt: a Claude Code PreToolUse hook that stops an agent before a
destructive database command and asks you first.

It pattern-matches commands and SQL; it is a seatbelt, not a firewall. For a
real gate with approvals and row-level undo on production Postgres, see
https://github.com/ege-usta/rowback
"""
import json
import os
import re
import sys

LEARN_MORE = "For production databases, Rowback adds approvals and row-level undo: github.com/ege-usta/rowback"

# Bash: only look for SQL when a database client is actually invoked, so commit
# messages and greps that merely mention "DROP TABLE" pass. The preceding set
# includes "/" so a path-prefixed client (/usr/bin/psql, ./psql) is still seen.
DB_CLIENT = re.compile(
    r"(^|[\s;&|(/])(psql|pgcli|mysql|mariadb|sqlite3|duckdb|cockroach\s+sql|clickhouse(-client)?|usql|supabase\s+db\s+query)\b", re.I)

# Commands longer than this are not pattern-scanned (the scan would be the only
# slow part on adversarial input); we fail closed and ask instead.
MAX_CMD = 20_000

DESTRUCTIVE_CLI = [
    (r"\bdropdb\b", "dropdb deletes a whole database"),
    (r"\bprisma\s+migrate\s+reset\b", "prisma migrate reset drops and recreates the database"),
    (r"\bprisma\s+db\s+push\b.*(--force-reset|--accept-data-loss)", "prisma db push with data loss accepted"),
    (r"\b(rails|rake)\s+db:(drop|reset|schema:load|purge)\b", "rails db task that wipes the database"),
    (r"\bmanage\.py\s+flush\b", "django flush deletes all rows"),
    (r"\bsupabase\s+db\s+reset\b.*(--linked|--db-url)", "supabase db reset against a remote database"),
    (r"\bredis-cli\b.*\bflush(all|db)\b", "redis FLUSHALL/FLUSHDB"),
    (r"\bdropDatabase\s*\(", "MongoDB dropDatabase()"),
    (r"\bheroku\s+pg:reset\b", "heroku pg:reset"),
    (r"\bterraform\s+destroy\b", "terraform destroy"),
    (r"\baws\s+rds\s+delete-db-(instance|cluster)\b", "deleting an RDS database"),
    (r"\bgcloud\s+sql\s+instances\s+delete\b", "deleting a Cloud SQL instance"),
    (r"\bfly(ctl)?\s+(volumes?|postgres|apps?)\s+destroy\b", "fly destroy"),
    (r"\bneonctl\s+(branches|projects)\s+delete\b", "deleting a Neon branch or project"),
]

SQL_STATEMENT_RULES = [
    (r"^\s*drop\s+(table|database|schema|view|materialized\s+view)\b", "DROP"),
    (r"^\s*truncate\b", "TRUNCATE"),
    (r"^\s*alter\s+table\b.*\bdrop\b", "ALTER TABLE ... DROP"),
]
# `_strip` runs first and rewrites every string literal to '', so a quoted trivially-true
# comparison like WHERE 'x'='x' arrives here as WHERE ''='' — match that, not the pre-strip '1'='1'.
TRIVIAL_WHERE = re.compile(r"\bwhere\s+(1\s*=\s*1|true|''\s*=\s*'')\s*$", re.I)


def _strip(sql):
    """Remove comments and string literals so a WHERE inside them doesn't count."""
    sql = re.sub(r"--[^\n]*", " ", sql)
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return re.sub(r"'(?:''|[^'])*'", "''", sql)


def check_sql(text):
    for stmt in _strip(text).split(";"):
        s = " ".join(stmt.split()).lower()
        if not s:
            continue
        for pat, what in SQL_STATEMENT_RULES:
            if re.search(pat, s):
                return f"{what} statement"
        is_delete = re.match(r"^(with\b.*\)\s*)?delete\s+from\b", s)
        is_update = re.match(r"^(with\b.*\)\s*)?update\b.*\bset\b", s)
        if (is_delete or is_update) and (" where " not in f" {s} " or TRIVIAL_WHERE.search(s)):
            return f"{'DELETE' if is_delete else 'UPDATE'} with no real WHERE clause (every row)"
    return None


def _sql_in_command(cmd):
    """Pull the SQL a DB client would run: -c/-e/--command args, quoted args, heredocs."""
    # `\n\t*\1`: the `<<-` heredoc form lets the closing terminator be tab-indented, so a plain
    # `\n\1` anchor would miss it and the body would never be scanned.
    parts = re.findall(r"<<-?\s*['\"]?(\w+)['\"]?\n(.*?)\n\t*\1", cmd, re.S)
    chunks = [body for _, body in parts]
    chunks += re.findall(r"\"((?:\\.|[^\"\\])*)\"", cmd) + re.findall(r"'([^']*)'", cmd)
    # An unquoted argument with backslash-escaped spaces (psql -c DROP\ TABLE\ users) carries no
    # quote or heredoc, so the patterns above miss it. Grab the value after a -c/-e/--command/
    # --execute flag as a run of escaped-or-non-space chars, then resolve the backslashes.
    for val in re.findall(r"(?:--command|--execute|-c|-e)(?:=|\s+)((?:\\.|\S)+)", cmd):
        if val[:1] not in ("'", '"'):
            chunks.append(re.sub(r"\\(.)", r"\1", val))
    return chunks


def _iter_strings(value):
    """Every string leaf in a nested tool_input, so SQL that an MCP tool nests or batches
    (e.g. {"statements": ["DROP TABLE x"]}) is scanned, not just top-level string values."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _iter_strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _iter_strings(v)


def check(event):
    tool = event.get("tool_name", "")
    data = event.get("tool_input") or {}
    if tool == "Bash":
        cmd = data.get("command", "")
        if len(cmd) > MAX_CMD:
            return "command too long to inspect safely"
        for pat, why in DESTRUCTIVE_CLI:
            if re.search(pat, cmd, re.I | re.S):
                return why
        if DB_CLIENT.search(cmd):
            for chunk in _sql_in_command(cmd):
                found = check_sql(chunk)
                if found:
                    return found
        return None
    if tool.startswith("mcp__"):
        for value in _iter_strings(data):
            if len(value) > MAX_CMD:  # same ReDoS fail-safe as the Bash path
                return "input too long to inspect safely"
            found = check_sql(value)
            if found:
                return found
    return None


def main():
    try:
        event = json.load(sys.stdin)
        found = check(event) if isinstance(event, dict) else None
    except Exception:
        # A seatbelt must never break the session: on any error, stay silent and allow.
        return
    if not found:
        return
    mode = "deny" if os.environ.get("SEATBELT_MODE") == "deny" else "ask"
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": mode,
        "permissionDecisionReason": f"Rowback Seatbelt: this looks destructive ({found}). Check the target database before allowing it. {LEARN_MORE}",
    }}))


if __name__ == "__main__":
    main()
