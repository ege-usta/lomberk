"""Run: python3 -m unittest seatbelt/test_seatbelt.py  (stdlib only)"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

HOOK = pathlib.Path(__file__).parent / "hooks" / "seatbelt.py"
_spec = importlib.util.spec_from_file_location("seatbelt_hook", HOOK)
seatbelt = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(seatbelt)

DANGEROUS_BASH = [
    'psql "$DATABASE_URL" -c "DROP TABLE users"',
    "psql -c 'delete from public.users'",
    'psql -h prod -c "DELETE FROM orders WHERE 1=1"',
    "psql -c \"UPDATE accounts SET balance = 0\"",
    'psql -c "TRUNCATE payments"',
    "mysql -e 'DROP DATABASE shop'",
    "sqlite3 app.db 'DELETE FROM sessions'",
    'psql <<SQL\nDROP SCHEMA public CASCADE;\nSQL',
    'psql -c "ALTER TABLE users DROP COLUMN email"',
    "dropdb production",
    "npx prisma migrate reset --force",
    "npx prisma db push --accept-data-loss",
    "bin/rails db:drop",
    "rake db:reset",
    "python manage.py flush --noinput",
    "supabase db reset --linked",
    "redis-cli -h cache FLUSHALL",
    "mongosh prod --eval 'db.dropDatabase()'",
    "heroku pg:reset DATABASE_URL --confirm app",
    "terraform destroy -auto-approve",
    "aws rds delete-db-instance --db-instance-identifier prod",
    "gcloud sql instances delete prod-db",
    "fly volumes destroy vol_123",
    "neonctl branches delete main",
    "cd api && psql -c 'drop table users;'",
    # F3: a path-prefixed client must still be inspected
    '/usr/bin/psql "$DATABASE_URL" -c "DROP TABLE users"',
    "./psql -c 'delete from public.users'",
    # F4: a tab-indented `<<-` heredoc terminator must not escape extraction
    "psql <<-SQL\n\tDROP SCHEMA public CASCADE;\n\tSQL",
    # run-2 S1: a quoted trivially-true WHERE ('x'='x') must still count as no real WHERE
    "psql -c \"DELETE FROM orders WHERE '1'='1'\"",
    "psql -c \"UPDATE accounts SET balance = 0 WHERE 'a' = 'a'\"",
    # run-2 S2: an unquoted, backslash-escaped client argument must still be inspected
    "psql -c DROP\\ TABLE\\ users",
    "psql -c DELETE\\ FROM\\ orders",
]

SAFE_BASH = [
    "psql -c 'SELECT * FROM users'",
    'psql -c "DELETE FROM sessions WHERE expires_at < now()"',
    "psql -c \"UPDATE users SET name = 'x' WHERE id = 3\"",
    'git commit -m "fix: DELETE FROM users bug"',
    "grep -r 'DROP TABLE' migrations/",
    "npx prisma migrate dev",
    "supabase db reset",
    "rails db:migrate",
    "ls -la",
    "echo 'TRUNCATE is scary'",
    "cat schema.sql",
    "psql -c SELECT\\ 1",                       # unquoted but harmless: the -c fallback must not false-positive
    "psql -c \"SELECT count(*) FROM orders WHERE 1=1\"",  # 1=1 on a SELECT is not a destructive write
]


def mcp(sql, name="mcp__postgres__query"):
    return {"tool_name": name, "tool_input": {"sql": sql}}


class Seatbelt(unittest.TestCase):
    def test_dangerous_bash_is_caught(self):
        for cmd in DANGEROUS_BASH:
            with self.subTest(cmd=cmd):
                self.assertIsNotNone(seatbelt.check({"tool_name": "Bash", "tool_input": {"command": cmd}}))

    def test_safe_bash_passes(self):
        for cmd in SAFE_BASH:
            with self.subTest(cmd=cmd):
                self.assertIsNone(seatbelt.check({"tool_name": "Bash", "tool_input": {"command": cmd}}))

    def test_mcp_sql_tools(self):
        self.assertIsNotNone(seatbelt.check(mcp("DELETE FROM users")))
        self.assertIsNotNone(seatbelt.check(mcp("drop table users", "mcp__supabase__execute_sql")))
        self.assertIsNotNone(seatbelt.check({"tool_name": "mcp__db__run", "tool_input": {"query": "TRUNCATE t"}}))
        self.assertIsNone(seatbelt.check(mcp("SELECT 1; DELETE FROM t WHERE id = 1")))
        # a second statement with no WHERE is still caught
        self.assertIsNotNone(seatbelt.check(mcp("DELETE FROM t WHERE id = 1; DELETE FROM t")))

    def test_where_inside_a_string_does_not_count(self):
        self.assertIsNotNone(seatbelt.check(mcp("DELETE FROM notes -- WHERE id = 1")))
        self.assertIsNotNone(seatbelt.check(mcp("UPDATE t SET note = 'where am i'")))

    def test_other_tools_ignored(self):
        self.assertIsNone(seatbelt.check({"tool_name": "Write", "tool_input": {"content": "DROP TABLE users"}}))

    def test_oversized_command_fails_closed(self):
        # F4 (ReDoS): an enormous command is not pattern-scanned; it is asked about instead,
        # so a heredoc-bomb can neither hang the hook nor slip through unscanned.
        bomb = "psql <<X\n" * 20000
        self.assertIsNotNone(seatbelt.check({"tool_name": "Bash", "tool_input": {"command": bomb}}))

    def test_nested_and_batched_mcp_sql_is_caught(self):
        # run-2 S3: SQL nested in a dict or batched in a list must be scanned, not skipped.
        self.assertIsNotNone(seatbelt.check({"tool_name": "mcp__db__batch", "tool_input": {"statements": ["SELECT 1", "DROP TABLE users"]}}))
        self.assertIsNotNone(seatbelt.check({"tool_name": "mcp__db__run", "tool_input": {"query": {"sql": "TRUNCATE payments"}}}))
        self.assertIsNone(seatbelt.check({"tool_name": "mcp__db__batch", "tool_input": {"statements": ["SELECT 1", "SELECT 2"]}}))

    def test_oversized_mcp_input_fails_closed(self):
        # run-2 S-ReDoS: the MCP path caps input length before its regexes run, like the Bash path.
        self.assertIsNotNone(seatbelt.check({"tool_name": "mcp__postgres__query", "tool_input": {"sql": "/*" * 20000}}))

    def test_hook_protocol(self):
        run = lambda payload, env=None: subprocess.run(
            [sys.executable, str(HOOK)], input=json.dumps(payload), capture_output=True, text=True, env=env)
        out = run({"tool_name": "Bash", "tool_input": {"command": "dropdb prod"}})
        decision = json.loads(out.stdout)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "ask")
        self.assertIn("Lomberk", decision["permissionDecisionReason"])
        self.assertEqual(run({"tool_name": "Bash", "tool_input": {"command": "ls"}}).stdout, "")
        denied = run({"tool_name": "Bash", "tool_input": {"command": "dropdb prod"}}, env={"SEATBELT_MODE": "deny", "PATH": ""})
        self.assertEqual(json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(run("not json at all").returncode, 0)  # never breaks the session


if __name__ == "__main__":
    unittest.main()
