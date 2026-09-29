"""Run: python3 -m unittest seatbelt/test_seatbelt.py  (stdlib only)"""
import json
import pathlib
import subprocess
import sys
import importlib.util
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

    def test_hook_protocol(self):
        run = lambda payload, env=None: subprocess.run(  # noqa: E731
            [sys.executable, str(HOOK)], input=json.dumps(payload), capture_output=True, text=True, env=env)
        out = run({"tool_name": "Bash", "tool_input": {"command": "dropdb prod"}})
        decision = json.loads(out.stdout)["hookSpecificOutput"]
        self.assertEqual(decision["permissionDecision"], "ask")
        self.assertIn("Rowback", decision["permissionDecisionReason"])
        self.assertEqual(run({"tool_name": "Bash", "tool_input": {"command": "ls"}}).stdout, "")
        denied = run({"tool_name": "Bash", "tool_input": {"command": "dropdb prod"}}, env={"SEATBELT_MODE": "deny", "PATH": ""})
        self.assertEqual(json.loads(denied.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(run("not json at all").returncode, 0)  # never breaks the session


if __name__ == "__main__":
    unittest.main()
