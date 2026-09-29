# Rowback Seatbelt

**Your agent stops and asks before it drops your database.**

A free Claude Code plugin. When an agent is about to run a destructive database command, Seatbelt pauses it and asks you first, even if you've already allowed the agent to use the shell.

```
Rowback Seatbelt: this looks destructive (DELETE with no real WHERE clause (every row)).
Check the target database before allowing it.
```

## Install
```bash
claude plugin marketplace add ege-usta/rowback
claude plugin install seatbelt@rowback
```
It needs only Python 3 (standard library), no other dependencies. Restart Claude Code after installing.

## What it catches
| Where | Examples |
|---|---|
| SQL through `psql`, `mysql`, `sqlite3`, `duckdb`, `pgcli`, … (`-c`, `-e`, quoted args, heredocs) | `DROP TABLE/DATABASE/SCHEMA`, `TRUNCATE`, `ALTER TABLE … DROP`, `DELETE`/`UPDATE` with no `WHERE` (or `WHERE 1=1`) |
| SQL sent to any MCP tool (Postgres, Supabase, your own) | the same statements, checked per statement |
| Framework and platform CLIs | `dropdb`, `prisma migrate reset`, `prisma db push --accept-data-loss`, `rails db:drop/reset`, `manage.py flush`, `supabase db reset --linked`, `redis-cli FLUSHALL`, `dropDatabase()`, `heroku pg:reset`, `terraform destroy`, `aws rds delete-db-*`, `gcloud sql instances delete`, `fly … destroy`, `neonctl … delete` |

It stays quiet for reads, for writes with a real `WHERE`, for commit messages or greps that only mention SQL, and for local-only resets like `supabase db reset`.

To hard-block instead of asking, set `SEATBELT_MODE=deny` in your environment.

## What it is not
Seatbelt pattern-matches commands, so a determined or obfuscated command can get past it: SQL built at runtime, a file run with `psql -f`, or an API call made with `curl`. It's a seatbelt for honest mistakes, not a security boundary.

For production, **[Rowback](https://github.com/ege-usta/rowback)** is the real gate:
- Agents never hold database credentials.
- SQL is checked by PostgreSQL's own parser.
- Risky writes wait for a human, over Slack, SSO or the CLI.
- Every applied write can be undone row by row, foreign-key cascades included.

## Develop
```bash
python3 -m unittest seatbelt/test_seatbelt.py
claude --plugin-dir ./seatbelt     # try it in a session
```
