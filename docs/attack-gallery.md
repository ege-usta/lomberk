# Attack gallery

Below are 20 things an agent (or a prompt injection) might try, and what Rowback answers. Each row is checked by `tests/unit/test_attack_gallery.py`. If this page ever stops being true, that test fails.

Rowback has three layers. An attack only has to be stopped by one of them; most are stopped by all three.
1. **The parser gate.** PostgreSQL's own parser reads the SQL before anything runs.
2. **The policy.** The statement's class, the tables it touches, and hidden columns.
3. **The database.** The agent's role has no rights beyond the tables you registered, and no `SELECT` on columns you hid.

## Destroying data
| Attempt | SQL | Answer |
|---|---|---|
| Drop a table | `DROP TABLE public.users` | Command DropStmt is structurally banned |
| Wipe a table | `TRUNCATE public.payments` | Command TruncateStmt is structurally banned |
| DELETE with no WHERE | `DELETE FROM public.users` | DELETE statement missing WHERE clause |
| UPDATE with no WHERE | `UPDATE public.users SET balance = 0` | UPDATE statement missing WHERE clause |
| Smuggle a second statement | `SELECT 1; DELETE FROM public.users WHERE true` | Multiple stacked SQL statements detected |
| Hide a write inside a read | `WITH x AS (DELETE … RETURNING *) SELECT count(*) FROM x` | Writes nested inside another statement are structurally banned |
| Erase the undo history | `DELETE FROM rowback.row_changes WHERE id > 0` | Blocked by the policy. The agent's role also has no rights on it. |

A `DELETE` or `UPDATE` with a real `WHERE` still runs. If it touches more rows than your limit, or touches a protected table, it waits for a person. Either way, it can be undone afterwards.

## Escaping the database
| Attempt | SQL | Answer |
|---|---|---|
| Read a server file | `SELECT pg_read_file('/etc/passwd')` | Function pg_read_file() is not on the allowlist |
| Turn off a safety setting | `SELECT set_config('statement_timeout', '0', false)` | Function set_config() is not on the allowlist |
| Tie up the database | `SELECT pg_sleep(600)` | Function pg_sleep() is not on the allowlist |
| Reach another server | `SELECT * FROM dblink('host=evil', …)` | Function dblink() is not on the allowlist |
| Give itself rights | `GRANT ALL ON public.users TO PUBLIC` | Command GrantStmt is structurally banned |
| Fool the human approver | `SELECT 1 /* U+202E */` (invisible text-direction character) | Invisible text-direction characters are not allowed in SQL |

## Reading secrets
Each column listed in `sensitive_columns`, and each column whose name looks secret (`password`, `token`, `api_key`, …), is hidden in two places:
- Rowback refuses any query that could reveal it.
- `rowback register` revokes the agent's `SELECT` on it in the database itself.

| Attempt | SQL | Answer |
|---|---|---|
| Ask for it | `SELECT email, password_hash FROM public.users` | refused: password_hash |
| Pull it out of JSON | `SELECT settings->>'api_key' FROM public.users` | refused: a secret-looking JSON key |
| Cast the whole row to text | `SELECT u::text FROM public.users u` | refused: whole-row reference u |
| Rename it in a subquery | `SELECT * FROM (SELECT * FROM public.users) s` | refused: * outside the top-level select list |
| Compare it without naming it | `SELECT id FROM public.users NATURAL JOIN public.users_copy` | refused: NATURAL JOIN, which compares columns the query never names |
| Sort by it to guess it | `SELECT * FROM public.users ORDER BY 4` | refused: ordering or grouping by column position next to * |
| Read sampled values from statistics | `SELECT most_common_vals FROM pg_stats …` | System catalog pg_stats is not readable |

Naming the columns you need still works: `SELECT id, email FROM public.users`. A `SELECT *` on a registered table with hidden columns is refused by the database, and the agent is told to name its columns. On tables registered before a column was marked secret, results are masked by column name.

## What this page does not claim
- **Stolen credentials.** Rowback can't stop a person or a tool that holds your database's owner credentials. Keep them out of the agent's reach. Rowback exists so the agent never needs them.
- **Infrastructure and cloud API tokens.** An agent with a cloud API token can delete the database server itself, and Rowback never sees that request. In the PocketOS incident, an agent deleted a production database and its backups through an infrastructure token, not through SQL.
- The full threat model and limits are in [SECURITY.md](../SECURITY.md).
