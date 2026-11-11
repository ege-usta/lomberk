# Changelog

All notable changes to Lomberk. Versions follow [Semantic Versioning](https://semver.org/); before 1.0, a minor version may change behavior.

## [0.2.0] — unreleased

First release on PyPI and the MCP Registry.

### Added
- `lomberk setup`: one owner connection string in, a working deployment out. It creates two least-privilege roles with generated passwords, installs the schema, registers the tables you pick, writes `lomberk.yaml` and a private `.env`, runs `lomberk doctor` and prints the config line for Claude Code, Cursor, Claude Desktop, VS Code and Codex. It never changes a role or file that already exists.
- Agent tools: `describe_tables`, `wait_for_approval` (waits inside the tool call and reports progress), `checkpoint_status` and `list_my_changes`. An agent sees only its own checkpoints.
- `lomberk log` and `GET /v1/checkpoints?status=applied`, to find the checkpoint to undo on the free plan.
- Solo plan ($49/month): one database, 30-day undo window, web panel and audit export.
- `lomberk doctor` tells stdio and HTTP mode apart, shows the plan, and warns about Row Level Security without a policy for the agent and about sequences no registered table uses.
- Supabase session pooler, Railway and `lomberk setup` in [docs/hosted-postgres.md](docs/hosted-postgres.md).

### Changed
- Slack approvals and approver SSO need the `pro` extra: `pip install 'lomberk[pro]'` (or `uvx --from 'lomberk[pro]' lomberk serve`). The Docker image includes it. Without it, the gateway refuses to start with one line that says what to install.
- `lomberk serve` runs the stdio server in the same process, so it works on Windows.
- `init`, `register` and gateway startup print one line that says how to fix the problem, not a traceback.
- The CLI finds `.env` in the working directory, also when run through `uvx`.
- The agent role gets only the sequences its registered tables use, not every sequence in the schema.
- Python 3.12, 3.13 and 3.14 are tested in CI.

### Fixed
- The two-person rule is stored on each held write and enforced in SQL, so an approver can't get around it with a CLI that has a different setting.
- `lomberk serve` (stdio) refuses the same unsafe setups as the HTTP gateway: a superuser role, one role for both connections, a missing license for paid features.
- Approving a write that had no preview still runs only the rows that were held.
- A `COMMIT` the server refused is reported as failed, not as outcome unknown, and an approved write a crash left unfinished can be closed with `lomberk reject`.
- Connection errors no longer show the database host or user to the agent.
- License checks: only a real Polar outage keeps paid features on; a 5xx or malformed reply doesn't, and activation isn't retried after a timeout.
- Secret column names spelled with `\u`, `\u{…}` or `\x` escapes are hidden like plain ones.
- A held write past `approval_timeout_minutes` reads as expired to the agent instead of waiting forever.

### Upgrading from an earlier checkout
1. Run `lomberk init` again as the database owner. It upgrades the schema in place and keeps your checkpoints; the gateway refuses to start against the old schema.
2. Run `lomberk doctor`. If it lists sequences the agent no longer needs, run the `REVOKE` it prints (or see [Upgrading](docs/hosted-postgres.md) for the one-line version).
3. If you use Slack or SSO outside Docker, install `lomberk[pro]`.
