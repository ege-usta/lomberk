# Undogate — notes for Claude

MCP gateway that puts AI agents' SQL behind a firewall, human approval and undo. Python 3, FastAPI, psycopg, pglast. Read README.md and SECURITY.md before changing behavior. SECURITY.md is the promise to buyers, so keep it true.

## Commands
- Tests (Docker must be running, testcontainers): `PYTHONPATH=src uv run pytest tests/ -q`
- Fast, no Docker: `PYTHONPATH=src uv run pytest tests/unit -q`
- Core without Enterprise must still pass. Check with a copy that has `src/undogate/ee/` removed.
- Lint: `uv run ruff check src tests`. Existing B008 warnings in api.py are the FastAPI idiom, so leave them.

## Layout
- `src/undogate/policy.py`: AST hard gate + policy. `executor.py`: execution, capture, holds.
- `recovery.py`: undo. `audit.py`: audit log. `api.py`: REST + remote MCP. `cli.py`: CLI.
- `src/undogate/ee/`: Enterprise (Slack, SSO), under a separate license (`ee/LICENSE`).
  - Core never imports `ee` at module load, only lazily when the feature is enabled.
  - Everything outside `ee/` is Apache-2.0.

## Rules
- Security paths fail closed. Any auth/approval/firewall change gets attack tests (see `tests/unit/test_firewall_attacks.py`, `tests/unit/test_sso.py`) and a security review.
- Config is strict (`extra="forbid"`). New options go in `config.py`, README and, if security-relevant, SECURITY.md.
- Git:
  - No `git stash`.
  - No push, and no merge to main, without the owner.
  - Work on feature branches.
- The owner's uncommitted WIP is theirs. Do not edit, stage or commit it unless asked: `.gitignore`, `pyproject.toml`, `uv.lock`, `docs/Phase_3B_*`, `src/undogate/offline_pilot.py`, `tests/integration/test_slack_integration.py`, `poc/`, `graphify-out/`, `.mcp.json`. Check `git status` first.
- `pyjwt` (used by `ee/sso.py`) comes in transitively via `mcp[crypto]`. Declare it in pyproject once the owner's pyproject WIP is resolved.
