# Lomberk — notes for Claude

MCP gateway that puts AI agents' SQL behind a firewall, human approval and undo. Python 3, FastAPI, psycopg, pglast. Read README.md and SECURITY.md before changing behavior. SECURITY.md is the promise to buyers, so keep it true.

## Commands
- Tests (Docker must be running, testcontainers): `PYTHONPATH=src uv run pytest tests/ -q`
- Fast, no Docker: `PYTHONPATH=src uv run pytest tests/unit -q`
- Core without Enterprise must still pass. Check with a copy that has `src/lomberk/ee/` removed.
- Lint: `uv run ruff check src tests` (and `seatbelt`) — both clean. The rule set and the reasoned ignores (incl. B008, the FastAPI `Depends()` idiom) live in `[tool.ruff]` in pyproject.toml; keep lint clean, and add an ignore with a reason rather than a bare `# noqa`.
- Security scanners (run in CI, reproducible locally, no install needed):
  - Deps/CVEs: `uv export --no-emit-project --format requirements-txt | uvx pip-audit -r /dev/stdin` — must be clean.
  - SAST: `uvx bandit -r src seatbelt --severity-level medium --confidence-level medium` — must be clean. Known-safe hits carry a reasoned `# <why>  # nosec <id>` (reason first so bandit doesn't parse it as a test id); never a bare suppression.
  - Secrets in history: `docker run --rm -v "$PWD":/repo:ro zricethezav/gitleaks:v8.30.1 git /repo --log-opts="--all" --gitleaks-ignore-path /repo/.gitleaksignore` — must be clean (CI job `secrets`).
  - Not in CI, run before a release: `uvx semgrep scan --metrics off --config p/python --config p/security-audit --config p/secrets src seatbelt` (4 known `dynamic-urllib` hits = the same reviewed urlopen sites as bandit); OSV `docker run --rm -v "$PWD":/src:ro ghcr.io/google/osv-scanner scan source --lockfile /src/uv.lock`; API fuzzing with schemathesis against `docker compose up` (export `app.openapi()`, run with the admin and the agent key, `--checks not_a_server_error`).

## Layout
- `src/lomberk/sentinel.py`: AST hard gate (`_ast_firewall`). `policy.py`: allow/hold/deny policy. `executor.py`: execution, capture, holds.
- Undo lives in SQL: `lomberk.execute_undo` in `capture/sql/02_functions.sql`. `recovery.py` is the client-side retry/outcome-unknown helper. `audit.py`: audit log. `api.py`: REST + remote MCP. `cli.py`: CLI.
- `src/lomberk/ee/`: Enterprise (Slack, SSO), under a separate license (`ee/LICENSE`).
  - Core never imports `ee` at module load, only lazily when the feature is enabled.
  - Everything outside `ee/` is Apache-2.0.

## Rules
- Security paths fail closed. Any auth/approval/firewall change gets attack tests (see `tests/unit/test_firewall_attacks.py`, `tests/unit/test_sso.py`) and a security review.
- Config is strict (`extra="forbid"`). New options go in `config.py`, README and, if security-relevant, SECURITY.md.
- Git:
  - No `git stash`.
  - No push, and no merge to main, without the owner.
  - Work on feature branches.
- Uncommitted changes you didn't make are the owner's. Do not edit, stage or commit them unless asked. Check `git status` first.
- Graphify (`graphify-out/`, `.mcp.json`, `.graphifyignore`) and `.impeccable/review/` are local tools, hidden by `.git/info/exclude`. Never commit them.
