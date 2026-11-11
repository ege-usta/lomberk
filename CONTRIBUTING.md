# Contributing to Lomberk

Thanks for helping. Lomberk sits between AI agents and production databases, so changes are held to a high bar: every safety path fails closed, and every claim in [SECURITY.md](SECURITY.md) has to stay true.

## Report a security problem
Don't open a public issue. Follow [SECURITY.md](SECURITY.md).

## Set up
You need [uv](https://docs.astral.sh/uv/) and Docker (the tests start real PostgreSQL containers).
```bash
git clone https://github.com/ege-usta/lomberk && cd lomberk
uv sync --all-groups
PYTHONPATH=src uv run pytest tests/ -q          # everything, needs Docker
PYTHONPATH=src uv run pytest tests/unit -q      # fast, no Docker
```

## Before you open a pull request
- `uv run ruff check src tests seatbelt` is clean.
- `uvx bandit -r src seatbelt --severity-level medium --confidence-level medium` is clean. A known-safe hit gets a `# <why>  # nosec <id>` comment, never a bare suppression.
- A bug fix comes with a test that fails without it.
- A change to the firewall, approvals, auth or undo comes with attack tests (see `tests/unit/test_firewall_attacks.py`) and is explained in the pull request.
- New config options go in `config.py` (config is strict, unknown keys are refused), the README and, if they affect safety, SECURITY.md.
- Core (everything outside `src/lomberk/ee/`) never imports `lomberk.ee` at module load. CI runs the tests with `ee/` removed.

## Licensing of contributions
Code outside `src/lomberk/ee/` is Apache-2.0 and contributions there are accepted under it. `src/lomberk/ee/` is under the Elastic License 2.0 ([ee/LICENSE](src/lomberk/ee/LICENSE)); please open an issue before working on it.
