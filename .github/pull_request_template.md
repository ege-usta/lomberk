## What and why

## Checks
- [ ] `PYTHONPATH=src uv run pytest tests/` passes (needs Docker)
- [ ] `uv run ruff check src tests seatbelt` and bandit are clean
- [ ] A bug fix has a test that fails without it
- [ ] Firewall, approval, auth or undo changes have attack tests, and SECURITY.md is still true
