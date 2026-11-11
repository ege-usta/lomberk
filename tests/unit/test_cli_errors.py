"""CLI failures are one line that says what went wrong, never a traceback."""
import logging

from typer.testing import CliRunner

from lomberk.cli import _OneLineStartupError, app

BAD_DSN = "postgresql://nobody:x@127.0.0.1:1/db"


def test_init_and_register_with_an_unreachable_database(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LOMBERK_CONFIG", raising=False)
    for args in (["init", "--control-role", "c", "--agent-role", "a", "--install-dsn", BAD_DSN],
                 ["register", "public.orders", "--agent-role", "a", "--install-dsn", BAD_DSN]):
        r = CliRunner().invoke(app, args)
        assert r.exit_code == 1, r.output
        assert "Traceback" not in r.output and "could not connect" in r.output


def test_api_startup_refusal_is_logged_as_its_reason():
    tb = ('Traceback (most recent call last):\n  File "api.py", line 68, in lifespan\n'
          "ValueError: Startup Refusal: Database DSN must be provided via LOMBERK_AGENT_DSN.")
    record = logging.LogRecord("uvicorn.error", logging.ERROR, "", 0, tb, (), None)
    assert _OneLineStartupError().filter(record)
    assert record.getMessage() == "Startup Refusal: Database DSN must be provided via LOMBERK_AGENT_DSN."
    plain = logging.LogRecord("uvicorn.error", logging.INFO, "", 0, "Waiting for %s", ("startup",), None)
    assert _OneLineStartupError().filter(plain) and plain.getMessage() == "Waiting for startup"
