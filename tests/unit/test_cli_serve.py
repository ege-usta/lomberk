"""`lomberk serve` runs the stdio server in this process (os.exec* doesn't replace the process on Windows)."""
import os

from typer.testing import CliRunner

from lomberk import server
from lomberk.cli import app


def test_serve_runs_main_in_process(monkeypatch):
    ran = []
    monkeypatch.setattr(server, "main", lambda: ran.append(os.getpid()))
    monkeypatch.setattr(os, "execvp", lambda *a: (_ for _ in ()).throw(AssertionError("exec")))
    assert CliRunner().invoke(app, ["serve"]).exit_code == 0
    assert ran == [os.getpid()]
