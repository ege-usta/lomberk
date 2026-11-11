"""`.env` is read from the directory the command runs in, as with `uvx lomberk ...` from a project."""
import subprocess
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"


def test_dotenv_is_read_from_the_working_directory(tmp_path):
    project, elsewhere = tmp_path / "project", tmp_path / "bin"
    project.mkdir()
    elsewhere.mkdir()
    (project / ".env").write_text("LOMBERK_DOTENV_PROBE=from-cwd\n")
    script = elsewhere / "probe.py"  # a script file, like the installed console entry point
    script.write_text("import os, lomberk.cli\nprint(os.environ.get('LOMBERK_DOTENV_PROBE'))\n")
    out = subprocess.run([sys.executable, str(script)], cwd=project, env={"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"},
                         capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "from-cwd"
