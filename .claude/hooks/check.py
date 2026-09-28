#!/usr/bin/env python3
"""Claude Code hooks for Undogate.

post-edit: after Claude edits a .py file, catch real errors (syntax, undefined names) at once.
stop:      if any .py was edited this turn, run the unit tests (~7s) before Claude may finish.
Exit code 2 feeds the output back to Claude so it fixes the problem itself.
"""
import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
FLAG = ROOT / ".claude" / ".py-edited"


def run(cmd):
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, env={"PYTHONPATH": "src", "PATH": __import__("os").environ["PATH"]})


def post_edit():
    path = json.load(sys.stdin).get("tool_input", {}).get("file_path", "")
    if not path.endswith(".py"):
        return 0
    FLAG.touch()
    r = run(["uv", "run", "--no-sync", "ruff", "check", "--select", "E9,F63,F7,F82", "-q", path])
    if r.returncode:
        print(f"Real error in {path}:\n{r.stdout}{r.stderr}", file=sys.stderr)
        return 2
    return 0


def stop():
    if json.load(sys.stdin).get("stop_hook_active") or not FLAG.exists():
        return 0  # nothing edited, or already retrying: never loop forever
    FLAG.unlink()
    r = run(["uv", "run", "--no-sync", "pytest", "tests/unit", "-q", "-x", "--no-header"])
    if r.returncode:
        print(f"Unit tests fail, fix before finishing:\n{r.stdout[-3000:]}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit({"post-edit": post_edit, "stop": stop}[sys.argv[1]]())
