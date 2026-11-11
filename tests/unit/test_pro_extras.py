"""Slack and SSO need `lomberk[pro]`: without it, one line that says how to install it, never an ImportError."""
import importlib.util

import pytest

from lomberk.config import LomberkConfig
from lomberk.startup import missing_extras, resolve_plan


def hide(monkeypatch, *modules):
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a: None if name in modules else real(name, *a))


def sso_config():
    return LomberkConfig.model_validate({"sso": {"issuer": "https://idp.example.com", "audience": "lomberk"}})


def test_nothing_missing_with_the_extras_installed(monkeypatch):
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    assert missing_extras(sso_config()) == []


def test_sso_without_pyjwt(monkeypatch):
    monkeypatch.delenv("LOMBERK_SLACK_ENABLED", raising=False)
    hide(monkeypatch, "jwt")
    assert missing_extras(sso_config()) == ["SSO"]
    assert missing_extras(LomberkConfig()) == []


def test_slack_without_slack_sdk(monkeypatch):
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    hide(monkeypatch, "slack_sdk", "aiohttp")
    assert missing_extras(LomberkConfig()) == ["Slack approvals"]


def test_startup_refuses_in_one_line(monkeypatch):
    monkeypatch.setenv("LOMBERK_SLACK_ENABLED", "true")
    monkeypatch.setenv("LOMBERK_LICENSE_KEY", "x" * 40)
    hide(monkeypatch, "aiohttp")
    with pytest.raises(ValueError, match=r"Startup Refusal: Slack approvals need.*lomberk\[pro\]"):
        resolve_plan(LomberkConfig())


def test_solo_features_import_without_the_pro_extra(monkeypatch):
    import builtins
    import importlib
    import sys

    real_import = builtins.__import__

    def blocked(name, *a, **kw):
        if name.split(".")[0] in ("jwt", "slack_sdk", "aiohttp"):
            raise ModuleNotFoundError(name)
        return real_import(name, *a, **kw)
    for mod in [m for m in sys.modules if m.startswith("lomberk.ee.")]:
        monkeypatch.delitem(sys.modules, mod)
    monkeypatch.setattr(builtins, "__import__", blocked)
    importlib.import_module("lomberk.ee.panel")
    importlib.import_module("lomberk.ee.export")
