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
