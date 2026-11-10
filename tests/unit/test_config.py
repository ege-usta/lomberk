import pytest

from rowback.config import RowbackConfig, quorum_without_identity_source


def test_quorum_without_identity_source(monkeypatch):
    # A >1 quorum with no SSO and no Slack is a silent deadlock (admin-key/CLI approvals don't count),
    # so startup must refuse it. With a single approver, or with an identity source, it is fine.
    monkeypatch.delenv("ROWBACK_SLACK_ENABLED", raising=False)
    assert quorum_without_identity_source(RowbackConfig(approvals={"required": 1})) is False
    assert quorum_without_identity_source(RowbackConfig(approvals={"required": 2})) is True

    monkeypatch.setenv("ROWBACK_SLACK_ENABLED", "true")
    assert quorum_without_identity_source(RowbackConfig(approvals={"required": 2})) is False
    monkeypatch.setenv("ROWBACK_SLACK_ENABLED", "false")
    cfg = RowbackConfig(approvals={"required": 2},
                        sso={"issuer": "https://issuer.example", "allowed_identities": ["a@x.io"]})
    assert quorum_without_identity_source(cfg) is False  # SSO issuer is an identity source


def test_rowback_config_env_points_at_the_config(tmp_path, monkeypatch):
    from rowback.config import load_config
    cfg = tmp_path / "prod.yaml"
    cfg.write_text("protected_tables:\n  - public.users\n")
    monkeypatch.chdir(tmp_path / "..")
    monkeypatch.setenv("ROWBACK_CONFIG", str(cfg))
    assert load_config().protected_tables == ["public.users"]


def test_missing_rowback_config_file_refuses_startup(tmp_path, monkeypatch):
    # Falling back to defaults here would silently run with no protected tables.
    from rowback.config import load_config
    monkeypatch.setenv("ROWBACK_CONFIG", str(tmp_path / "typo.yaml"))
    with pytest.raises(ValueError, match="does not exist"):
        load_config()


def test_missing_default_config_warns_once_and_uses_defaults(tmp_path, monkeypatch, capsys):
    from rowback import config as config_module
    monkeypatch.delenv("ROWBACK_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config_module, "_warned_missing", set())
    assert config_module.load_config().protected_tables == []
    config_module.load_config()
    err = capsys.readouterr().err
    assert err.count("no config at") == 1 and "ROWBACK_CONFIG" in err and str(tmp_path) in err


def test_empty_rowback_config_env_means_default_path(tmp_path, monkeypatch):
    from rowback.config import config_path
    monkeypatch.setenv("ROWBACK_CONFIG", "")
    assert config_path() == "rowback.yaml"


def test_config_error_names_the_bad_key():
    from pydantic import ValidationError

    from rowback.config import config_error_message
    with pytest.raises(ValidationError) as e:
        RowbackConfig(protected_table=["public.users"])
    assert config_error_message(e.value) == "protected_table: Extra inputs are not permitted"
    with pytest.raises(ValidationError) as e:
        RowbackConfig(limits={"max_row_without_approval": 5})
    assert config_error_message(e.value).startswith("limits.max_row_without_approval:")
