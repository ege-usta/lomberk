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
