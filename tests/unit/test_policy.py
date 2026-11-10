import pytest

from lomberk.config import LimitsConfig, LomberkConfig
from lomberk.models import ClassifiedStatement, PolicyDecision, StatementClass
from lomberk.policy import PolicyEngine


@pytest.fixture
def policy_engine():
    config = LomberkConfig(
        limits=LimitsConfig(max_rows_without_approval=50),
        protected_tables=["public.users"],
        deny_patterns=["DROP_SCHEMA"]
    )
    return PolicyEngine(config)

def test_policy_read(policy_engine):
    stmt = ClassifiedStatement(sql="SELECT 1", stmt_class=StatementClass.READ, tables=["public.users"])
    eval = policy_engine.evaluate(stmt)
    assert eval.decision == PolicyDecision.ALLOW

def test_policy_blocked(policy_engine):
    stmt = ClassifiedStatement(sql="ALTER ROLE", stmt_class=StatementClass.BLOCKED, tables=[])
    eval = policy_engine.evaluate(stmt)
    assert eval.decision == PolicyDecision.DENY

def test_policy_ddl_dangerous(policy_engine):
    stmt = ClassifiedStatement(sql="DROP DATABASE", stmt_class=StatementClass.DDL_DANGEROUS, tables=[])
    eval = policy_engine.evaluate(stmt)
    assert eval.decision == PolicyDecision.DENY

def test_policy_protected_table_write(policy_engine):
    stmt = ClassifiedStatement(sql="UPDATE public.users SET name='a'", stmt_class=StatementClass.WRITE_DML, tables=["public.users"])
    eval = policy_engine.evaluate(stmt)
    assert eval.decision == PolicyDecision.REQUIRE_APPROVAL

def test_policy_unprotected_table_write(policy_engine):
    stmt = ClassifiedStatement(sql="UPDATE public.orders SET amount=1 WHERE id=1", stmt_class=StatementClass.WRITE_DML, tables=["public.orders"])
    eval = policy_engine.evaluate(stmt)
    # Without rows_affected, assumes it might be under limit, so ALLOW_WITH_CAPTURE
    assert eval.decision == PolicyDecision.ALLOW_WITH_CAPTURE

def test_policy_rows_affected_limit(policy_engine):
    stmt = ClassifiedStatement(sql="DELETE FROM public.orders WHERE id=1", stmt_class=StatementClass.WRITE_DML, tables=["public.orders"])
    eval = policy_engine.evaluate(stmt, rows_affected=40)
    assert eval.decision == PolicyDecision.ALLOW_WITH_CAPTURE

    eval_over = policy_engine.evaluate(stmt, rows_affected=51)
    assert eval_over.decision == PolicyDecision.REQUIRE_APPROVAL

def test_policy_deny_pattern(policy_engine):
    stmt = ClassifiedStatement(sql="CREATE TABLE DROP_SCHEMA", stmt_class=StatementClass.DDL_REVERSIBLE, tables=[])
    eval = policy_engine.evaluate(stmt)
    assert eval.decision == PolicyDecision.DENY

def test_policy_unknown(policy_engine):
    stmt = ClassifiedStatement(sql="DO $$ $$", stmt_class=StatementClass.UNKNOWN, tables=[])
    eval = policy_engine.evaluate(stmt)
    assert eval.decision == PolicyDecision.REQUIRE_APPROVAL


def test_config_typo_is_rejected_not_silently_ignored(tmp_path):
    import pytest
    from pydantic import ValidationError

    from lomberk.config import load_config
    cfg = tmp_path / "lomberk.yaml"
    cfg.write_text("protected_table:\n  - public.users\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg))
    cfg.write_text("limits:\n  max_row_without_approval: 5\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg))


def test_protected_tables_must_name_a_schema():
    # A bare name never matches the schema.table a write names, so it would protect nothing.
    import pydantic
    with pytest.raises(pydantic.ValidationError, match="schema.table"):
        LomberkConfig(protected_tables=["orders"])
