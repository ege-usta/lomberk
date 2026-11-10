
from lomberk.config import LomberkConfig
from lomberk.models import (
    ClassifiedStatement,
    PolicyDecision,
    StatementClass,
    StatementEvaluation,
)


class PolicyEngine:
    def __init__(self, config: LomberkConfig):
        self.config = config

    def evaluate(self, stmt: ClassifiedStatement, rows_affected: int | None = None) -> StatementEvaluation:
        # 1. Check BLOCKED or DENY rules first
        if stmt.stmt_class == StatementClass.BLOCKED:
            return StatementEvaluation(statement=stmt, decision=PolicyDecision.DENY, reason="Statement class is BLOCKED.")

        if stmt.stmt_class == StatementClass.DDL_DANGEROUS:
            return StatementEvaluation(statement=stmt, decision=PolicyDecision.DENY, reason="Dangerous DDL operations are not allowed.")

        # Check deny patterns (rudimentary string matching or AST type matching)
        for pattern in self.config.deny_patterns:
            if pattern.lower() in stmt.sql.lower():
                return StatementEvaluation(statement=stmt, decision=PolicyDecision.DENY, reason=f"Matches deny pattern: {pattern}")

        # 2. Check protected tables
        for table in stmt.tables:
            if table in self.config.protected_tables:
                if stmt.stmt_class in (StatementClass.WRITE_DML, StatementClass.DDL_REVERSIBLE, StatementClass.UNKNOWN):
                    return StatementEvaluation(statement=stmt, decision=PolicyDecision.REQUIRE_APPROVAL, reason=f"Table {table} is protected.")

        # 3. Class-based defaults
        if stmt.stmt_class == StatementClass.READ:
            return StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW, reason="Read-only statement.")

        elif stmt.stmt_class == StatementClass.UNKNOWN:
            return StatementEvaluation(statement=stmt, decision=PolicyDecision.REQUIRE_APPROVAL, reason="Unknown or dynamic statement requires approval.")

        elif stmt.stmt_class == StatementClass.DDL_REVERSIBLE:
            return StatementEvaluation(statement=stmt, decision=PolicyDecision.REQUIRE_APPROVAL, reason="Reversible DDL requires approval.")

        elif stmt.stmt_class == StatementClass.WRITE_DML:
            if rows_affected is not None and rows_affected > self.config.limits.max_rows_without_approval:
                return StatementEvaluation(statement=stmt, decision=PolicyDecision.REQUIRE_APPROVAL, reason=f"Rows affected ({rows_affected}) exceeds limit ({self.config.limits.max_rows_without_approval}).")

            # AI Sentinel (Semantic Anomaly Detection)
            from lomberk.sentinel import AISentinel
            sentinel = AISentinel()
            is_safe, ai_reason = sentinel.evaluate_intent(stmt.sql, stmt.tables)
            if not is_safe:
                return StatementEvaluation(statement=stmt, decision=PolicyDecision.REQUIRE_APPROVAL, reason=f"AI Sentinel Blocked: {ai_reason}")

            return StatementEvaluation(statement=stmt, decision=PolicyDecision.ALLOW_WITH_CAPTURE, reason="DML statement within limits.")

        return StatementEvaluation(statement=stmt, decision=PolicyDecision.DENY, reason="Fallback deny.")

