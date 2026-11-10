from enum import Enum

from pydantic import BaseModel


class StatementClass(str, Enum):
    READ = "READ"
    WRITE_DML = "WRITE_DML"
    DDL_REVERSIBLE = "DDL_REVERSIBLE"
    DDL_DANGEROUS = "DDL_DANGEROUS"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"

class PolicyDecision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_CAPTURE = "ALLOW_WITH_CAPTURE"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"

class ClassifiedStatement(BaseModel):
    sql: str
    stmt_class: StatementClass
    tables: list[str]
    is_multistatement: bool = False

class StatementEvaluation(BaseModel):
    statement: ClassifiedStatement
    decision: PolicyDecision
    reason: str
