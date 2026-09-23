from undogate.config import load_config
from undogate.policy import PolicyEngine
from undogate.models import StatementClass, ClassifiedStatement

config = load_config()
policy = PolicyEngine(config)

stmt = ClassifiedStatement(sql="UPDATE users SET salary = salary * 10 WHERE id = 1;", stmt_class=StatementClass.WRITE_DML, tables=["users"])
res = policy.evaluate(stmt)
print(res.decision.value, res.reason)
