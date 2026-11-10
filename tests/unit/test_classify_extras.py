import pytest

from lomberk.models import StatementClass
from lomberk.sql.classify import classify_sql


@pytest.mark.parametrize("sql, expected_class", [
    ("CREATE VIEW my_view AS SELECT 1;", StatementClass.DDL_REVERSIBLE),
    ("CREATE MATERIALIZED VIEW mv AS SELECT * FROM users;", StatementClass.DDL_REVERSIBLE),
    ("DROP TYPE my_type;", StatementClass.DDL_REVERSIBLE),
    ("CREATE TYPE my_type AS ENUM ('a', 'b');", StatementClass.DDL_REVERSIBLE),
    ("ALTER TABLE t RENAME TO new_t;", StatementClass.DDL_REVERSIBLE),
    ("CREATE FUNCTION my_func() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql;", StatementClass.UNKNOWN),
    ("PREPARE my_plan AS SELECT * FROM users;", StatementClass.UNKNOWN),
])
def test_classify_extras(sql, expected_class):
    results = classify_sql(sql)
    assert len(results) == 1
    assert results[0].stmt_class == expected_class
