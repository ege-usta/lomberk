import pytest

from rowback.models import StatementClass
from rowback.sql.classify import classify_sql


@pytest.mark.parametrize("sql, expected_class, expected_tables", [
    # READ
    ("SELECT * FROM users;", StatementClass.READ, ["users"]),
    ("SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id;", StatementClass.READ, ["users", "orders"]),
    ("WITH cte AS (SELECT * FROM a) SELECT * FROM cte;", StatementClass.READ, ["a"]),
    ("EXPLAIN SELECT * FROM public.customers;", StatementClass.READ, ["public.customers"]),
    ("SHOW search_path;", StatementClass.READ, []),

    # WRITE_DML
    ("INSERT INTO users (name) VALUES ('Ali');", StatementClass.WRITE_DML, ["users"]),
    ("UPDATE orders SET total = 100 WHERE id = 1;", StatementClass.WRITE_DML, ["orders"]),
    ("DELETE FROM public.customers WHERE id = 5;", StatementClass.WRITE_DML, ["public.customers"]),
    ("INSERT INTO users (id) VALUES (1) ON CONFLICT DO NOTHING;", StatementClass.WRITE_DML, ["users"]),
    ("WITH deleted AS (DELETE FROM users RETURNING *) SELECT * FROM deleted;", StatementClass.WRITE_DML, ["users"]),

    # DDL_REVERSIBLE
    ("TRUNCATE TABLE logs;", StatementClass.DDL_REVERSIBLE, ["logs"]),
    ("DROP TABLE old_data;", StatementClass.DDL_REVERSIBLE, ["old_data"]),
    ("ALTER TABLE users DROP COLUMN age;", StatementClass.DDL_REVERSIBLE, ["users"]),
    ("CREATE TABLE new_table (id INT);", StatementClass.DDL_REVERSIBLE, ["new_table"]),
    ("ALTER TABLE users ADD COLUMN phone TEXT;", StatementClass.DDL_REVERSIBLE, ["users"]),
    ("CREATE INDEX idx_name ON users (name);", StatementClass.DDL_REVERSIBLE, ["users"]),

    # DDL_DANGEROUS
    ("DROP SCHEMA public;", StatementClass.DDL_DANGEROUS, []),
    ("DROP DATABASE mydb;", StatementClass.DDL_DANGEROUS, []),
    ("DROP TABLE users CASCADE;", StatementClass.DDL_DANGEROUS, ["users"]),

    # BLOCKED (Roles, system, etc)
    ("ALTER ROLE admin SET search_path TO public;", StatementClass.BLOCKED, []),
    ("GRANT ALL ON users TO agent;", StatementClass.BLOCKED, ["users"]),
    ("REVOKE SELECT ON orders FROM agent;", StatementClass.BLOCKED, ["orders"]),
    ("CREATE ROLE hacker;", StatementClass.BLOCKED, []),
    ("ALTER SYSTEM SET work_mem = '1GB';", StatementClass.BLOCKED, []),

    # BLOCKED (Rowback schemas)
    ("SELECT * FROM rowback.checkpoints;", StatementClass.BLOCKED, ["rowback.checkpoints"]),
    ("DELETE FROM rowback.row_changes;", StatementClass.BLOCKED, ["rowback.row_changes"]),
    ("TRUNCATE rowback_trash.some_table;", StatementClass.BLOCKED, ["rowback_trash.some_table"]),
    ("UPDATE rowback.checkpoints SET status = 'undone';", StatementClass.BLOCKED, ["rowback.checkpoints"]),

    # UNKNOWN
    ("DO $$ BEGIN RAISE NOTICE 'hello'; END; $$;", StatementClass.UNKNOWN, []),
    ("INVALID SQL SYNTAX HERE", StatementClass.UNKNOWN, []),
])
def test_classify_single_statement(sql, expected_class, expected_tables):
    results = classify_sql(sql)
    assert len(results) == 1
    assert results[0].stmt_class == expected_class
    assert sorted(results[0].tables) == sorted(expected_tables)

def test_classify_multi_statement():
    sql = "SELECT 1; UPDATE users SET a=1; DROP TABLE logs;"
    results = classify_sql(sql)
    assert len(results) == 3
    assert results[0].stmt_class == StatementClass.READ
    assert results[1].stmt_class == StatementClass.WRITE_DML
    assert results[2].stmt_class == StatementClass.DDL_REVERSIBLE
    for r in results:
        assert r.is_multistatement is True

@pytest.mark.parametrize("sql, expected_class, expected_tables", [
    # More READs
    ("SELECT * FROM users FOR UPDATE;", StatementClass.READ, ["users"]),
    ("SELECT count(*) FROM (SELECT id FROM a UNION ALL SELECT id FROM b) c;", StatementClass.READ, ["a", "b"]),
    ("TABLE users;", StatementClass.READ, ["users"]),
    ("SELECT 1 AS one;", StatementClass.READ, []),
    ("VALUES (1, 'a'), (2, 'b');", StatementClass.READ, []),

    # More WRITE_DMLs
    ("UPDATE users SET name = 'x' FROM orders WHERE users.id = orders.u_id;", StatementClass.WRITE_DML, ["users", "orders"]),
    ("WITH updated AS (UPDATE t SET a=1 RETURNING *) SELECT * FROM updated;", StatementClass.WRITE_DML, ["t"]),
    ("INSERT INTO t SELECT * FROM s;", StatementClass.WRITE_DML, ["t", "s"]),
    ("DELETE FROM t WHERE id IN (SELECT id FROM s);", StatementClass.WRITE_DML, ["t", "s"]),
    ("MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET a=s.a WHEN NOT MATCHED THEN INSERT (a) VALUES (s.a);", StatementClass.WRITE_DML, ["t", "s"]),

    # More DDL_REVERSIBLE
    ("DROP VIEW my_view;", StatementClass.DDL_REVERSIBLE, ["my_view"]),
    ("CREATE VIEW my_view AS SELECT 1;", StatementClass.DDL_REVERSIBLE, ["my_view"]),
    ("CREATE MATERIALIZED VIEW mv AS SELECT * FROM users;", StatementClass.DDL_REVERSIBLE, ["mv", "users"]),
    ("DROP TYPE my_type;", StatementClass.DDL_REVERSIBLE, []),
    ("CREATE TYPE my_type AS ENUM ('a', 'b');", StatementClass.DDL_REVERSIBLE, []),
    ("ALTER TABLE t ALTER COLUMN c SET DEFAULT 1;", StatementClass.DDL_REVERSIBLE, ["t"]),
    ("ALTER TABLE t RENAME TO new_t;", StatementClass.DDL_REVERSIBLE, ["t"]),

    # More DDL_DANGEROUS
    ("DROP DATABASE IF EXISTS mydb;", StatementClass.DDL_DANGEROUS, []),
    ("DROP SCHEMA s CASCADE;", StatementClass.DDL_DANGEROUS, []),

    # More BLOCKED
    ("GRANT SELECT ON ALL TABLES IN SCHEMA public TO agent;", StatementClass.BLOCKED, []),
    ("REVOKE ALL PRIVILEGES ON DATABASE mydb FROM public;", StatementClass.BLOCKED, []),
    ("DROP ROLE admin;", StatementClass.BLOCKED, []),
    ("ALTER SYSTEM RESET ALL;", StatementClass.BLOCKED, []),

    # More BLOCKED (rowback schema variants)
    ("SELECT * FROM rowback.checkpoints JOIN public.users ON 1=1;", StatementClass.BLOCKED, ["rowback.checkpoints", "public.users"]),
    ("INSERT INTO rowback_trash.some_table VALUES(1);", StatementClass.BLOCKED, ["rowback_trash.some_table"]),

    # More UNKNOWN
    ("CREATE FUNCTION my_func() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql;", StatementClass.UNKNOWN, []),
    ("EXECUTE 'SELECT 1';", StatementClass.UNKNOWN, []),
    ("PREPARE my_plan AS SELECT * FROM users;", StatementClass.UNKNOWN, ["users"]),
])
def test_classify_more_statements(sql, expected_class, expected_tables):
    results = classify_sql(sql)
    assert len(results) == 1
    assert results[0].stmt_class == expected_class
    assert sorted(results[0].tables) == sorted(expected_tables)
