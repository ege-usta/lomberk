"""Attack catalogue for the AST hard gate: every entry is a way an agent could try to
escape the gateway. A new bypass found later belongs in this list."""
import pytest

from undogate.sentinel import AISentinel

MUST_BLOCK = [
    # stacked / smuggled statements
    "SELECT 1; DELETE FROM public.users WHERE id = 1",
    "DELETE FROM public.users WHERE id = 1; COMMIT",
    # GUC tampering (checkpoint/capability spoofing)
    "SELECT set_config('undogate.checkpoint_id', '1', false)",
    "SELECT current_setting('undogate.capability_token')",
    "UPDATE public.users SET name = current_setting('undogate.capability_token') WHERE id = 1",
    "SET undogate.checkpoint_id = '1'",
    "SET session_replication_role = replica",
    "RESET ALL",
    # side-effect / exfiltration functions
    "SELECT pg_sleep(60)",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT lo_import('/etc/passwd')",
    "SELECT pg_terminate_backend(1)",
    "SELECT nextval('public.users_id_seq')",
    "SELECT dblink('host=evil', 'SELECT 1')",
    "SELECT public.count(1)",
    "SELECT evil.lower('x')",
    # DDL / privilege / session commands
    "DROP TABLE public.users",
    "TRUNCATE public.users",
    "ALTER TABLE public.users DISABLE TRIGGER undogate_capture",
    "GRANT ALL ON public.users TO PUBLIC",
    "CREATE FUNCTION public.f() RETURNS int AS 'SELECT 1' LANGUAGE sql",
    "DO $$ BEGIN DELETE FROM public.users; END $$",
    "COPY public.users TO '/tmp/x'",
    "PREPARE p AS DELETE FROM public.users",
    "CALL public.proc()",
    "LOCK TABLE public.users",
    "SELECT * INTO public.stolen FROM public.users",
    # unscoped writes, including nested in CTEs
    "DELETE FROM public.users",
    "UPDATE public.users SET name = 'x'",
    "WITH d AS (DELETE FROM public.users RETURNING *) SELECT * FROM d",
    # writes hidden inside a statement: outer rowcount would hide their size
    "WITH m AS (DELETE FROM public.orders WHERE true RETURNING id) INSERT INTO public.audit (note) SELECT 'x' FROM m LIMIT 1",
    "WITH m AS (UPDATE public.orders SET total = 0 WHERE true RETURNING id) SELECT count(*) FROM m",
    "WITH m AS (INSERT INTO public.orders (id) VALUES (1) RETURNING id) DELETE FROM public.x WHERE id IN (SELECT id FROM m)",
    "INSERT INTO users (name) VALUES ('x')",
    # malformed input fails closed
    "DELETE FROM public.users WHERE",
]

MUST_ALLOW = [
    "SELECT count(*) FROM public.users",
    "SELECT lower(name), coalesce(plan, 'free') FROM public.users WHERE id = 1",
    "SELECT pg_catalog.now()",
    "UPDATE public.users SET plan = 'pro' WHERE id = 1",
    "DELETE FROM public.users WHERE id = 1",
    "INSERT INTO public.users (name, email) VALUES ('a', 'a@x.io')",
    "WITH recent AS (SELECT id FROM public.users WHERE id > 5) DELETE FROM public.users WHERE id IN (SELECT id FROM recent)",
]


@pytest.mark.parametrize("sql", MUST_BLOCK)
def test_hard_gate_blocks(sql):
    safe, reason = AISentinel()._ast_firewall(sql)
    assert not safe, f"bypass: {sql}"
    assert reason


@pytest.mark.parametrize("sql", MUST_ALLOW)
def test_hard_gate_allows_safe_sql(sql):
    safe, reason = AISentinel()._ast_firewall(sql)
    assert safe, reason
