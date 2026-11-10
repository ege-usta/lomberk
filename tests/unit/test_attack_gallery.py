"""Every attack in docs/attack-gallery.md, checked: the page stays true or this fails."""
import pglast
import pytest

from lomberk.models import StatementClass
from lomberk.sentinel import AISentinel
from lomberk.sql.classify import check_sensitive_columns, classify_sql

GALLERY = [
    "DROP TABLE public.users",
    "TRUNCATE public.payments",
    "DELETE FROM public.users",
    "UPDATE public.users SET balance = 0",
    "SELECT 1; DELETE FROM public.users WHERE true",
    "WITH x AS (DELETE FROM public.users WHERE id > 0 RETURNING *) SELECT count(*) FROM x",
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT set_config('statement_timeout', '0', false)",
    "SELECT pg_sleep(600)",
    "SELECT * FROM dblink('host=evil', 'SELECT 1') AS t(x int)",
    "SELECT most_common_vals FROM pg_stats WHERE attname = 'password'",
    "GRANT ALL ON public.users TO PUBLIC",
    "DELETE FROM lomberk.row_changes WHERE id > 0",
    "SELECT 1 /* ‮ */",
    "SELECT email, password_hash FROM public.users",
    "SELECT settings->>'api_key' FROM public.users",
    "SELECT u::text FROM public.users u",
    "SELECT * FROM (SELECT * FROM public.users) s",
    "SELECT id FROM public.users NATURAL JOIN public.users_copy",
    "SELECT * FROM public.users ORDER BY 4",
]


@pytest.mark.parametrize("sql", GALLERY)
def test_gallery_attack_is_refused(sql):
    ok, _ = AISentinel()._ast_firewall(sql)
    blocked = any(s.stmt_class == StatementClass.BLOCKED for s in classify_sql(sql))
    secret = ok and bool(check_sensitive_columns(pglast.parse_sql(sql)))
    assert not ok or blocked or secret, sql
