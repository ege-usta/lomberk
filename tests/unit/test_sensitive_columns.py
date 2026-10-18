"""Secret-looking columns (password, token, secret, ssn, hash, credit_card) must not reach the
agent under any name. Masking works on output column names, so every way to move a secret
into a differently named column, or into one value, has to be refused before execution."""
import pglast
import pytest

from rowback.sql.classify import check_sensitive_columns


def refused(sql: str) -> bool:
    return bool(check_sensitive_columns(pglast.parse_sql(sql)))


LEAKS = [
    "SELECT password_hash FROM public.users",
    "SELECT password_hash AS x FROM public.users",
    "SELECT u FROM public.users u",                                   # whole row as one value
    "SELECT users FROM public.users",
    "SELECT u::text AS x FROM public.users u",
    "SELECT jsonb_build_object('r', u) AS x FROM public.users u",
    "SELECT (u).password_hash AS x FROM public.users u",              # field selection
    "SELECT upper((u).api_token) FROM public.users u",
    "SELECT y FROM (SELECT * FROM public.users) s(a, b, y)",          # * in a subquery, renamed
    "SELECT y FROM (TABLE public.users) s(a, b, y)",
    "SELECT * FROM public.users AS u(a, b, y)",                       # base-table columns renamed
    "SELECT * FROM (public.users JOIN public.t USING (id)) AS j(a, b, y)",
    "SELECT id, name, 'x' AS y FROM public.a UNION ALL SELECT * FROM public.users",
    "WITH s AS (SELECT * FROM public.users) SELECT * FROM s",
    "INSERT INTO public.notes (body) SELECT u::text FROM public.users u",
    "INSERT INTO public.notes SELECT * FROM public.users",
    "SELECT count(*) FROM public.users JOIN public.guess USING (password_hash)",
    "SELECT concat(u.*) FROM public.users u",
    "SELECT id FROM public.users u WHERE u::text LIKE '%a%'",
    "SELECT a FROM public.t WHERE a IN (SELECT * FROM public.users)",
    "SELECT u.pwd FROM public.users u",                               # other common secret names
    "SELECT row(u.id, u.passwd) FROM public.users u",
    "SELECT stripe_api_key FROM public.accounts",
    "SELECT private_key_pem FROM public.certs",
    "SELECT * FROM public.users ORDER BY 4",                          # sorts by a masked column unnamed
    "SELECT * FROM public.users ORDER BY 4 DESC, 1",
    "SELECT u.* FROM public.users u GROUP BY 1, 2, 3, 4",
    "SELECT DISTINCT ON (4) * FROM public.users",
    "SELECT * FROM public.users NATURAL JOIN public.guesses",         # joins on columns never named
    "UPDATE public.t SET a = 1 FROM public.users NATURAL JOIN public.g WHERE t.id = 1",
    "SELECT settings->>'api_key' FROM public.users",                  # secrets inside JSON
    "SELECT settings #>> '{auth,token}' FROM public.users",
    "SELECT settings['stripe_secret'] FROM public.users",
    "SELECT id FROM public.users WHERE settings ? 'password'",
    "SELECT id FROM public.users WHERE settings @> '{\"pwd\": \"x\"}'::jsonb",
    # A JSON key chosen at run time can be any key (security-audit run-3, findings 1-2):
    "SELECT k, settings->>k FROM public.users u, jsonb_object_keys(u.settings) k",
    "SELECT k, jsonb_extract_path_text(u.settings, k) FROM public.users u, jsonb_object_keys(u.settings) k",
    "SELECT settings->>k.name FROM public.users, public.keys k",
    "SELECT settings->>('api_'||'key') FROM public.users",
    "SELECT settings->>coalesce('api_key', '') FROM public.users",
    "SELECT settings #>> ARRAY['auth', 'api_key'] FROM public.users",
    "SELECT jsonb_extract_path_text(settings, VARIADIC ARRAY['api_key']) FROM public.users",
    "SELECT jsonb_extract_path_text(settings, 'api_' || 'key') FROM public.users",
    "SELECT json_extract_path(settings::json, lower('API_KEY')) FROM public.users",
    "SELECT jsonb_set(settings, ARRAY['token'], '1') FROM public.users",
    # Pinned by mutation testing: each one only fails if a branch of the walk is dropped.
    "SELECT id FROM public.users WHERE password IN (SELECT 'x')",  # SubLink testexpr
    "SELECT (api_key)[1] FROM public.users",  # A_Indirection arg
    "SELECT settings['api_key':'z'] FROM public.users",  # slice bound
]

ALLOWED = [
    "SELECT * FROM public.users",                                     # top-level *: masked by name
    "SELECT u.* FROM public.users u",
    "SELECT id, name FROM public.users WHERE id = 1",
    "SELECT count(*) FROM public.users",
    "SELECT id FROM public.t WHERE EXISTS (SELECT * FROM public.users WHERE users.id = t.id)",
    "SELECT 'password' AS label, 'my token' FROM public.t",           # string literals are data
    "SELECT a, b FROM (VALUES (1, 2)) v(a, b)",
    "SELECT id, name FROM public.users ORDER BY 2, 1",
    "SELECT * FROM public.users ORDER BY id",
    "SELECT DISTINCT * FROM public.users",
    "SELECT settings->>'theme' FROM public.users WHERE settings ? 'beta'",
    "UPDATE public.users SET name = 'x' WHERE id = 1 RETURNING *",
    "DELETE FROM public.users WHERE id = 1",
    "SELECT o.id, c.name FROM public.orders o JOIN public.customers c ON c.id = o.customer_id",
    "SELECT tags->0, meta->'items'->-1 FROM public.posts",             # constant keys and indexes
    "SELECT settings #>> ARRAY['ui', 'theme'] FROM public.users",
    "SELECT settings #>> '{ui,theme}' FROM public.users",
    "SELECT jsonb_extract_path_text(meta, 'items', '0', 'sku') FROM public.orders",
    "SELECT item->>'sku' FROM public.orders, jsonb_array_elements(meta->'items') item",
    "SELECT d::date FROM generate_series(now(), now() + interval '2 days', interval '1 day') d",
    "SELECT id FROM public.users WHERE settings @> jsonb_build_object('beta', true)",
    # A secret word in a value compared with `=` or LIKE is data, not a JSON key.
    "SELECT id FROM public.users WHERE status = 'password_reset'",
    "SELECT id FROM public.users WHERE note ILIKE '%token%'",
]


@pytest.mark.parametrize("sql", LEAKS)
def test_every_route_to_a_secret_is_refused(sql):
    assert refused(sql), sql


@pytest.mark.parametrize("sql", ALLOWED)
def test_ordinary_queries_still_pass(sql):
    assert not refused(sql), check_sensitive_columns(pglast.parse_sql(sql))


def test_configured_names_are_secrets_too():
    # sensitive_columns: exact names the keyword list can't guess.
    ast = pglast.parse_sql("SELECT pass, profile FROM public.users")
    assert check_sensitive_columns(ast) == []
    assert set(check_sensitive_columns(ast, ["PASS", "profile"])) == {"pass", "profile"}
    assert not check_sensitive_columns(pglast.parse_sql("SELECT passenger FROM public.trips"), ["pass"])


def test_secret_json_keys_are_masked_in_results():
    from rowback.executor import RowbackExecutor
    ex = RowbackExecutor("x", "y", sensitive_columns=["pin"])
    rows = ex._mask_and_sanitize_rows(
        ["id", "settings", "raw", "pin"],
        [(1, {"theme": "dark", "api_key": "K", "nested": [{"token": "T", "pin": "1234"}]},
          '{"password": "p", "ok": 1}', "9999")])
    assert rows == [{"id": 1, "settings": {"theme": "dark", "api_key": "***MASKED***",
                                          "nested": [{"token": "***MASKED***", "pin": "***MASKED***"}]},
                     "raw": '{"password": "***MASKED***", "ok": 1}', "pin": "***MASKED***"}]


@pytest.mark.parametrize("sql", ["SELECT settings->>'pin' FROM public.users", "SELECT settings['pin'] FROM public.users",
                                 "SELECT jsonb_extract_path_text(settings, 'pin') FROM public.users"])
def test_configured_names_are_secret_json_keys_too(sql):
    assert check_sensitive_columns(pglast.parse_sql(sql), {"pin"}), sql
    assert not refused(sql)
