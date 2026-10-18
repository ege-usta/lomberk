"""The other half of the firewall contract: ordinary agent SQL must get through.

test_firewall_attacks.py proves bad SQL is refused. This file proves good SQL is not:
every query below is the kind of thing an agent writes in its first ten minutes (CRUD,
reporting, JSON, search, schema discovery). A false block here is a product bug, because
an agent that keeps hitting "not on the allowlist" gets uninstalled.
"""
import pglast
import pytest

from rowback.sentinel import ALLOWED_FUNCS, AISentinel
from rowback.sql.classify import check_sensitive_columns


def gate(sql: str) -> tuple[bool, str]:
    """Both checks every agent statement meets before it runs: the hard gate, then data minimisation."""
    safe, reason = AISentinel()._ast_firewall(sql)
    if not safe:
        return False, reason
    found = check_sensitive_columns(pglast.parse_sql(sql))
    return not found, f"sensitive: {found}"

AGENT_WORKLOAD = [
    # schema discovery
    "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
    "SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_name = 'orders'",
    "EXPLAIN SELECT * FROM public.orders WHERE customer_id = 42",
    "EXPLAIN (FORMAT JSON) SELECT count(*) FROM public.orders",
    "EXPLAIN (VERBOSE, COSTS) SELECT id FROM public.users WHERE email = 'a@b.co'",
    # plain reads
    "SELECT * FROM public.users WHERE id = 1",
    "SELECT id, email FROM public.users ORDER BY created_at DESC LIMIT 20",
    "SELECT * FROM public.users WHERE email ILIKE '%@gmail.com'",
    "SELECT * FROM public.users WHERE email ~* 'gmail'",
    "SELECT * FROM public.orders WHERE status IN ('paid', 'shipped') AND total BETWEEN 10 AND 100",
    "SELECT EXISTS (SELECT 1 FROM public.users WHERE id = 1)",
    "SELECT DISTINCT country FROM public.users",
    "SELECT * FROM public.users WHERE deleted_at IS NULL",
    "SELECT u.id, o.total FROM public.users u JOIN public.orders o ON o.user_id = u.id WHERE u.id = 7",
    "SELECT * FROM public.users u WHERE NOT EXISTS (SELECT 1 FROM public.orders o WHERE o.user_id = u.id)",
    "SELECT * FROM public.users ORDER BY random() LIMIT 5",
    # reporting / analytics
    "SELECT created_at::date AS day, count(*) FROM public.orders GROUP BY 1 ORDER BY 1",
    "SELECT date_trunc('week', created_at) AS wk, sum(total) FROM public.orders GROUP BY 1",
    "SELECT date_bin('15 minutes', created_at, TIMESTAMPTZ '2026-01-01') AS b, count(*) FROM public.events GROUP BY 1",
    "SELECT * FROM public.orders WHERE created_at > current_date - interval '7 days'",
    "SELECT * FROM public.orders WHERE created_at > now() - make_interval(days => 30)",
    "SELECT status, count(*) FILTER (WHERE total > 100) FROM public.orders GROUP BY status",
    "SELECT id, row_number() OVER (PARTITION BY user_id ORDER BY created_at) FROM public.orders",
    "SELECT id, rank() OVER (ORDER BY total DESC), dense_rank() OVER (ORDER BY total DESC) FROM public.orders",
    "SELECT day, total - lag(total) OVER (ORDER BY day) AS delta FROM public.daily_sales",
    "SELECT day, lead(total, 1, 0) OVER (ORDER BY day) FROM public.daily_sales",
    "SELECT user_id, first_value(id) OVER w, last_value(id) OVER w FROM public.orders "
    "WINDOW w AS (PARTITION BY user_id ORDER BY created_at ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING)",
    "SELECT ntile(4) OVER (ORDER BY total), percent_rank() OVER (ORDER BY total) FROM public.orders",
    "SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY total) FROM public.orders",
    "SELECT percentile_disc(0.9) WITHIN GROUP (ORDER BY latency_ms) FROM public.requests",
    "SELECT mode() WITHIN GROUP (ORDER BY country) FROM public.users",
    "SELECT stddev(total), variance(total), corr(total, items) FROM public.orders",
    "SELECT width_bucket(total, 0, 1000, 10) AS bucket, count(*) FROM public.orders GROUP BY 1",
    "SELECT round(avg(total)::numeric, 2) FROM public.orders",
    "SELECT d::date, coalesce(s.total, 0) FROM generate_series(current_date - 6, current_date, interval '1 day') d "
    "LEFT JOIN public.daily_sales s ON s.day = d::date",
    "WITH monthly AS (SELECT date_trunc('month', created_at) m, sum(total) t FROM public.orders GROUP BY 1) "
    "SELECT m, t, t / nullif(lag(t) OVER (ORDER BY m), 0) - 1 AS growth FROM monthly",
    "SELECT extract(dow FROM created_at) AS weekday, count(*) FROM public.orders GROUP BY 1",
    "SELECT to_char(created_at, 'YYYY-MM') AS month, count(*) FROM public.users GROUP BY 1",
    "SELECT age(now(), created_at) FROM public.users WHERE id = 1",
    "SELECT date_part('epoch', now() - created_at) FROM public.sessions WHERE id = 3",
    "SELECT created_at AT TIME ZONE 'Europe/Istanbul' FROM public.orders WHERE id = 1",
    "SELECT count(*) FILTER (WHERE email IS NULL), num_nulls(phone, email) FROM public.users",
    # text
    "SELECT split_part(email, '@', 2) AS domain, count(*) FROM public.users GROUP BY 1 ORDER BY 2 DESC",
    "SELECT regexp_replace(phone, '[^0-9]', '', 'g') FROM public.users",
    "SELECT (regexp_match(note, 'order #(\\d+)'))[1] FROM public.tickets",
    "SELECT initcap(name), upper(left(name, 1)) FROM public.users",
    "SELECT md5(lower(trim(email))) FROM public.users",
    "SELECT concat(name, ' <', email, '>') FROM public.users",
    "SELECT string_agg(tag, ', ' ORDER BY tag) FROM public.post_tags WHERE post_id = 9",
    "SELECT * FROM public.users WHERE starts_with(email, 'admin')",
    "SELECT concat_ws(' ', first_name, last_name) FROM public.users",
    "SELECT translate(slug, '-', ' ') FROM public.posts",
    # full-text search
    "SELECT id FROM public.posts WHERE to_tsvector('english', body) @@ websearch_to_tsquery('english', 'refund policy')",
    "SELECT id, ts_rank(to_tsvector(body), plainto_tsquery('refund')) r FROM public.posts ORDER BY r DESC LIMIT 5",
    # arrays
    "SELECT unnest(tags) FROM public.posts",
    "SELECT tag, count(*) FROM public.posts, unnest(tags) tag GROUP BY tag",
    "SELECT array_length(tags, 1), cardinality(tags) FROM public.posts",
    "SELECT * FROM public.posts WHERE 'sale' = ANY(tags)",
    "SELECT array_to_string(tags, ',') FROM public.posts",
    "SELECT string_to_array('a,b,c', ',')",
    # json
    "SELECT meta->>'plan' FROM public.users WHERE id = 1",
    "SELECT jsonb_array_length(meta->'items') FROM public.orders",
    "SELECT * FROM public.orders, jsonb_array_elements(meta->'items') item WHERE item->>'sku' = 'A1'",
    "SELECT jsonb_object_keys(meta) FROM public.users WHERE id = 1",
    "SELECT jsonb_build_object('id', id, 'email', email) FROM public.users LIMIT 5",
    "SELECT jsonb_typeof(meta) FROM public.users WHERE id = 1",
    "SELECT jsonb_extract_path_text(meta, 'items', '0', 'sku') FROM public.orders WHERE id = 2",
    "SELECT to_jsonb(name), to_json(created_at) FROM public.users WHERE id = 1",
    # Refused by design, not by accident (SECURITY.md, data minimisation): a whole row
    # (`to_jsonb(o)`) could carry a secret column, so agents name the columns they need.
    # writes
    "INSERT INTO public.users (id, email) VALUES (gen_random_uuid(), 'new@x.io')",
    "INSERT INTO public.users (email, created_at) VALUES ('a@x.io', now()) RETURNING id",
    "INSERT INTO public.orders (user_id, total) SELECT id, 0 FROM public.users WHERE id = 3",
    "INSERT INTO public.users (id, email) VALUES (1, 'x@x.io') ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email",
    "INSERT INTO public.tags (name) VALUES ('a'), ('b') ON CONFLICT DO NOTHING",
    "UPDATE public.users SET plan = 'pro' WHERE id = 1",
    "UPDATE public.users SET meta = jsonb_set(meta, '{plan}', '\"pro\"') WHERE id = 1",
    "UPDATE public.users SET meta = meta || jsonb_build_object('beta', true) WHERE id = 1",
    "UPDATE public.users SET tags = array_append(tags, 'vip') WHERE id = 1",
    "UPDATE public.users SET tags = array_remove(tags, 'trial') WHERE id = 1",
    "UPDATE public.users SET email = lower(trim(email)) WHERE id = 1",
    "UPDATE public.orders SET status = 'cancelled', updated_at = now() WHERE id = 5 RETURNING id, status",
    "UPDATE public.orders o SET total = o.total * 1.2 FROM public.users u WHERE u.id = o.user_id AND u.id = 2",
    "UPDATE public.sessions SET expires_at = now() + interval '1 hour' WHERE id = 4",
    "DELETE FROM public.sessions WHERE expires_at < now()",
    "DELETE FROM public.users WHERE id = 1 RETURNING id",
    "DELETE FROM public.cart_items c USING public.carts k WHERE k.id = c.cart_id AND k.user_id = 3",
    "WITH stale AS (SELECT id FROM public.carts WHERE updated_at < now() - interval '30 days') "
    "DELETE FROM public.carts WHERE id IN (SELECT id FROM stale)",
]

# New ways to misuse the functions and statements this file opened up.
NEWLY_OPENED_ATTACKS = [
    "EXPLAIN ANALYZE DELETE FROM public.users WHERE id = 1",
    "EXPLAIN ANALYZE SELECT * FROM public.users",
    "EXPLAIN (ANALYZE) UPDATE public.users SET plan = 'x' WHERE id = 1",
    "EXPLAIN (ANALYZE false) SELECT 1",
    "EXPLAIN DELETE FROM public.users",
    "EXPLAIN SELECT * FROM pg_catalog.pg_stats",
    "SELECT query_to_xml('DELETE FROM public.users', true, true, '')",
    "SELECT table_to_xml('public.users', true, true, '')",
    "SELECT setseed(0.5)",
    "SELECT repeat('x', 1000000000)",
    "SELECT lpad('x', 1000000000, 'y')",
    "SELECT format('%1073000000s', 'x')",                       # padding width: 1 GB in one call
    "SELECT format('%-1073000000s', 'x')",
    "SELECT public.jsonb_set(meta, '{a}', '1') FROM public.users",
    "SELECT evil.generate_series(1, 3)",
    "SELECT * FROM generate_series(1, 3), pg_sleep(10)",
    "SELECT to_jsonb(current_setting('rowback.capability_token'))",
]


# Secrets inside a JSON column must stay out of reach whatever function an agent tries.
SECRET_JSON_ATTACKS = [
    "SELECT jsonb_extract_path_text(settings, 'api_key') FROM public.users",
    "SELECT jsonb_extract_path(settings, 'auth', 'token') FROM public.users",
    "SELECT strpos(settings::text, 'api_key') FROM public.users",
    "SELECT substring(settings::text, strpos(settings::text, 'secret'), 80) FROM public.users",
    "SELECT regexp_match(settings::text, 'token\":\"([^\"]+)') FROM public.users",
    "SELECT key, value FROM public.users u, jsonb_each_text(u.settings)",
    "SELECT jsonb_each(settings) FROM public.users",
    "SELECT jsonb_path_query(settings, '$.*') FROM public.users",
    "SELECT jsonb_path_exists(settings, '$.* ? (@ starts with \"sk-\")') FROM public.users",
    "SELECT to_jsonb(u) FROM public.users u",
    "SELECT t FROM public.users t",
]


@pytest.mark.parametrize("sql", AGENT_WORKLOAD)
def test_everyday_agent_sql_passes(sql):
    safe, reason = gate(sql)
    assert safe, reason


@pytest.mark.parametrize("sql", NEWLY_OPENED_ATTACKS + SECRET_JSON_ATTACKS)
def test_opened_surface_still_blocks(sql):
    safe, _ = gate(sql)
    assert not safe, f"bypass: {sql}"


def test_workload_pass_rate_is_reported():
    # A single number to track release over release: share of everyday agent SQL let through.
    passed = sum(gate(sql)[0] for sql in AGENT_WORKLOAD)
    assert passed == len(AGENT_WORKLOAD), f"{passed}/{len(AGENT_WORKLOAD)}"


def test_dangerous_names_never_join_the_allowlist():
    # A guard against a well-meant future addition, not just today's list.
    banned = {"set_config", "current_setting", "nextval", "setval", "currval", "setseed", "dblink",
              "query_to_xml", "table_to_xml", "cursor_to_xml", "database_to_xml", "schema_to_xml",
              "repeat", "lpad", "rpad", "array_fill", "format", "lo_import", "lo_export", "txid_current", "version",
              "jsonb_each", "jsonb_each_text", "json_each", "json_each_text", "jsonb_path_query",
              "jsonb_path_query_array", "jsonb_path_query_first", "jsonb_path_exists", "jsonb_path_match"}
    assert not (banned & ALLOWED_FUNCS)
    assert not any(name.startswith("pg_") for name in ALLOWED_FUNCS)
