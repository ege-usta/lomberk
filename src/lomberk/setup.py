"""`lomberk setup`: from one owner connection string to a deployment `lomberk doctor` passes.

It creates the two roles with generated passwords, installs the schema, registers the chosen
tables, and writes lomberk.yaml and a private .env. It never changes a role or file that
already exists, so running it twice can't rotate a password something else still uses.
"""
import json
import os
import re
import secrets
import shlex
import shutil
from dataclasses import dataclass

import psycopg
import yaml
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from lomberk.sql.classify import is_secret

CONTROL_ROLE, AGENT_ROLE = "lomberk_control", "lomberk_agent"
# Platform schemas an agent's writes have no business in (Supabase, extensions, catalogs).
SKIP_SCHEMAS = ("lomberk", "information_schema", "auth", "storage", "realtime", "extensions", "graphql",
                "graphql_public", "vault", "pgsodium", "pgsodium_masks", "net", "cron", "supabase_functions",
                "supabase_migrations", "_realtime", "pgbouncer")


class SetupError(Exception):
    """A one-line reason setup stopped, with what to do about it."""


@dataclass
class TableInfo:
    name: str  # schema.table
    has_pk: bool
    triggers: int
    rls: bool


def list_tables(conn) -> list[TableInfo]:
    """Ordinary and partitioned tables in the user's own schemas, with what decides if they can be registered."""
    rows = conn.execute("""
        SELECT n.nspname || '.' || c.relname,
               EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p'),
               (SELECT count(*) FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
                  AND t.tgname NOT LIKE 'lomberk%%'),
               c.relrowsecurity
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
          AND n.nspname NOT LIKE 'pg\\_%%' AND n.nspname <> ALL(%s)
        ORDER BY 1""", (list(SKIP_SCHEMAS),)).fetchall()
    return [TableInfo(name, has_pk, triggers, rls) for name, has_pk, triggers, rls in rows]


def register_table(conn, table: str, agent_role: str, pk: str | None = None, allow_triggers: bool = False,
                   extra_secrets: list[str] | None = None) -> tuple[list[str], str | None]:
    """Put one schema.table under Lomberk: (columns hidden from the agent, an unregistered cascade child or None)."""
    schema, _, name = table.partition(".")
    qualified = f'"{schema}"."{name}"'
    columns = [r[0] for r in conn.execute(
        "SELECT attname FROM pg_attribute WHERE attrelid = %s::regclass AND attnum > 0 AND NOT attisdropped",
        (qualified,))]
    hidden = [c for c in columns if is_secret(c, extra_secrets or [])]
    conn.execute("SELECT lomberk.register_table(%s, %s, %s, %s, %s, %s)", (schema, name, pk, agent_role, hidden, allow_triggers))
    unprotected = conn.execute("SELECT lomberk.unprotected_cascade_child(%s::regclass)", (qualified,)).fetchone()[0]
    return hidden, unprotected


def login_name(role: str, owner_user: str) -> str:
    """Supabase's pooler logs in as `role.<project ref>`; every other host uses the role name."""
    m = re.fullmatch(r"[^.]+\.([a-z0-9]+)", owner_user or "")
    return f"{role}.{m.group(1)}" if m else role


def client_command() -> list[str]:
    """How an MCP client should start the gateway: uvx when this run came from uvx's cache, else this install."""
    exe = shutil.which("lomberk")
    if not exe or "/uv/" in exe or "/archive-v" in exe:
        return ["uvx", "lomberk", "serve"]
    return [exe, "serve"]


def client_instructions(config_path: str) -> str:
    """What to paste into each MCP client. Only the config path goes there; the secrets stay in .env beside it."""
    cmd = client_command()
    command, args, env = json.dumps(cmd[0]), json.dumps(cmd[1:]), json.dumps({"LOMBERK_CONFIG": config_path})
    entry = f'{{"command": {command}, "args": {args}, "env": {env}}}'
    return f"""Claude Code:
  claude mcp add lomberk -e {shlex.quote("LOMBERK_CONFIG=" + config_path)} -- {shlex.join(cmd)}
Cursor (.cursor/mcp.json) or Claude Desktop (claude_desktop_config.json):
  {{"mcpServers": {{"lomberk": {entry}}}}}
VS Code (.vscode/mcp.json):
  {{"servers": {{"lomberk": {entry}}}}}
Codex (~/.codex/config.toml):
  [mcp_servers.lomberk]
  command = {command}
  args = {args}
  env = {{ LOMBERK_CONFIG = {json.dumps(config_path)} }}"""


def check_files(directory: str) -> tuple[str, str]:
    """Checked before any database change: once the roles exist, a file that can't be written loses their passwords."""
    if not os.path.isdir(directory):
        raise SetupError(f"{directory} is not a directory. Create it first, or pass --dir.")
    if not os.access(directory, os.W_OK | os.X_OK):
        raise SetupError(f"can't write to {directory}. Pass --dir with a folder you can write to.")
    config, env = os.path.join(directory, "lomberk.yaml"), os.path.join(directory, ".env")
    for path in (config, env):
        if os.path.exists(path):
            raise SetupError(f"{path} already exists. Setup never overwrites it; move it away or use "
                             "`lomberk init` and `lomberk register` on an existing deployment.")
    return config, env


def connect(owner_dsn: str):
    if "${" in owner_dsn:  # python-dotenv expands ${VAR} in .env values whatever the quoting
        raise SetupError("the connection string contains ${, which .env would read as a variable. "
                         "Use the value itself, or set Lomberk up by hand with lomberk init.")
    try:
        return psycopg.connect(owner_dsn, autocommit=True, connect_timeout=10)
    except psycopg.Error as e:
        raise SetupError(f"could not connect with the owner connection string: {str(e).strip().splitlines()[-1]}") from None


def check_roles_absent(conn) -> None:
    for role in (CONTROL_ROLE, AGENT_ROLE):
        if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
            raise SetupError(f"role {role} already exists. Setup won't change its password (something may be using it). "
                             "Drop it first, or use `lomberk init` with the roles you have.")


def create_roles(conn, owner_dsn: str) -> tuple[str, str]:
    """Create both roles with fresh passwords; return their connection strings."""
    owner_user = conninfo_to_dict(owner_dsn).get("user") or ""
    dsns = []
    for role in (CONTROL_ROLE, AGENT_ROLE):
        password = secrets.token_hex(24)
        # Hashed here, so the plain password never reaches the server's statement log.
        verifier = conn.pgconn.encrypt_password(password.encode(), role.encode(), b"scram-sha-256").decode()
        try:
            conn.execute(sql.SQL("CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}").format(
                sql.Identifier(role), sql.Literal(verifier)))
        except psycopg.Error as e:
            raise SetupError(f"could not create role {role}: {str(e).strip().splitlines()[0]}. "
                             "The owner connection needs the CREATEROLE privilege.") from None
        dsns.append(make_conninfo(owner_dsn, user=login_name(role, owner_user), password=password))
    return dsns[0], dsns[1]


def env_quote(value: str) -> str:
    """A single-quoted .env value; only \\ and ' need escaping. connect() refuses ${, which dotenv would expand."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def write_files(config_path: str, env_path: str, protect: list[str], control_dsn: str, agent_dsn: str) -> None:
    config = {"protected_tables": protect, "limits": {"max_rows_without_approval": 100}}
    with open(config_path, "w") as f:
        f.write("# Written by `lomberk setup`. Every write to protected_tables waits for a human;\n"
                "# writes larger than max_rows_without_approval wait too. See README for all keys.\n")
        yaml.safe_dump(config, f, sort_keys=False)
    values = {"LOMBERK_CONFIG": os.path.abspath(config_path), "LOMBERK_ADMIN_DSN": control_dsn,
              "LOMBERK_AGENT_DSN": agent_dsn, "LOMBERK_API_KEY": secrets.token_hex(32),
              "LOMBERK_ADMIN_KEY": secrets.token_hex(32)}
    fd = os.open(env_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # private from the first byte
    with os.fdopen(fd, "w") as f:
        f.write("# Written by `lomberk setup`. Secrets: keep this file out of git.\n")
        f.writelines(f"{k}={env_quote(v)}\n" for k, v in values.items())
    for k, v in values.items():
        os.environ[k] = v  # so doctor checks what was just written
