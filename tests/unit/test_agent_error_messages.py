"""A database the gateway can't reach must not tell the agent where it lives or who logs in."""
import pytest

from lomberk.config import LomberkConfig
from lomberk.executor import LomberkExecutor
from lomberk.policy import PolicyEngine
from lomberk.server import run_agent_sql

DSN = "postgresql://leaky_user:pw@127.0.0.1:1/secretdb?connect_timeout=2"


@pytest.mark.parametrize("sql", ["SELECT id FROM public.t WHERE id = 1", "UPDATE public.t SET v = 1 WHERE id = 1"])
def test_connection_errors_hide_host_and_user(sql):
    out = run_agent_sql(LomberkExecutor(DSN, DSN), PolicyEngine(LomberkConfig()), sql, None, "agent")
    for leak in ("127.0.0.1", "leaky_user", "secretdb", "port 1"):
        assert leak not in out, out
    assert "could not reach the database" in out.lower(), out
