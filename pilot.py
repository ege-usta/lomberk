import sys
with open("undogate.yaml", "w") as f:
    f.write("limits:\n  max_rows_without_approval: 0\nprotected_tables:\n  - public.users\n")

import uuid
import psycopg
import json
import logging
from fastapi.testclient import TestClient
from undogate.api import app
from undogate.recovery import execute_with_recovery, RecoveryBudgetExhausted, TransientError
import os
from testcontainers.postgres import PostgresContainer
from typer.testing import CliRunner
from undogate.cli import app as cli_app

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("pilot")

def assert_eq(actual, expected, msg):
    if actual != expected:
        logger.error(f"ASSERTION FAILED: {msg} (Expected: {expected}, Got: {actual})")
        sys.exit(1)

class HTTPConflict(Exception):
    pass

def run_pilot():
    with open("undogate.yaml", "w") as f:
        f.write("limits:\n  max_rows_without_approval: 0\nprotected_tables:\n  - public.users\n")
    logger.info("Starting local pilot...")
    
    postgres = PostgresContainer("postgres:16-alpine")
    postgres.start()
    
    try:
        dsn = postgres.get_connection_url().replace("postgresql+psycopg2", "postgresql")
        runtime_dsn = dsn.replace("test:test", "mcp_agent:secret")
        
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE ROLE undogate_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
            
        from undogate.capture.install import install_undogate
        install_undogate(dsn, control_role="undogate_control", agent_role="mcp_agent")
        
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE TABLE public.users (id SERIAL PRIMARY KEY, data TEXT NOT NULL)")
            cur.execute("CREATE TABLE public.pilot_unprotected (id SERIAL PRIMARY KEY, data TEXT NOT NULL)")
            cur.execute("GRANT ALL ON SCHEMA public TO mcp_agent")
            cur.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO mcp_agent")
            cur.execute("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO mcp_agent")
            cur.execute("SELECT undogate.register_table('public', 'users', 'id', 'mcp_agent')")
            cur.execute("SELECT undogate.register_table('public', 'pilot_unprotected', 'id', 'mcp_agent')")
            
        os.environ["UNDOGATE_AGENT_DSN"] = runtime_dsn
        os.environ["UNDOGATE_API_KEY"] = "agent-key"
        os.environ["UNDOGATE_ADMIN_KEY"] = "admin-key"
        
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(dsn)
        admin_dsn = urlunparse((parsed.scheme, f"undogate_control:secret@{parsed.hostname}:{parsed.port}", parsed.path, parsed.params, parsed.query, parsed.fragment))
        os.environ["UNDOGATE_ADMIN_DSN"] = admin_dsn
        
        with TestClient(app) as client:
            def execute_sql(sql, op_id, use_auth=True):
                headers = {"X-API-Key": "agent-key"} if use_auth else {}
                
                def submit(timeout: float):
                    if timeout < 0.001:
                        raise TransientError("Transport connection timeout")
                    res = client.post("/v1/execute", json={"sql": sql, "operation_id": op_id}, headers=headers)
                    if res.status_code == 401:
                        raise ValueError("Unauthorized")
                    if res.status_code == 409:
                        raise HTTPConflict()
                    if res.status_code == 502 or res.status_code == 500:
                        raise TransientError("Network Error")
                    return res.json()
                    
                def status_fn(pub_id: str, timeout: float):
                    if timeout < 0.001:
                        raise TransientError("Transport connection timeout")
                    s_res = client.get(f"/v1/checkpoints/{pub_id}/status", headers={"X-API-Key": "admin-key"})
                    if s_res.status_code == 502 or s_res.status_code == 500:
                        raise TransientError("Network Error")
                    return s_res.json()["status"]
                
                return execute_with_recovery(op_id, submit, status_fn, timeout_seconds=5.0, base_delay=0.1, max_delay=0.5)

            logger.info("--- SCENARIO 1: Approval Required & Recovery ---")
            op1 = str(uuid.uuid4())
            res1 = execute_sql("INSERT INTO public.users (data) VALUES ('a'), ('b')", op1)
            assert_eq(res1.status, "approval_required", "S1 status should be approval_required")
            pub_id1 = res1.resume_id
            
            res_appr = client.post(f"/v1/checkpoints/{pub_id1}/approve", headers={"X-API-Key": "admin-key"}, json={"decision": "ALLOW"})
            assert_eq(res_appr.json()["status"], "approved", "S1 admin approve should be approved")
            
            res1_retry = execute_sql("INSERT INTO public.users (data) VALUES ('a'), ('b')", op1)
            assert_eq(res1_retry.status, "applied", "S1 retry should be applied")
            
            with psycopg.connect(dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM public.users")
                assert_eq(cur.fetchone()[0], 2, "S1 exactly 2 rows inserted")

            logger.info("--- SCENARIO 2: Runtime Commit Loss ---")
            original_exit = psycopg.Transaction.__exit__
            commit_count = 0
            
            def patched_exit_mcp(self, exc_type, exc_val, exc_tb):
                nonlocal commit_count
                original_exit(self, exc_type, exc_val, exc_tb)
                if exc_type is None and self.connection and "mcp_agent" in self.connection.info.user:
                    commit_count += 1
                    if commit_count == 1:
                        raise psycopg.OperationalError("Simulated TCP Drop")

            psycopg.Transaction.__exit__ = patched_exit_mcp
            op2 = str(uuid.uuid4())
            
            try:
                res_first = execute_sql("INSERT INTO public.pilot_unprotected (data) VALUES ('c@c.com')", op2)
                
                pub_id2 = res_first.resume_id
            except TransientError:
                pass
                
            psycopg.Transaction.__exit__ = original_exit
            
            with psycopg.connect(dsn) as check_conn, check_conn.cursor() as check_cur:
                check_cur.execute("SELECT status FROM undogate.checkpoints WHERE public_id = %s", (pub_id2,))
                
            res2 = execute_sql("INSERT INTO public.pilot_unprotected (data) VALUES ('c@c.com')", op2)
            assert_eq(res2.status, "applied", "S2 recovered status should be applied")

            with psycopg.connect(dsn) as conn, conn.cursor() as cur:
                pub_id2 = res2.resume_id
                cur.execute("SELECT count(*) FROM undogate.row_changes WHERE checkpoint_id = (SELECT id FROM undogate.checkpoints WHERE public_id = %s)", (pub_id2,))
                c = cur.fetchone()[0]
                assert_eq(c, 1, "S2 only 1 capture mutation happened")
                
            logger.info("--- SCENARIO 3: Checkpoint Creation Loss ---")
            commit_count = 0
            def patched_exit_cp(self, exc_type, exc_val, exc_tb):
                nonlocal commit_count
                original_exit(self, exc_type, exc_val, exc_tb)
                if exc_type is None and self.connection and "undogate_control" in self.connection.info.user:
                    commit_count += 1
                    if commit_count == 1:
                        raise psycopg.OperationalError("Simulated TCP Drop CP")

            psycopg.Transaction.__exit__ = patched_exit_cp
            op3 = str(uuid.uuid4())
            try:
                execute_sql("INSERT INTO public.pilot_unprotected (data) VALUES ('d@d.com')", op3)
            except TransientError:
                pass
                
            psycopg.Transaction.__exit__ = original_exit
            res3 = execute_sql("INSERT INTO public.pilot_unprotected (data) VALUES ('d@d.com')", op3)
            assert_eq(res3.status, "approved", "S3 recovered CP status should be approved, NOT applied")

            with psycopg.connect(dsn) as conn, conn.cursor() as cur:
                pub_id3 = res3.resume_id
                cur.execute("SELECT count(*) FROM undogate.row_changes WHERE checkpoint_id = (SELECT id FROM undogate.checkpoints WHERE public_id = %s)", (pub_id3,))
                c = cur.fetchone()[0]
                assert_eq(c, 0, "S3 ZERO additional iş mutations happened")
                
            logger.info("--- SCENARIO 4: Conflicts & Errors ---")
            try:
                execute_sql("INSERT INTO public.pilot_unprotected (data) VALUES ('e@e.com')", op3)
                logger.error("S4 Should have raised Conflict")
                sys.exit(1)
            except Exception as e:
                assert_eq(e.__class__.__name__, "HTTPConflict", "S4 Should raise HTTPConflict exactly")
                
            logger.info("--- SCENARIO 5: Unauthorized Action ---")
            try:
                execute_sql("INSERT INTO public.pilot_unprotected (data) VALUES ('f@f.com')", str(uuid.uuid4()), use_auth=False)
                logger.error("S5 Should have raised Unauthorized")
                sys.exit(1)
            except ValueError as e:
                if "Unauthorized" not in str(e):
                    logger.error("S5 Should raise Unauthorized ValueError")
                    sys.exit(1)

            logger.info("--- SCENARIO 6: Explicit Undo via CLI (Public Interface) ---")
            pub_id_undo = res2.resume_id
            os.environ["UNDOGATE_ADMIN_DSN"] = admin_dsn
            runner = CliRunner()
            
            res_cli = runner.invoke(cli_app, ["undo", pub_id_undo])
            assert_eq(res_cli.exit_code, 0, "CLI Undo exit code")
            if "already undone" in res_cli.stdout.lower() or "failed" in res_cli.stdout.lower():
                logger.error(f"S6 Undo failed incorrectly: {res_cli.stdout}")
                sys.exit(1)
                
            with psycopg.connect(dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT data FROM public.pilot_unprotected WHERE data = 'c@c.com'")
                row = cur.fetchone()
                assert_eq(row, None, "S6 Source row should be deleted (undone)")
                
                cur.execute("SELECT status FROM undogate.checkpoints WHERE public_id = %s", (pub_id_undo,))
                cp_status = cur.fetchone()[0]
                assert_eq(cp_status, "undone", "S6 Ledger status should be undone")
                
            # Second undo
            res_cli2 = runner.invoke(cli_app, ["undo", pub_id_undo])
            if "already undone" not in res_cli2.stdout.lower():
                logger.error(f"S6 Second Undo failed to report already undone: {res_cli2.stdout}")
                sys.exit(1)

            logger.info("--- SCENARIO 7: DB Unreachable & Budget Exhaustion ---")
            def failing_submit(t):
                raise TransientError("DB Unreachable")
            
            try:
                execute_with_recovery("op_unreach", failing_submit, lambda x, t: "unknown", timeout_seconds=1.0, base_delay=0.1, max_delay=0.2)
                logger.error("S7 Should have exhausted budget")
                sys.exit(1)
            except RecoveryBudgetExhausted as e:
                assert_eq(e.last_known_state, "unknown", "S7 Last known state")
                assert_eq(e.operation_id, "op_unreach", "S7 Operation ID")

            logger.info("Pilot completed successfully with all assertions verified.")
            
    finally:
        postgres.stop()

if __name__ == "__main__":
    run_pilot()
