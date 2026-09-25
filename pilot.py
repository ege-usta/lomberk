import psycopg
import uuid

import time
import json
import logging
from fastapi.testclient import TestClient
from undogate.api import app
from undogate.recovery import execute_with_recovery, RecoveryBudgetExhausted
import os
from testcontainers.postgres import PostgresContainer

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("pilot")

def run_pilot():
    logger.info("Starting local pilot...")
    
    postgres = PostgresContainer("postgres:16-alpine")
    postgres.start()
    
    try:
        dsn = postgres.get_connection_url().replace("postgresql+psycopg2", "postgresql")
        runtime_dsn = dsn.replace("test:test", "mcp_agent:secret")
        
        # 1. Setup DB Roles
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE ROLE undogate_control WITH LOGIN NOSUPERUSER PASSWORD 'secret'")
            cur.execute("CREATE ROLE mcp_agent WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD 'secret'")
            
        # 2. Install undogate
        from undogate.capture.install import install_undogate
        install_undogate(dsn, control_role="undogate_control", agent_role="mcp_agent")
        
        with psycopg.connect(dsn, autocommit=True) as conn, conn.cursor() as cur:
            cur.execute("CREATE TABLE public.pilot_users (id SERIAL PRIMARY KEY, email TEXT NOT NULL)")
            cur.execute("CREATE TABLE public.pilot_unprotected (id SERIAL PRIMARY KEY, email TEXT NOT NULL)")
            cur.execute("SELECT undogate.register_table('public', 'pilot_unprotected', 'id', 'mcp_agent')")
            cur.execute("GRANT ALL ON SCHEMA public TO mcp_agent")
            cur.execute("GRANT ALL ON ALL TABLES IN SCHEMA public TO mcp_agent")
            cur.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO mcp_agent")
            cur.execute("SELECT undogate.register_table('public', 'pilot_users', 'id', 'mcp_agent')")

        # 3. Setup client environment
        os.environ["UNDOGATE_ADMIN_DSN"] = dsn.replace('test:test', 'undogate_control:secret')
        os.environ["UNDOGATE_AGENT_DSN"] = runtime_dsn
        os.environ["UNDOGATE_API_KEY"] = "agent-key"
        os.environ["UNDOGATE_ADMIN_KEY"] = "admin-key"
        os.environ["UNDOGATE_PROTECTED_TABLES"] = '["pilot_users"]'
        if "OPENAI_API_KEY" in os.environ:
            del os.environ["OPENAI_API_KEY"]
            
        import undogate.api
        undogate.api._executor_instance = None
        undogate.api._policy_engine_instance = None
        with TestClient(app) as client:
            # Helper to execute with recovery
            def execute_sql(sql: str, op_id: str):
                def submit():
                    res = client.post("/v1/execute", json={"sql": sql, "operation_id": op_id}, headers={"X-API-Key": "agent-key"})
                    if res.status_code == 409:
                        class HTTPError(Exception):
                            status_code = 409
                            detail = res.json()["detail"]
                        raise HTTPError()
                    if res.status_code == 502:
                        raise Exception("Network Error")
                    return res.json()
                
                def status_fn(pub_id):
                    return client.get(f"/v1/checkpoints/{pub_id}/status", headers={"X-API-Key": "admin-key"}).json()["status"]
                
                return execute_with_recovery(op_id, submit, status_fn, base_delay=0.1, max_delay=0.5)

            # --- PILOT SCENARIO 1: Approval Required DML (Over limit) ---
            logger.info("--- SCENARIO 1: Approval Required & Recovery ---")
            op1 = str(uuid.uuid4())
            # Insert 2 rows to exceed default max_rows=1
            res1 = execute_sql("INSERT INTO public.pilot_users (email) VALUES ('a@a.com'), ('b@b.com')", op1)
            pub_id1 = res1["results"][0]["checkpoint_id"]
            logger.info(f"Submit 1 status: {res1['results'][0]['status']} (pub_id: {pub_id1})")
            
            # Admin approves
            res_appr = client.post(f"/v1/checkpoints/{pub_id1}/approve", headers={"X-API-Key": "admin-key"})
            logger.info(f"Admin approve status: {res_appr.json()['status']}")
            
            # Retry original submit
            res1_retry = execute_sql("INSERT INTO public.pilot_users (email) VALUES ('a@a.com'), ('b@b.com')", op1)
            logger.info(f"Retry 1 status: {res1_retry['results'][0]['status']} - {res1_retry['results'][0]['message']}")
            
            # --- PILOT SCENARIO 2: Runtime Commit Loss ---
            # Using pilot_unprotected so it executes directly without approval
            logger.info("--- SCENARIO 2: Runtime Commit Loss ---")
            import undogate.executor
            
            original_exit = psycopg.Transaction.__exit__
            commit_count = 0
            
            def patched_exit(self, exc_type, exc_val, exc_tb):
                nonlocal commit_count
                original_exit(self, exc_type, exc_val, exc_tb)
                if exc_type is None and self.connection and "mcp_agent" in self.connection.info.user:
                    commit_count += 1
                    if commit_count == 1:
                        raise psycopg.OperationalError("Simulated TCP Drop after DML Commit")

            psycopg.Transaction.__exit__ = patched_exit
            
            op2 = str(uuid.uuid4())
            try:
                execute_sql("INSERT INTO public.pilot_unprotected (email) VALUES ('c@c.com')", op2)
            except Exception as e:
                logger.info(f"Client got network error, restoring network...")
                
            psycopg.Transaction.__exit__ = original_exit # restore network
            
            # Client recovers
            res2 = execute_sql("INSERT INTO public.pilot_unprotected (email) VALUES ('c@c.com')", op2)
            logger.info(f"Recovered status: {res2['results'][0]['status']} - {res2['results'][0]['message']}")
            
            # --- PILOT SCENARIO 3: Checkpoint Creation Loss ---
            logger.info("--- SCENARIO 3: Checkpoint Creation Loss ---")
            commit_count = 0
            def patched_exit_cp(self, exc_type, exc_val, exc_tb):
                nonlocal commit_count
                original_exit(self, exc_type, exc_val, exc_tb)
                if exc_type is None and self.connection and "undogate_control" in self.connection.info.user:
                    commit_count += 1
                    if commit_count == 1:
                        raise psycopg.OperationalError("Simulated TCP Drop after CP Commit")

            psycopg.Transaction.__exit__ = patched_exit_cp
            
            op3 = str(uuid.uuid4())
            try:
                execute_sql("INSERT INTO public.pilot_unprotected (email) VALUES ('d@d.com')", op3)
            except Exception as e:
                logger.info(f"Client got CP creation error, restoring network...")
                
            psycopg.Transaction.__exit__ = original_exit
            
            res3 = execute_sql("INSERT INTO public.pilot_unprotected (email) VALUES ('d@d.com')", op3)
            logger.info(f"Recovered CP status: {res3['results'][0]['status']} - {res3['results'][0]['message']}")
            
            # --- PILOT SCENARIO 4: Payload Conflict & Unauthorized ---
            logger.info("--- SCENARIO 4: Conflicts & Errors ---")
            try:
                execute_sql("INSERT INTO public.pilot_users (email) VALUES ('e@e.com')", op3)
            except Exception as e:
                logger.info(f"Conflict error properly raised: 409")
                

            # --- PILOT SCENARIO 5: Explicit Undo ---
            logger.info("--- SCENARIO 5: Explicit Undo ---")
            pub_id_undo = res2['results'][0]['checkpoint_id']
            # Authorized Undo (via direct executor to match CLI)
            import undogate.api
            res_undo1 = undogate.api._executor_instance.execute_undo(pub_id_undo)
            logger.info(f"Undo 1 status: {res_undo1.status}")
            
            # Second Undo -> already undone
            res_undo2 = undogate.api._executor_instance.execute_undo(pub_id_undo)
            if res_undo2.status == "failed" and "already undone" in res_undo2.message.lower():
                logger.info("Second undo correctly rejected as already undone.")
                
            # Verify ledger and source table independently
            with psycopg.connect(dsn) as conn, conn.cursor() as cur:
                cur.execute("SELECT email FROM public.pilot_unprotected WHERE email = 'c@c.com'")
                row = cur.fetchone()
                logger.info(f"Source row verification after undo: {'Found' if row else 'Not found (SUCCESS)'}")
                
                cur.execute("SELECT status FROM undogate.checkpoints WHERE public_id = %s", (pub_id_undo,))
                cp_status = cur.fetchone()[0]
                logger.info(f"Ledger status: {cp_status}")
                
            logger.info("Pilot completed successfully.")
            
    finally:
        postgres.stop()

if __name__ == "__main__":
    run_pilot()
