CREATE OR REPLACE FUNCTION rowback.begin_checkpoint(
    p_sql_text TEXT,
    p_classification TEXT,
    p_agent_label TEXT,
    p_principal TEXT,
    p_operation_id TEXT DEFAULT NULL,
    OUT o_cp_id BIGINT,
    OUT o_public_id TEXT
) AS $$
DECLARE
    v_public_id TEXT;
    v_id BIGINT;
BEGIN
    v_public_id := 'cp_' || replace(gen_random_uuid()::text, '-', '');
    
    INSERT INTO rowback.checkpoints (
        public_id, sql_text, classification, agent_label, principal, status, decision, operation_id
    ) VALUES (
        v_public_id, p_sql_text, p_classification, p_agent_label, p_principal, 'pending', 'REQUIRE_APPROVAL', p_operation_id
    ) RETURNING id INTO v_id;
    
    o_cp_id := v_id;
    o_public_id := v_public_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.approve_checkpoint(
    p_public_id TEXT,
    p_decision TEXT
) RETURNS UUID AS $$
DECLARE
    v_token UUID;
BEGIN
    v_token := gen_random_uuid();
    
    UPDATE rowback.checkpoints 
    SET status = 'approved', decision = p_decision, capability_token = v_token
    WHERE public_id = p_public_id AND status = 'pending';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or not in pending state.', p_public_id;
    END IF;
    
    RETURN v_token;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.reject_checkpoint(
    p_public_id TEXT
) RETURNS VOID AS $$
BEGIN
    UPDATE rowback.checkpoints 
    SET status = 'rejected'
    WHERE public_id = p_public_id AND status = 'pending';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or not in pending state.', p_public_id;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.fail_checkpoint(
    p_public_id TEXT
) RETURNS VOID AS $$
BEGIN
    UPDATE rowback.checkpoints 
    SET status = 'failed'
    WHERE public_id = p_public_id AND status IN ('pending', 'approved', 'executing');
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or invalid state transition.', p_public_id;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.claim_checkpoint(
    p_capability_token UUID
) RETURNS VOID AS $$
DECLARE
    v_txid BIGINT;
BEGIN
    v_txid := txid_current();
    
    UPDATE rowback.checkpoints 
    SET status = 'executing', exec_txid = v_txid
    WHERE capability_token = p_capability_token AND status = 'approved';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint not found or not in approved state for the given capability token.';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.finish_checkpoint(
    p_capability_token UUID,
    p_rows_affected INTEGER
) RETURNS VOID AS $$
DECLARE
    v_txid BIGINT;
    v_guc TEXT;
BEGIN
    v_txid := txid_current();
    v_guc := current_setting('rowback.capability_token', true);
    
    IF p_capability_token::TEXT != v_guc THEN
        RAISE EXCEPTION 'Security Violation: Cannot finish checkpoint without matching execution token in GUC.';
    END IF;

    UPDATE rowback.checkpoints 
    SET status = 'applied', rows_affected = p_rows_affected
    WHERE capability_token = p_capability_token AND status = 'executing' AND exec_txid = v_txid;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint not found or invalid execution context (txid mismatch).';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.capture_row_change() RETURNS TRIGGER AS $$
DECLARE
    v_cp_id_text TEXT;
    v_cp_id BIGINT;
    v_seq BIGINT;
    v_pk TEXT;
    v_old JSONB := NULL;
    v_new JSONB := NULL;
    v_caller TEXT;
    v_schema_snapshot JSONB;
BEGIN
    v_caller := session_user;
    v_cp_id_text := current_setting('rowback.checkpoint_id', true);
    
    IF v_cp_id_text IS NULL OR v_cp_id_text = '' THEN
        IF v_caller = '__AGENT_ROLE__' THEN
            RAISE EXCEPTION 'Rowback Security Violation: DML execution attempted outside of a trusted checkpoint context.';
        ELSE
            RETURN NULL;
        END IF;
    END IF;
    
    v_cp_id := v_cp_id_text::BIGINT;
    
    -- Anti-forgery guard: Validate capability, txid, and state
    DECLARE
        v_db_token UUID;
        v_db_status TEXT;
        v_db_txid BIGINT;
        v_guc_token TEXT;
    BEGIN
        SELECT capability_token, status, exec_txid INTO v_db_token, v_db_status, v_db_txid
        FROM rowback.checkpoints 
        WHERE id = v_cp_id;
        
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Rowback Security Violation: Invalid checkpoint context.';
        END IF;
        
        v_guc_token := current_setting('rowback.capability_token', true);
        
        IF v_db_token IS NULL OR v_guc_token IS NULL OR v_db_token::TEXT != v_guc_token THEN
            RAISE EXCEPTION 'Rowback Security Violation: Invalid or missing capability token.';
        END IF;
        
        IF v_db_status != 'executing' THEN
            RAISE EXCEPTION 'Rowback Security Violation: Checkpoint is not in executing state.';
        END IF;
        
        IF v_db_txid IS DISTINCT FROM txid_current() THEN
            RAISE EXCEPTION 'Rowback Security Violation: Transaction context mismatch (token stolen or replayed).';
        END IF;
    END;
    
    v_seq := current_setting('rowback.seq', true)::BIGINT + 1;
    PERFORM set_config('rowback.seq', v_seq::text, true);

    SELECT a.attname INTO v_pk
    FROM pg_index i
    JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
    WHERE i.indrelid = TG_RELID AND i.indisprimary;
    
    IF v_pk IS NULL THEN
        RAISE EXCEPTION 'Rowback Security Violation: Table %.% has no primary key.', TG_TABLE_SCHEMA, TG_TABLE_NAME;
    END IF;
    
    IF (SELECT indnatts FROM pg_index WHERE indrelid = TG_RELID AND indisprimary) > 1 THEN
        RAISE EXCEPTION 'Rowback Security Violation: Composite primary keys are not supported (%.%).', TG_TABLE_SCHEMA, TG_TABLE_NAME;
    END IF;

    SELECT jsonb_object_agg(attname, jsonb_build_object('typoid', atttypid, 'typmod', atttypmod, 'notnull', attnotnull))
    INTO v_schema_snapshot
    FROM pg_attribute
    WHERE attrelid = TG_RELID AND attnum > 0 AND NOT attisdropped;

    IF TG_OP = 'DELETE' THEN
        v_old := row_to_json(OLD);
    ELSIF TG_OP = 'UPDATE' THEN
        v_old := row_to_json(OLD);
        v_new := row_to_json(NEW);
        IF (v_old->>v_pk) IS DISTINCT FROM (v_new->>v_pk) THEN
            RAISE EXCEPTION 'Rowback Security Violation: Primary key updates are forbidden.';
        END IF;
    ELSIF TG_OP = 'INSERT' THEN
        v_new := row_to_json(NEW);
    END IF;

    INSERT INTO rowback.row_changes (
        checkpoint_id, table_schema, table_name, table_oid, op, pk,
        old_row, new_row, schema_snapshot, seq
    ) VALUES (
        v_cp_id, TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_RELID, substr(TG_OP, 1, 1), jsonb_build_object(v_pk, COALESCE(v_old->>v_pk, v_new->>v_pk)),
        v_old, v_new, v_schema_snapshot, v_seq
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;


-- Records one approval of a pending checkpoint and returns the two-person quorum: the
-- most distinct people who approved within ONE verified identity system (oidc: or
-- slack:). The shared admin key and CLI users prove no identity, and one person may
-- hold both an SSO and a Slack identity, so neither can make up a quorum.
-- The row lock serializes concurrent approvers.
CREATE OR REPLACE FUNCTION rowback.record_approval(p_public_id TEXT, p_actor TEXT) RETURNS INTEGER AS $$
DECLARE
    v_status TEXT;
    v_count INTEGER;
BEGIN
    SELECT status INTO v_status FROM rowback.checkpoints WHERE public_id = p_public_id FOR UPDATE;
    IF NOT FOUND OR v_status <> 'pending' THEN
        RAISE EXCEPTION 'Checkpoint % not found or not in pending state.', p_public_id;
    END IF;
    INSERT INTO rowback.approvals (public_id, actor) VALUES (p_public_id, p_actor) ON CONFLICT DO NOTHING;
    SELECT coalesce(max(n), 0) INTO v_count FROM (
        SELECT count(*) AS n FROM rowback.approvals
        WHERE public_id = p_public_id AND split_part(actor, ':', 1) IN ('oidc', 'slack')
        GROUP BY split_part(actor, ':', 1)) per_system;
    RETURN v_count;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.guard_approvals_immutability() RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Rowback approvals are append-only.';
END;
$$ LANGUAGE plpgsql SET search_path = rowback, pg_temp;

DROP TRIGGER IF EXISTS rowback_approvals_immutable ON rowback.approvals;
CREATE TRIGGER rowback_approvals_immutable BEFORE UPDATE OR DELETE ON rowback.approvals
    FOR EACH ROW EXECUTE FUNCTION rowback.guard_approvals_immutability();

CREATE OR REPLACE FUNCTION rowback.get_pending_checkpoint(
    p_public_id TEXT
) RETURNS TABLE (id BIGINT, sql_text TEXT, status TEXT) AS $$
BEGIN
    RETURN QUERY SELECT c.id, c.sql_text, c.status
    FROM rowback.checkpoints c
    WHERE c.public_id = p_public_id FOR UPDATE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.register_table(
    p_schema TEXT,
    p_table TEXT,
    p_pk_column TEXT,
    p_agent_role TEXT,
    p_secret_columns TEXT[] DEFAULT '{}'  -- the agent may never SELECT these; enforced by PostgreSQL
) RETURNS VOID AS $$
DECLARE
    v_table_oid OID;
    v_all TEXT;
    v_visible TEXT;
BEGIN
    SELECT c.oid INTO v_table_oid
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = p_schema AND c.relname = p_table;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Table %.% does not exist.', p_schema, p_table;
    END IF;

    INSERT INTO rowback.registered_tables (schema_name, table_name, table_oid, pk_column)
    VALUES (p_schema, p_table, v_table_oid, p_pk_column)
    ON CONFLICT (schema_name, table_name) DO UPDATE 
    SET table_oid = EXCLUDED.table_oid, pk_column = EXCLUDED.pk_column;

    EXECUTE format('DROP TRIGGER IF EXISTS rowback_capture ON %I.%I', p_schema, p_table);
    EXECUTE format('CREATE TRIGGER rowback_capture AFTER INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION rowback.capture_row_change()', p_schema, p_table);

    EXECUTE format('GRANT INSERT, UPDATE, DELETE ON %I.%I TO %I', p_schema, p_table, p_agent_role);
    IF coalesce(cardinality(p_secret_columns), 0) = 0 THEN
        EXECUTE format('GRANT SELECT ON %I.%I TO %I', p_schema, p_table, p_agent_role);
    ELSE
        -- Column privileges: no query trick (pg_stats, error details, JSON casts) can read a
        -- column the role can't SELECT. Start from nothing, so re-registering also hides.
        SELECT string_agg(quote_ident(attname), ', '),
               string_agg(quote_ident(attname), ', ') FILTER (WHERE NOT attname = ANY (p_secret_columns))
          INTO v_all, v_visible
          FROM pg_attribute WHERE attrelid = v_table_oid AND attnum > 0 AND NOT attisdropped;
        EXECUTE format('REVOKE SELECT ON %I.%I FROM %I', p_schema, p_table, p_agent_role);
        EXECUTE format('REVOKE SELECT (%s) ON %I.%I FROM %I', v_all, p_schema, p_table, p_agent_role);
        IF v_visible IS NOT NULL THEN
            EXECUTE format('GRANT SELECT (%s) ON %I.%I TO %I', v_visible, p_schema, p_table, p_agent_role);
        END IF;
    END IF;
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', p_schema, p_agent_role);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.grant_access(p_control_role TEXT, p_agent_role TEXT) RETURNS VOID AS $$
BEGIN
    -- Revoke all from public for security definer functions
    EXECUTE 'REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA rowback FROM PUBLIC';

    -- Common schema usage
    EXECUTE format('GRANT USAGE ON SCHEMA rowback TO %I', p_control_role);
    EXECUTE format('GRANT USAGE ON SCHEMA rowback TO %I', p_agent_role);
    
    -- Control Plane (only control role)
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.begin_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.approve_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.reject_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.fail_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.requeue_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.claim_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.finish_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.get_pending_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.record_approval TO %I', p_control_role);
    EXECUTE format('GRANT SELECT ON rowback.approvals TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.register_table TO %I', p_control_role);
    
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.execute_undo TO %I', p_control_role);
    

    EXECUTE format('GRANT SELECT ON rowback.checkpoints TO %I', p_control_role);
    EXECUTE format('GRANT SELECT ON rowback.row_changes TO %I', p_control_role);
    EXECUTE format('GRANT INSERT ON rowback.undo_operations TO %I', p_control_role);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA rowback TO %I', p_control_role);
    
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.list_pending_checkpoints TO %I', p_control_role);
    
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.check_checkpoint_status TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.verify_ledger TO %I', p_control_role);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON rowback.slack_messages TO %I', p_control_role);
    
    
    -- Runtime (only agent role)
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.claim_checkpoint TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.finish_checkpoint TO %I', p_agent_role);
    
    -- Ensure separation of duties
    
    
    
    EXECUTE format('REVOKE EXECUTE ON FUNCTION rowback.begin_checkpoint FROM %I', p_agent_role);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION rowback.approve_checkpoint FROM %I', p_agent_role);
    
    -- Legacy cleanup
    EXECUTE format('REVOKE ALL ON rowback.checkpoints FROM %I', p_agent_role);
    
    
    EXECUTE format('GRANT SELECT ON rowback.registered_tables TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.unprotected_cascade_child TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION rowback.unprotected_cascade_child TO %I', p_control_role);
    EXECUTE format('GRANT SELECT ON rowback.registered_tables TO %I', p_control_role);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp;

CREATE OR REPLACE FUNCTION rowback.check_checkpoint_status(
    p_public_id TEXT
) RETURNS TEXT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_status TEXT;
BEGIN
    SELECT status INTO v_status 
    FROM rowback.checkpoints 
    WHERE public_id = p_public_id 
    FOR SHARE NOWAIT;
    
    IF NOT FOUND THEN
        RETURN 'not_found';
    END IF;
    
    RETURN v_status;
EXCEPTION WHEN lock_not_available THEN
    RETURN 'busy';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION rowback.list_pending_checkpoints()
RETURNS TABLE (
    id BIGINT,
    public_id TEXT,
    sql_text TEXT,
    agent_label TEXT,
    created_at TIMESTAMPTZ
)
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT c.id, c.public_id, c.sql_text, c.agent_label, c.created_at
    FROM rowback.checkpoints c
    WHERE c.status = 'pending';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;



-- Returns the first table reachable from p_table_oid through ON DELETE CASCADE /
-- SET NULL / SET DEFAULT foreign keys that has no enabled capture trigger, or NULL.
-- A write whose cascade reaches such a table would change rows Rowback cannot undo.
CREATE OR REPLACE FUNCTION rowback.unprotected_cascade_child(p_table_oid OID)
RETURNS TEXT
LANGUAGE sql STABLE
SET search_path = pg_catalog, pg_temp
AS $$
    WITH RECURSIVE reach(oid) AS (
        SELECT p_table_oid
        UNION
        SELECT c.conrelid FROM pg_constraint c JOIN reach r ON c.confrelid = r.oid
        WHERE c.contype = 'f' AND (c.confdeltype IN ('c', 'n', 'd') OR c.confupdtype IN ('c', 'n', 'd'))
    )
    SELECT r.oid::regclass::text FROM reach r
    WHERE r.oid <> p_table_oid AND NOT EXISTS (
        SELECT 1 FROM pg_trigger t
        WHERE t.tgrelid = r.oid AND t.tgname = 'rowback_capture' AND t.tgenabled IN ('O', 'A')
    )
    ORDER BY 1 LIMIT 1
$$;

-- Re-inserts deleted rows whose FK parent was not restored yet, retrying until
-- every row lands or a pass makes no progress (then the whole undo aborts).
-- ponytail: O(n^2) passes for pathological self-referencing chains; fine for per-statement checkpoints.
-- Re-insert a captured row exactly: skip generated columns (Postgres recomputes
-- them) and keep the original ids, including GENERATED ALWAYS AS IDENTITY.
CREATE OR REPLACE FUNCTION rowback.restore_insert_sql(p_table TEXT) RETURNS TEXT AS $$
DECLARE
    v_cols TEXT;
BEGIN
    SELECT string_agg(quote_ident(attname), ', ' ORDER BY attnum) INTO v_cols
    FROM pg_attribute
    WHERE attrelid = p_table::regclass AND attnum > 0 AND NOT attisdropped AND attgenerated = '';
    RETURN format('INSERT INTO %s (%s) OVERRIDING SYSTEM VALUE SELECT %s FROM jsonb_populate_record(null::%s, $1::jsonb)',
                  p_table, v_cols, v_cols, p_table);
END;
$$ LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp;

CREATE OR REPLACE FUNCTION rowback.replay_deferred_inserts(p_tables TEXT[], p_rows JSONB[])
RETURNS INT
SET search_path = rowback, pg_temp
AS $$
DECLARE
    v_left_tables TEXT[];
    v_left_rows JSONB[];
    v_done INT := 0;
    i INT;
BEGIN
    WHILE coalesce(array_length(p_tables, 1), 0) > 0 LOOP
        v_left_tables := '{}';
        v_left_rows := '{}';
        FOR i IN 1..array_length(p_tables, 1) LOOP
            BEGIN
                EXECUTE rowback.restore_insert_sql(p_tables[i]) USING p_rows[i];
                v_done := v_done + 1;
            EXCEPTION WHEN foreign_key_violation THEN
                v_left_tables := v_left_tables || p_tables[i];
                v_left_rows := v_left_rows || p_rows[i];
            END;
        END LOOP;
        IF coalesce(array_length(v_left_tables, 1), 0) = array_length(p_tables, 1) THEN
            RAISE EXCEPTION 'Conflict: % deleted row(s) cannot be restored because their foreign key parent no longer exists', array_length(v_left_tables, 1);
        END IF;
        p_tables := v_left_tables;
        p_rows := v_left_rows;
    END LOOP;
    RETURN v_done;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION rowback.execute_undo(
    p_public_id TEXT,
    p_agent_label TEXT
) RETURNS JSONB AS $$
DECLARE
    v_cp_id BIGINT;
    v_status TEXT;
    v_undo_cp_id BIGINT;
    v_undo_public_id TEXT;
    v_token UUID;
    v_change RECORD;
    v_full_table TEXT;
    v_curr JSONB;
    v_set_clauses TEXT;
    v_affected INT := 0;
    v_seq_val BIGINT;
    v_live_pk TEXT;
    v_live_pk_count INT;
    v_unprotected TEXT;
    v_captured INT;
    v_retry_tables TEXT[] := '{}';
    v_retry_rows JSONB[] := '{}';
    v_drained BOOLEAN := false;
BEGIN
    -- 1. Fetch and lock original checkpoint
    SELECT id, status INTO v_cp_id, v_status
    FROM rowback.checkpoints
    WHERE public_id = p_public_id
    FOR UPDATE NOWAIT;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint not found: %', p_public_id;
    END IF;
    
    IF v_status = 'undone' THEN
        RAISE EXCEPTION 'Checkpoint already undone: %', p_public_id;
    END IF;
    IF v_status != 'applied' THEN
        RAISE EXCEPTION 'Cannot undo checkpoint in state: %', v_status;
    END IF;

    -- 2. Lock affected tables in deterministic order (by table_oid)
    -- Also validate schema (unsupported constructs)
    FOR v_change IN 
        SELECT DISTINCT table_schema, table_name, table_oid 
        FROM rowback.row_changes 
        WHERE checkpoint_id = v_cp_id 
        ORDER BY table_oid
    LOOP
        EXECUTE format('LOCK TABLE %I.%I IN SHARE ROW EXCLUSIVE MODE NOWAIT', v_change.table_schema, v_change.table_name);
        
        -- Validate table identity (OID match)
        IF v_change.table_oid IS NULL THEN
            RAISE EXCEPTION 'Table identity missing (NULL OID) for %.%', v_change.table_schema, v_change.table_name;
        END IF;
        IF v_change.table_oid != (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass::oid THEN
            RAISE EXCEPTION 'Table identity drifted for %.%', v_change.table_schema, v_change.table_name;
        END IF;

        -- Check unsupported schemas

        IF EXISTS (
            SELECT 1 FROM pg_inherits 
            WHERE inhrelid = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass 
               OR inhparent = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass
        ) THEN
            RAISE EXCEPTION 'Unsupported schema: Table inheritance is not allowed on %', v_change.table_name;
        END IF;

        -- Foreign keys are supported: LIFO replay restores parents before children.
        -- Cascades must stay inside captured tables so nothing changes invisibly.
        v_unprotected := rowback.unprotected_cascade_child(v_change.table_oid);
        IF v_unprotected IS NOT NULL THEN
            RAISE EXCEPTION 'Unsupported schema: % cascades into % which is not registered with Rowback', v_change.table_name, v_unprotected;
        END IF;
        
        -- Check triggers: exactly ONE trigger allowed, and it MUST be rowback_capture, and ENABLED.
        IF EXISTS (
            SELECT 1 FROM pg_trigger 
            WHERE tgrelid = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass
            AND tgname != 'rowback_capture' AND tgisinternal = false
        ) THEN
            RAISE EXCEPTION 'Unsupported schema: Triggers not allowed on %', v_change.table_name;
        END IF;
        
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger 
            WHERE tgrelid = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass
            AND tgname = 'rowback_capture' AND tgenabled = 'O'
            AND tgtype = 29 AND tgattr = '' 
            AND tgfoid = 'rowback.capture_row_change'::regproc
            AND tgqual IS NULL
        ) THEN
            RAISE EXCEPTION 'Capture trigger missing or disabled on %', v_change.table_name;
        END IF;
        
        IF EXISTS (
            SELECT 1 FROM pg_rewrite 
            WHERE ev_class = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass 
            AND rulename != '_RETURN'
        ) THEN
            RAISE EXCEPTION 'Unsupported schema: Rules not allowed on %', v_change.table_name;
        END IF;

    END LOOP;

    -- 3. Create new checkpoint for the undo operation
    SELECT gen_random_uuid() INTO v_token;
    v_undo_public_id := 'undo_' || replace(gen_random_uuid()::text, '-', '');
    
    INSERT INTO rowback.checkpoints (public_id, sql_text, classification, decision, agent_label, status, capability_token, exec_txid)
    VALUES (v_undo_public_id, 'UNDO ' || p_public_id, 'WRITE_UNDO', 'ALLOW', p_agent_label, 'executing', v_token, txid_current())
    RETURNING id INTO v_undo_cp_id;

    -- Set GUCs so trigger logs it
    PERFORM set_config('rowback.checkpoint_id', v_undo_cp_id::text, true);
    PERFORM set_config('rowback.capability_token', v_token::text, true);
    PERFORM set_config('rowback.seq', '1', true);
    
    v_seq_val := 1;

    -- 4. Apply reverse DML. Capture order is not a reliable FK order (RI actions
    -- such as SET NULL can be captured after their parent), so replay in phases:
    -- re-insert deleted rows parents-first (FK depth), then revert updates, then
    -- delete inserted rows; LIFO within each phase (covers self-referencing FKs).
    FOR v_change IN
        SELECT rc.table_schema, rc.table_name, rc.table_oid, rc.op, rc.pk, rc.old_row, rc.new_row, rc.schema_snapshot
        FROM rowback.row_changes rc
        LEFT JOIN LATERAL (
            WITH RECURSIVE up(oid, d) AS (
                SELECT rc.table_oid, 0
                UNION ALL
                SELECT c.confrelid, up.d + 1 FROM pg_catalog.pg_constraint c JOIN up ON c.conrelid = up.oid
                WHERE c.contype = 'f' AND c.confrelid <> c.conrelid AND up.d < 32
            )
            SELECT max(d) AS depth FROM up
        ) fk ON true
        WHERE rc.checkpoint_id = v_cp_id
        ORDER BY CASE rc.op WHEN 'D' THEN 0 WHEN 'U' THEN 1 ELSE 2 END,
                 CASE WHEN rc.op = 'D' THEN fk.depth END,
                 rc.seq DESC
    LOOP
        IF v_change.op <> 'D' AND NOT v_drained THEN
            v_affected := v_affected + rowback.replay_deferred_inserts(v_retry_tables, v_retry_rows);
            v_drained := true;
        END IF;
        PERFORM set_config('rowback.seq', v_seq_val::text, true);
        v_seq_val := v_seq_val + 1;
        
        v_full_table := quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name);
        
        -- Validate PK hasn't drifted
        BEGIN
            SELECT a.attname, i.indnatts INTO v_live_pk, v_live_pk_count
            FROM pg_index i
            JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
            WHERE i.indrelid = v_change.table_oid AND i.indisprimary;
            
            IF v_live_pk IS NULL THEN
                RAISE EXCEPTION 'Security Violation: Table % has no primary key', v_full_table;
            END IF;
            IF v_live_pk_count > 1 THEN
                RAISE EXCEPTION 'Security Violation: Composite primary keys are not supported (%)', v_full_table;
            END IF;
            IF NOT (v_change.pk ? v_live_pk) THEN
                RAISE EXCEPTION 'Security Violation: PK identity drifted for % (expected %, got %)', v_full_table, array_to_string(ARRAY(SELECT jsonb_object_keys(v_change.pk)), ','), v_live_pk;
            END IF;
            
            IF v_change.schema_snapshot IS NULL THEN
                RAISE EXCEPTION 'Unsupported: Missing schema snapshot for %', v_full_table;
            END IF;
            
            DECLARE
                v_live_snapshot JSONB;
            BEGIN
                SELECT jsonb_object_agg(attname, jsonb_build_object('typoid', atttypid, 'typmod', atttypmod, 'notnull', attnotnull))
                INTO v_live_snapshot
                FROM pg_attribute
                WHERE attrelid = v_change.table_oid AND attnum > 0 AND NOT attisdropped;
                
                IF v_change.schema_snapshot != v_live_snapshot THEN
                    RAISE EXCEPTION 'Security Violation: Schema drift detected (type/nullability change, dropped, or added column) for %', v_full_table;
                END IF;
            END;
        END;
        
        IF v_change.op = 'I' THEN
            EXECUTE format('SELECT row_to_json(t) FROM %s t WHERE %I = %L FOR UPDATE NOWAIT', 
                v_full_table, 
                v_live_pk, 
                (v_change.pk->>v_live_pk)) INTO v_curr;
            
            IF v_curr IS NULL THEN
                RAISE EXCEPTION 'Conflict: Row % missing in %', v_change.pk, v_full_table;
            END IF;
            
            -- Full new_row comparison
            IF v_curr::jsonb IS DISTINCT FROM v_change.new_row::jsonb THEN
                RAISE EXCEPTION 'Conflict: Row % in % has been modified', v_change.pk, v_full_table;
            END IF;
            
            EXECUTE format('DELETE FROM %s WHERE %I = %L', 
                v_full_table, 
                v_live_pk, 
                (v_change.pk->>v_live_pk));
                
        ELSIF v_change.op = 'U' THEN
            EXECUTE format('SELECT row_to_json(t) FROM %s t WHERE %I = %L FOR UPDATE NOWAIT', 
                v_full_table, 
                v_live_pk, 
                (v_change.pk->>v_live_pk)) INTO v_curr;
                
            IF v_curr IS NULL THEN
                RAISE EXCEPTION 'Conflict: Row % missing in %', v_change.pk, v_full_table;
            END IF;
            IF v_curr::jsonb IS DISTINCT FROM v_change.new_row::jsonb THEN
                RAISE EXCEPTION 'Conflict: Row % in % has been modified', v_change.pk, v_full_table;
            END IF;
            
            SELECT string_agg(quote_ident(key) || ' = (SELECT (' || quote_literal(value#>>'{}') || ')::text)', ', ') 
            -- Using text cast is simple but might fail types. 
            -- Safest: USING parameter, but jsonb_populate_record is better.
            -- User request: "SELECT %I FROM jsonb_populate_record(null::%s, $1::jsonb)"
            INTO v_set_clauses
            FROM jsonb_each(v_change.old_row);
            
            SELECT string_agg(quote_ident(key) || ' = (SELECT ' || quote_ident(key) || ' FROM jsonb_populate_record(null::' || v_full_table || ', $1::jsonb))', ', ') 
            INTO v_set_clauses
            FROM jsonb_object_keys(v_change.old_row) AS key
            -- generated columns recompute themselves; ALWAYS-identity columns can't be set
            WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = v_change.table_oid
                              AND a.attname = key AND (a.attgenerated <> '' OR a.attidentity = 'a'));
            
            EXECUTE format('UPDATE %s SET %s WHERE %I = %L', 
                v_full_table, 
                v_set_clauses, 
                v_live_pk, 
                (v_change.pk->>v_live_pk)) USING v_change.old_row;

        ELSIF v_change.op = 'D' THEN
            BEGIN
                EXECUTE rowback.restore_insert_sql(v_full_table) USING v_change.old_row;
            EXCEPTION WHEN foreign_key_violation THEN
                v_retry_tables := v_retry_tables || v_full_table;
                v_retry_rows := v_retry_rows || v_change.old_row;
                CONTINUE;
            END;
        ELSE
            RAISE EXCEPTION 'Unknown operation: %', v_change.op;
        END IF;
        
        v_affected := v_affected + 1;
    END LOOP;

    IF NOT v_drained THEN
        v_affected := v_affected + rowback.replay_deferred_inserts(v_retry_tables, v_retry_rows);
    END IF;

    -- Every row the undo touched is captured. More captured rows than replayed
    -- changes means an FK cascade reached rows written after the checkpoint.
    SELECT count(*) INTO v_captured FROM rowback.row_changes WHERE checkpoint_id = v_undo_cp_id;
    IF v_captured <> v_affected THEN
        RAISE EXCEPTION 'Conflict: undo would cascade into % row(s) changed after checkpoint %', v_captured - v_affected, p_public_id;
    END IF;

    -- 5. Mark old checkpoint undone, new checkpoint applied
    UPDATE rowback.checkpoints SET status = 'undone' WHERE id = v_cp_id;
    UPDATE rowback.checkpoints SET status = 'applied' WHERE id = v_undo_cp_id;
    
    INSERT INTO rowback.undo_operations (source_checkpoint_id, undo_checkpoint_id)
    VALUES (v_cp_id, v_undo_cp_id);

    RETURN jsonb_build_object(
        'status', 'applied',
        'public_id', v_undo_public_id,
        'rows_affected', v_affected
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

-- Row-limit hold: an auto-approved write that touched too many rows is rolled
-- back by the executor and sent back to the human approval queue.
CREATE OR REPLACE FUNCTION rowback.requeue_checkpoint(
    p_public_id TEXT
) RETURNS VOID AS $$
BEGIN
    UPDATE rowback.checkpoints
    SET status = 'pending', decision = 'REQUIRE_APPROVAL', capability_token = NULL, exec_txid = NULL
    WHERE public_id = p_public_id AND status = 'approved';

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or not in approved state.', p_public_id;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = rowback, pg_temp;

-- ---------------------------------------------------------------------------
-- Tamper-evident ledger. Every checkpoint row carries sha256(prev_hash + its
-- immutable fields); editing or deleting any past row breaks the chain.
-- ponytail: one advisory lock serializes checkpoint creation; shard the chain per
-- principal if write throughput ever needs it. The chain lives in the same DB as
-- an attacker with superuser, so ship verify_ledger()'s head hash to your SIEM.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION rowback.checkpoint_hash(
    p_prev TEXT, p_public_id TEXT, p_created_at TIMESTAMPTZ, p_principal TEXT,
    p_agent_label TEXT, p_classification TEXT, p_sql_text TEXT, p_operation_id TEXT
) RETURNS TEXT
LANGUAGE sql IMMUTABLE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT encode(sha256(convert_to(jsonb_build_array(
        p_prev, p_public_id, extract(epoch FROM p_created_at)::text, p_principal,
        p_agent_label, p_classification, p_sql_text, p_operation_id
    )::text, 'UTF8')), 'hex')
$$;

CREATE OR REPLACE FUNCTION rowback.chain_checkpoint() RETURNS TRIGGER AS $$
DECLARE
    v_prev TEXT;
    v_seq BIGINT;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('rowback.ledger'));
    SELECT hash, chain_seq INTO v_prev, v_seq
    FROM rowback.checkpoints WHERE chain_seq IS NOT NULL
    ORDER BY chain_seq DESC LIMIT 1;

    NEW.prev_hash := coalesce(v_prev, 'genesis');
    NEW.chain_seq := coalesce(v_seq, 0) + 1;
    NEW.hash := rowback.checkpoint_hash(NEW.prev_hash, NEW.public_id, NEW.created_at, NEW.principal,
                                         NEW.agent_label, NEW.classification, NEW.sql_text, NEW.operation_id);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = rowback, pg_temp;

CREATE OR REPLACE FUNCTION rowback.guard_checkpoint_immutability() RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'Rowback ledger is append-only: checkpoints cannot be deleted.';
    END IF;
    IF (NEW.public_id, NEW.created_at, NEW.principal, NEW.agent_label, NEW.classification, NEW.sql_text,
        NEW.operation_id, NEW.prev_hash, NEW.hash, NEW.chain_seq)
       IS DISTINCT FROM
       (OLD.public_id, OLD.created_at, OLD.principal, OLD.agent_label, OLD.classification, OLD.sql_text,
        OLD.operation_id, OLD.prev_hash, OLD.hash, OLD.chain_seq) THEN
        RAISE EXCEPTION 'Rowback ledger is append-only: recorded checkpoint fields cannot be changed.';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SET search_path = rowback, pg_temp;

DROP TRIGGER IF EXISTS rowback_chain ON rowback.checkpoints;
CREATE TRIGGER rowback_chain BEFORE INSERT ON rowback.checkpoints
    FOR EACH ROW EXECUTE FUNCTION rowback.chain_checkpoint();
DROP TRIGGER IF EXISTS rowback_immutable ON rowback.checkpoints;
CREATE TRIGGER rowback_immutable BEFORE UPDATE OR DELETE ON rowback.checkpoints
    FOR EACH ROW EXECUTE FUNCTION rowback.guard_checkpoint_immutability();

-- Walks the chain; returns how many links were checked, the first broken one
-- (NULL if intact) and the head hash to anchor externally.
CREATE OR REPLACE FUNCTION rowback.verify_ledger()
RETURNS TABLE (checked BIGINT, first_broken_public_id TEXT, head_hash TEXT)
SET search_path = rowback, pg_temp
AS $$
DECLARE
    r RECORD;
    v_prev TEXT := 'genesis';
    v_expected_seq BIGINT := 1;
BEGIN
    checked := 0;
    FOR r IN SELECT * FROM rowback.checkpoints WHERE chain_seq IS NOT NULL ORDER BY chain_seq LOOP
        IF r.chain_seq <> v_expected_seq OR r.prev_hash IS DISTINCT FROM v_prev
           OR r.hash IS DISTINCT FROM rowback.checkpoint_hash(r.prev_hash, r.public_id, r.created_at, r.principal,
                                                            r.agent_label, r.classification, r.sql_text, r.operation_id) THEN
            first_broken_public_id := r.public_id;
            head_hash := NULL;
            RETURN NEXT;
            RETURN;
        END IF;
        v_prev := r.hash;
        v_expected_seq := v_expected_seq + 1;
        checked := checked + 1;
    END LOOP;
    head_hash := CASE WHEN checked > 0 THEN v_prev END;
    RETURN NEXT;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
