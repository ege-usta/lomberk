CREATE OR REPLACE FUNCTION undogate.begin_checkpoint(
    p_sql_text TEXT,
    p_classification TEXT,
    p_agent_label TEXT,
    OUT o_cp_id BIGINT,
    OUT o_public_id TEXT
) AS $$
DECLARE
    v_public_id TEXT;
    v_id BIGINT;
BEGIN
    v_public_id := 'cp_' || replace(gen_random_uuid()::text, '-', '');
    
    INSERT INTO undogate.checkpoints (
        public_id, sql_text, classification, agent_label, status, decision
    ) VALUES (
        v_public_id, p_sql_text, p_classification, p_agent_label, 'pending', 'REQUIRE_APPROVAL'
    ) RETURNING id INTO v_id;
    
    o_cp_id := v_id;
    o_public_id := v_public_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.approve_checkpoint(
    p_public_id TEXT,
    p_decision TEXT
) RETURNS UUID AS $$
DECLARE
    v_token UUID;
BEGIN
    v_token := gen_random_uuid();
    
    UPDATE undogate.checkpoints 
    SET status = 'approved', decision = p_decision, capability_token = v_token
    WHERE public_id = p_public_id AND status = 'pending';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or not in pending state.', p_public_id;
    END IF;
    
    RETURN v_token;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.reject_checkpoint(
    p_public_id TEXT
) RETURNS VOID AS $$
BEGIN
    UPDATE undogate.checkpoints 
    SET status = 'rejected'
    WHERE public_id = p_public_id AND status = 'pending';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or not in pending state.', p_public_id;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.fail_checkpoint(
    p_public_id TEXT
) RETURNS VOID AS $$
BEGIN
    UPDATE undogate.checkpoints 
    SET status = 'failed'
    WHERE public_id = p_public_id AND status IN ('pending', 'approved', 'executing');
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or invalid state transition.', p_public_id;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.claim_checkpoint(
    p_capability_token UUID
) RETURNS VOID AS $$
DECLARE
    v_txid BIGINT;
BEGIN
    v_txid := txid_current();
    
    UPDATE undogate.checkpoints 
    SET status = 'executing', exec_txid = v_txid
    WHERE capability_token = p_capability_token AND status = 'approved';
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint not found or not in approved state for the given capability token.';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.finish_checkpoint(
    p_capability_token UUID,
    p_rows_affected INTEGER
) RETURNS VOID AS $$
DECLARE
    v_txid BIGINT;
    v_guc TEXT;
BEGIN
    v_txid := txid_current();
    v_guc := current_setting('undogate.capability_token', true);
    
    IF p_capability_token::TEXT != v_guc THEN
        RAISE EXCEPTION 'Security Violation: Cannot finish checkpoint without matching execution token in GUC.';
    END IF;

    UPDATE undogate.checkpoints 
    SET status = 'applied', rows_affected = p_rows_affected
    WHERE capability_token = p_capability_token AND status = 'executing' AND exec_txid = v_txid;
    
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint not found or invalid execution context (txid mismatch).';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.capture_row_change() RETURNS TRIGGER AS $$
DECLARE
    v_cp_id_text TEXT;
    v_cp_id BIGINT;
    v_seq BIGINT;
    v_pk TEXT;
    v_old JSONB := NULL;
    v_new JSONB := NULL;
    v_caller TEXT;
BEGIN
    v_caller := session_user;
    v_cp_id_text := current_setting('undogate.checkpoint_id', true);
    
    IF v_cp_id_text IS NULL OR v_cp_id_text = '' THEN
        IF v_caller = '__AGENT_ROLE__' THEN
            RAISE EXCEPTION 'Undogate Security Violation: DML execution attempted outside of a trusted checkpoint context.';
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
        FROM undogate.checkpoints 
        WHERE id = v_cp_id;
        
        IF NOT FOUND THEN
            RAISE EXCEPTION 'Undogate Security Violation: Invalid checkpoint context.';
        END IF;
        
        v_guc_token := current_setting('undogate.capability_token', true);
        
        IF v_db_token IS NULL OR v_guc_token IS NULL OR v_db_token::TEXT != v_guc_token THEN
            RAISE EXCEPTION 'Undogate Security Violation: Invalid or missing capability token.';
        END IF;
        
        IF v_db_status != 'executing' THEN
            RAISE EXCEPTION 'Undogate Security Violation: Checkpoint is not in executing state.';
        END IF;
        
        IF v_db_txid IS DISTINCT FROM txid_current() THEN
            RAISE EXCEPTION 'Undogate Security Violation: Transaction context mismatch (token stolen or replayed).';
        END IF;
    END;
    
    v_seq := current_setting('undogate.seq', true)::BIGINT + 1;
    PERFORM set_config('undogate.seq', v_seq::text, true);

    SELECT pk_column INTO v_pk 
    FROM undogate.registered_tables 
    WHERE schema_name = TG_TABLE_SCHEMA AND table_name = TG_TABLE_NAME;

    IF TG_OP = 'DELETE' THEN
        v_old := row_to_json(OLD);
    ELSIF TG_OP = 'UPDATE' THEN
        v_old := row_to_json(OLD);
        v_new := row_to_json(NEW);
        IF (v_old->>v_pk) IS DISTINCT FROM (v_new->>v_pk) THEN
            RAISE EXCEPTION 'Undogate Security Violation: Primary key updates are forbidden.';
        END IF;
    ELSIF TG_OP = 'INSERT' THEN
        v_new := row_to_json(NEW);
    END IF;

    INSERT INTO undogate.row_changes (
        checkpoint_id, table_schema, table_name, op, pk,
        old_row, new_row, seq
    ) VALUES (
        v_cp_id, TG_TABLE_SCHEMA, TG_TABLE_NAME, substr(TG_OP, 1, 1), jsonb_build_object(v_pk, COALESCE(v_old->>v_pk, v_new->>v_pk)),
        v_old, v_new, v_seq
    );

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    ELSE
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;


CREATE OR REPLACE FUNCTION undogate.get_pending_checkpoint(
    p_public_id TEXT
) RETURNS TABLE (id BIGINT, sql_text TEXT, status TEXT) AS $$
BEGIN
    RETURN QUERY SELECT c.id, c.sql_text, c.status
    FROM undogate.checkpoints c
    WHERE c.public_id = p_public_id FOR UPDATE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.register_table(
    p_schema TEXT,
    p_table TEXT,
    p_pk_column TEXT,
    p_agent_role TEXT
) RETURNS VOID AS $$
DECLARE
    v_table_oid OID;
BEGIN
    SELECT c.oid INTO v_table_oid
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = p_schema AND c.relname = p_table;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Table %.% does not exist.', p_schema, p_table;
    END IF;

    INSERT INTO undogate.registered_tables (schema_name, table_name, table_oid, pk_column)
    VALUES (p_schema, p_table, v_table_oid, p_pk_column)
    ON CONFLICT (schema_name, table_name) DO UPDATE 
    SET table_oid = EXCLUDED.table_oid, pk_column = EXCLUDED.pk_column;

    EXECUTE format('DROP TRIGGER IF EXISTS undogate_capture ON %I.%I', p_schema, p_table);
    EXECUTE format('CREATE TRIGGER undogate_capture AFTER INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION undogate.capture_row_change()', p_schema, p_table);

    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO %I', p_schema, p_table, p_agent_role);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', p_schema, p_agent_role);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.grant_access(p_control_role TEXT, p_agent_role TEXT) RETURNS VOID AS $$
BEGIN
    -- Revoke all from public for security definer functions
    EXECUTE 'REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA undogate FROM PUBLIC';

    -- Common schema usage
    EXECUTE format('GRANT USAGE ON SCHEMA undogate TO %I', p_control_role);
    EXECUTE format('GRANT USAGE ON SCHEMA undogate TO %I', p_agent_role);
    
    -- Control Plane (only control role)
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.begin_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.approve_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.reject_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.fail_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.claim_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.finish_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.get_pending_checkpoint TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.register_table TO %I', p_control_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.lock_table_for_undo TO %I', p_control_role);
    
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.execute_undo_dml TO %I', p_control_role);
    

    EXECUTE format('GRANT SELECT, UPDATE ON undogate.checkpoints TO %I', p_control_role);
    EXECUTE format('GRANT SELECT ON undogate.row_changes TO %I', p_control_role);
    EXECUTE format('GRANT INSERT ON undogate.undo_operations TO %I', p_control_role);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA undogate TO %I', p_control_role);
    
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.list_pending_checkpoints TO %I', p_control_role);
    
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.check_checkpoint_status TO %I', p_control_role);
    
    
    -- Runtime (only agent role)
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.claim_checkpoint TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.finish_checkpoint TO %I', p_agent_role);
    
    -- Ensure separation of duties
    
    
    
    EXECUTE format('REVOKE EXECUTE ON FUNCTION undogate.begin_checkpoint FROM %I', p_agent_role);
    EXECUTE format('REVOKE EXECUTE ON FUNCTION undogate.approve_checkpoint FROM %I', p_agent_role);
    
    -- Legacy cleanup
    EXECUTE format('REVOKE ALL ON undogate.checkpoints FROM %I', p_agent_role);
    
    
    EXECUTE format('GRANT SELECT ON undogate.registered_tables TO %I', p_agent_role);
    EXECUTE format('GRANT SELECT ON undogate.registered_tables TO %I', p_control_role);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION undogate.check_checkpoint_status(
    p_public_id TEXT
) RETURNS TEXT
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_status TEXT;
BEGIN
    SELECT status INTO v_status 
    FROM undogate.checkpoints 
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

CREATE OR REPLACE FUNCTION undogate.list_pending_checkpoints()
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
    FROM undogate.checkpoints c
    WHERE c.status = 'pending';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION undogate.execute_undo_dml(
    p_schema TEXT,
    p_table TEXT,
    p_op CHAR(1),
    p_pk_col TEXT,
    p_pk_val TEXT,
    p_old_row JSONB,
    p_new_row JSONB
) RETURNS VOID AS $$
DECLARE
    v_full_table TEXT := quote_ident(p_schema) || '.' || quote_ident(p_table);
    v_curr JSONB;
    v_set_clauses TEXT;
    v_key TEXT;
BEGIN
    IF p_op = 'I' THEN
        EXECUTE format('SELECT row_to_json(t) FROM %s t WHERE %I = %L FOR UPDATE NOWAIT', v_full_table, p_pk_col, p_pk_val) INTO v_curr;
        IF v_curr IS NULL THEN
            RAISE EXCEPTION 'Conflict: Row % missing in %', p_pk_val, v_full_table;
        END IF;
        IF (v_curr::jsonb - p_pk_col) != (p_new_row::jsonb - p_pk_col) THEN
            -- we compare everything except PK in case of formatting diffs, but actually let's compare exactly
            IF v_curr::jsonb != p_new_row::jsonb THEN
                RAISE EXCEPTION 'Conflict: Row % in % has been modified', p_pk_val, v_full_table;
            END IF;
        END IF;
        EXECUTE format('DELETE FROM %s WHERE %I = %L', v_full_table, p_pk_col, p_pk_val);
        
    ELSIF p_op = 'U' THEN
        EXECUTE format('SELECT row_to_json(t) FROM %s t WHERE %I = %L FOR UPDATE NOWAIT', v_full_table, p_pk_col, p_pk_val) INTO v_curr;
        IF v_curr IS NULL THEN
            RAISE EXCEPTION 'Conflict: Row % missing in %', p_pk_val, v_full_table;
        END IF;
        IF v_curr::jsonb != p_new_row::jsonb THEN
            RAISE EXCEPTION 'Conflict: Row % in % has been modified', p_pk_val, v_full_table;
        END IF;
        
        SELECT string_agg(quote_ident(key) || ' = (SELECT "' || key || '" FROM jsonb_populate_record(null::' || v_full_table || ', $1::jsonb))', ', ') 
        INTO v_set_clauses
        FROM jsonb_object_keys(p_old_row) AS key;
        
        EXECUTE format('UPDATE %s SET %s WHERE %I = %L', v_full_table, v_set_clauses, p_pk_col, p_pk_val) USING p_old_row;

    ELSIF p_op = 'D' THEN
        EXECUTE format('INSERT INTO %s SELECT * FROM jsonb_populate_record(null::%s, $1::jsonb)', v_full_table, v_full_table) USING p_old_row;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION undogate.lock_table_for_undo(
    p_schema TEXT,
    p_table TEXT
) RETURNS VOID AS $$
BEGIN
    EXECUTE format('LOCK TABLE %I.%I IN SHARE ROW EXCLUSIVE MODE NOWAIT', p_schema, p_table);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
