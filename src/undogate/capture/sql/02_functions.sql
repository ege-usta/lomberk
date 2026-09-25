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

    SELECT a.attname INTO v_pk
    FROM pg_index i
    JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
    WHERE i.indrelid = TG_RELID AND i.indisprimary;
    
    IF v_pk IS NULL THEN
        RAISE EXCEPTION 'Undogate Security Violation: Table %.% has no primary key.', TG_TABLE_SCHEMA, TG_TABLE_NAME;
    END IF;
    
    IF (SELECT indnatts FROM pg_index WHERE indrelid = TG_RELID AND indisprimary) > 1 THEN
        RAISE EXCEPTION 'Undogate Security Violation: Composite primary keys are not supported (%.%).', TG_TABLE_SCHEMA, TG_TABLE_NAME;
    END IF;

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
        checkpoint_id, table_schema, table_name, table_oid, op, pk,
        old_row, new_row, seq
    ) VALUES (
        v_cp_id, TG_TABLE_SCHEMA, TG_TABLE_NAME, TG_RELID, substr(TG_OP, 1, 1), jsonb_build_object(v_pk, COALESCE(v_old->>v_pk, v_new->>v_pk)),
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
    
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.execute_undo TO %I', p_control_role);
    

    EXECUTE format('GRANT SELECT ON undogate.checkpoints TO %I', p_control_role);
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



CREATE OR REPLACE FUNCTION undogate.lock_table_for_undo(
    p_schema TEXT,
    p_table TEXT
) RETURNS VOID AS $$
BEGIN
    EXECUTE format('LOCK TABLE %I.%I IN SHARE ROW EXCLUSIVE MODE NOWAIT', p_schema, p_table);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
CREATE OR REPLACE FUNCTION undogate.execute_undo(
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
BEGIN
    -- 1. Fetch and lock original checkpoint
    SELECT id, status INTO v_cp_id, v_status
    FROM undogate.checkpoints
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
        FROM undogate.row_changes 
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

        IF EXISTS (
            SELECT 1 FROM pg_constraint 
            WHERE (conrelid = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass 
               OR confrelid = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass)
            AND contype = 'f'
        ) THEN
            RAISE EXCEPTION 'Unsupported schema: Foreign keys not allowed on %', v_change.table_name;
        END IF;
        
        -- Check triggers: exactly ONE trigger allowed, and it MUST be undogate_capture, and ENABLED.
        IF EXISTS (
            SELECT 1 FROM pg_trigger 
            WHERE tgrelid = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass
            AND tgname != 'undogate_capture' AND tgisinternal = false
        ) THEN
            RAISE EXCEPTION 'Unsupported schema: Triggers not allowed on %', v_change.table_name;
        END IF;
        
        IF NOT EXISTS (
            SELECT 1 FROM pg_trigger 
            WHERE tgrelid = (quote_ident(v_change.table_schema) || '.' || quote_ident(v_change.table_name))::regclass
            AND tgname = 'undogate_capture' AND tgenabled = 'O'
            AND tgtype = 29 AND tgattr = '' 
            AND tgfoid = 'undogate.capture_row_change'::regproc
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
        
        IF EXISTS (
            SELECT 1 FROM pg_attribute
            WHERE attrelid = v_change.table_oid
            AND (attgenerated != '' OR attidentity != '')
            AND NOT attisdropped
        ) THEN
            RAISE EXCEPTION 'Unsupported schema: Generated/Identity columns not allowed on %', v_change.table_name;
        END IF;
    END LOOP;

    -- 3. Create new checkpoint for the undo operation
    SELECT gen_random_uuid() INTO v_token;
    v_undo_public_id := 'undo_' || replace(gen_random_uuid()::text, '-', '');
    
    INSERT INTO undogate.checkpoints (public_id, sql_text, classification, decision, agent_label, status, capability_token, exec_txid)
    VALUES (v_undo_public_id, 'UNDO ' || p_public_id, 'WRITE_UNDO', 'ALLOW', p_agent_label, 'executing', v_token, txid_current())
    RETURNING id INTO v_undo_cp_id;

    -- Set GUCs so trigger logs it
    PERFORM set_config('undogate.checkpoint_id', v_undo_cp_id::text, true);
    PERFORM set_config('undogate.capability_token', v_token::text, true);
    PERFORM set_config('undogate.seq', '1', true);
    
    v_seq_val := 1;

    -- 4. Apply reverse DML in LIFO order
    FOR v_change IN 
        SELECT table_schema, table_name, table_oid, op, pk, old_row, new_row 
        FROM undogate.row_changes 
        WHERE checkpoint_id = v_cp_id 
        ORDER BY seq DESC
    LOOP
        PERFORM set_config('undogate.seq', v_seq_val::text, true);
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
            
            IF EXISTS (
                SELECT 1 FROM jsonb_object_keys(COALESCE(v_change.old_row, '{}'::jsonb) || COALESCE(v_change.new_row, '{}'::jsonb)) k
                LEFT JOIN pg_attribute a ON a.attrelid = v_change.table_oid AND a.attname = k AND NOT a.attisdropped AND a.attnum > 0
                WHERE a.attname IS NULL
            ) THEN
                RAISE EXCEPTION 'Security Violation: Schema drift detected (dropped columns) for %', v_full_table;
            END IF;
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
            FROM jsonb_object_keys(v_change.old_row) AS key;
            
            EXECUTE format('UPDATE %s SET %s WHERE %I = %L', 
                v_full_table, 
                v_set_clauses, 
                v_live_pk, 
                (v_change.pk->>v_live_pk)) USING v_change.old_row;

        ELSIF v_change.op = 'D' THEN
            EXECUTE format('INSERT INTO %s SELECT * FROM jsonb_populate_record(null::%s, $1::jsonb)', v_full_table, v_full_table) USING v_change.old_row;
        ELSE
            RAISE EXCEPTION 'Unknown operation: %', v_change.op;
        END IF;
        
        v_affected := v_affected + 1;
    END LOOP;

    -- 5. Mark old checkpoint undone, new checkpoint applied
    UPDATE undogate.checkpoints SET status = 'undone' WHERE id = v_cp_id;
    UPDATE undogate.checkpoints SET status = 'applied' WHERE id = v_undo_cp_id;
    
    INSERT INTO undogate.undo_operations (source_checkpoint_id, undo_checkpoint_id)
    VALUES (v_cp_id, v_undo_cp_id);

    RETURN jsonb_build_object(
        'status', 'applied',
        'public_id', v_undo_public_id,
        'rows_affected', v_affected
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;
