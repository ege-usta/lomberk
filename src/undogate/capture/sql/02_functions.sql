-- 1. Checkpoint Management
CREATE OR REPLACE FUNCTION undogate.begin_checkpoint(
    p_sql_text TEXT,
    p_classification TEXT,
    p_decision TEXT,
    p_agent_label TEXT DEFAULT NULL
) RETURNS BIGINT AS $$
DECLARE
    v_cp_id BIGINT;
    v_public_id TEXT;
    v_prev_hash TEXT;
    v_hash TEXT;
BEGIN
    v_public_id := 'cp_' || substr(md5(random()::text || clock_timestamp()::text), 1, 8);
    
    LOCK TABLE undogate.checkpoints IN EXCLUSIVE MODE;
    
    SELECT hash INTO v_prev_hash 
    FROM undogate.checkpoints 
    ORDER BY id DESC LIMIT 1;
    
    IF v_prev_hash IS NULL THEN
        v_prev_hash := 'genesis';
    END IF;
    
    v_hash := md5(v_prev_hash || p_sql_text || p_classification || p_decision || COALESCE(p_agent_label, ''));
    
    INSERT INTO undogate.checkpoints (public_id, agent_label, sql_text, classification, decision, status, prev_hash, hash)
    VALUES (v_public_id, p_agent_label, p_sql_text, p_classification, p_decision, 'pending', v_prev_hash, v_hash)
    RETURNING id INTO v_cp_id;
    
    PERFORM set_config('undogate.checkpoint_id', v_cp_id::text, true);
    PERFORM set_config('undogate.seq', '0', true);
    
    RETURN v_cp_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.finish_checkpoint(
    p_cp_id BIGINT,
    p_rows_affected INTEGER
) RETURNS VOID AS $$
BEGIN
    UPDATE undogate.checkpoints 
    SET status = 'applied', rows_affected = p_rows_affected
    WHERE id = p_cp_id AND status = 'pending';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or invalid state transition.', p_cp_id;
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

-- 2. Row Trigger Function
CREATE OR REPLACE FUNCTION undogate.capture_row_change() RETURNS TRIGGER AS $$
DECLARE
    v_cp_id_text TEXT;
    v_cp_id BIGINT;
    v_seq BIGINT;
    v_pk JSONB;
    v_old JSONB := NULL;
    v_new JSONB := NULL;
    v_caller TEXT;
BEGIN
    v_cp_id_text := current_setting('undogate.checkpoint_id', true);
    IF v_cp_id_text IS NULL OR v_cp_id_text = '' THEN
        -- If current user is the agent role, DENY contextless writes
        IF session_user = '__AGENT_ROLE__' THEN
            RAISE EXCEPTION 'Undogate Security Violation: DML execution attempted outside of a trusted checkpoint context.';
        ELSE
            -- Normal backend application writing, just return NEW (skip capture)
            RETURN NULL; -- Wait, AFTER trigger returning NULL is fine, but for row triggers it's usually RETURN NULL for AFTER.
        END IF;
    END IF;
    
    v_cp_id := v_cp_id_text::BIGINT;
    
    v_seq := current_setting('undogate.seq', true)::BIGINT + 1;
    PERFORM set_config('undogate.seq', v_seq::text, true);

    IF TG_OP = 'DELETE' THEN
        v_old := to_jsonb(OLD);
        IF v_old ? 'id' THEN v_pk := jsonb_build_object('id', v_old->>'id'); ELSE v_pk := v_old; END IF;
    ELSIF TG_OP = 'UPDATE' THEN
        v_old := to_jsonb(OLD);
        v_new := to_jsonb(NEW);
        IF v_new ? 'id' THEN v_pk := jsonb_build_object('id', v_new->>'id'); ELSE v_pk := v_new; END IF;
    ELSIF TG_OP = 'INSERT' THEN
        v_new := to_jsonb(NEW);
        IF v_new ? 'id' THEN v_pk := jsonb_build_object('id', v_new->>'id'); ELSE v_pk := v_new; END IF;
    END IF;

    INSERT INTO undogate.row_changes (checkpoint_id, seq, table_schema, table_name, op, pk, old_row, new_row)
    VALUES (v_cp_id, v_seq, TG_TABLE_SCHEMA, TG_TABLE_NAME, substr(TG_OP, 1, 1), v_pk, v_old, v_new);
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

-- 3. Trigger Installer and Table Registration
CREATE OR REPLACE FUNCTION undogate.register_table(p_schema TEXT, p_table TEXT, p_pk_column TEXT DEFAULT 'id', p_agent_role TEXT DEFAULT 'undogate_agent') RETURNS VOID AS $$
DECLARE
    v_oid OID;
BEGIN
    -- Resolve OID
    SELECT c.oid INTO v_oid
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = p_schema AND c.relname = p_table AND c.relkind = 'r';
    
    IF v_oid IS NULL THEN
        RAISE EXCEPTION 'Table %.% does not exist or is not a base table.', p_schema, p_table;
    END IF;
    
    -- Insert into registry
    INSERT INTO undogate.registered_tables (table_oid, schema_name, table_name, pk_column)
    VALUES (v_oid, p_schema, p_table, p_pk_column)
    ON CONFLICT (schema_name, table_name) DO UPDATE 
    SET table_oid = EXCLUDED.table_oid, pk_column = EXCLUDED.pk_column;
    
    -- Attach trigger
    EXECUTE format('DROP TRIGGER IF EXISTS undogate_capture ON %I.%I', p_schema, p_table);
    EXECUTE format(
        'CREATE TRIGGER undogate_capture AFTER INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION undogate.capture_row_change()',
        p_schema, p_table
    );
    
    -- Grant DML to agent role
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO %I', p_schema, p_table, p_agent_role);
    EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO %I', p_schema, p_agent_role);

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
        RAISE EXCEPTION 'Pending checkpoint not found.';
    END IF;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.fail_checkpoint(
    p_cp_id BIGINT
) RETURNS VOID AS $$
BEGIN
    UPDATE undogate.checkpoints 
    SET status = 'failed'
    WHERE id = p_cp_id AND status = 'pending';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Checkpoint % not found or invalid state transition.', p_cp_id;
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

-- Revoke public execute

REVOKE ALL ON SCHEMA undogate FROM PUBLIC;
REVOKE ALL ON SCHEMA undogate_trash FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA undogate FROM PUBLIC;

CREATE OR REPLACE FUNCTION undogate.grant_agent_access(p_agent_role TEXT) RETURNS VOID AS $$
BEGIN
    EXECUTE format('GRANT USAGE ON SCHEMA undogate TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.begin_checkpoint TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.finish_checkpoint TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.reject_checkpoint TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.fail_checkpoint TO %I', p_agent_role);
    EXECUTE format('GRANT EXECUTE ON FUNCTION undogate.get_pending_checkpoint TO %I', p_agent_role);
    
    -- Agent only needs SELECT on checkpoints to fetch id, but they can use get_pending_checkpoint instead!
    -- Actually they do need SELECT in execute_pending if they don't use the function. Let's just grant SELECT, but NOT UPDATE.
    EXECUTE format('GRANT SELECT ON undogate.checkpoints TO %I', p_agent_role);
    EXECUTE format('GRANT SELECT ON undogate.registered_tables TO %I', p_agent_role);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

-- Revoke public execute
REVOKE ALL ON SCHEMA undogate FROM PUBLIC;
REVOKE ALL ON SCHEMA undogate_trash FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA undogate FROM PUBLIC;
