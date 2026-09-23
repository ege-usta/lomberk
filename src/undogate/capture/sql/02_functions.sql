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
BEGIN
    v_public_id := 'cp_' || substr(md5(random()::text || clock_timestamp()::text), 1, 8);
    
    INSERT INTO undogate.checkpoints (public_id, agent_label, sql_text, classification, decision, status)
    VALUES (v_public_id, p_agent_label, p_sql_text, p_classification, p_decision, 'pending')
    RETURNING id INTO v_cp_id;
    
    -- Set the local configuration for the transaction
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
    WHERE id = p_cp_id;
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
    v_pk_col TEXT;
BEGIN
    -- Check if we are inside a tracked checkpoint
    v_cp_id_text := current_setting('undogate.checkpoint_id', true);
    IF v_cp_id_text IS NULL OR v_cp_id_text = '' THEN
        RETURN NULL; -- Not tracked, do nothing. Returning NULL in AFTER trigger is fine.
    END IF;
    
    v_cp_id := v_cp_id_text::BIGINT;
    
    -- Increment sequence for ordering changes
    v_seq := current_setting('undogate.seq', true)::BIGINT + 1;
    PERFORM set_config('undogate.seq', v_seq::text, true);

    -- Try to find PK dynamically (simplified to 'id' for MVP, or we can use JSONB manipulation)
    -- Actually for MVP we assume tables have an 'id' column or we just capture the whole row as PK if none.
    -- To keep it robust, let's extract the PK based on pg_index if possible, but that's heavy per row.
    -- For now, let's just use 'id' if it exists, else use the whole row as an identifier.
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

-- 3. Trigger Installer
CREATE OR REPLACE FUNCTION undogate.attach_trigger_to_table(p_schema TEXT, p_table TEXT) RETURNS VOID AS $$
BEGIN
    EXECUTE format('DROP TRIGGER IF EXISTS undogate_capture ON %I.%I', p_schema, p_table);
    EXECUTE format(
        'CREATE TRIGGER undogate_capture AFTER INSERT OR UPDATE OR DELETE ON %I.%I FOR EACH ROW EXECUTE FUNCTION undogate.capture_row_change()',
        p_schema, p_table
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;

CREATE OR REPLACE FUNCTION undogate.attach_triggers_to_all() RETURNS VOID AS $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN 
        SELECT table_schema, table_name 
        FROM information_schema.tables 
        WHERE table_schema NOT IN ('undogate', 'undogate_trash', 'information_schema', 'pg_catalog') 
          AND table_type = 'BASE TABLE'
    LOOP
        PERFORM undogate.attach_trigger_to_table(r.table_schema, r.table_name);
    END LOOP;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = undogate, pg_temp;
