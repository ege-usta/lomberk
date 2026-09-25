-- 1. Create Schemas
CREATE SCHEMA IF NOT EXISTS undogate;
CREATE SCHEMA IF NOT EXISTS undogate_trash;

-- 2. Create Tables
CREATE TABLE IF NOT EXISTS undogate.checkpoints (
    id            BIGSERIAL PRIMARY KEY,
    public_id     TEXT UNIQUE NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    agent_label   TEXT,
    sql_text      TEXT NOT NULL,
    classification TEXT NOT NULL,
    decision      TEXT NOT NULL,
    status        TEXT NOT NULL, -- 'applied', 'undone', 'failed', 'pending'
    rows_affected INTEGER,
    exec_token UUID,
    ddl_undo_plan JSONB,
    prev_hash     TEXT,
    hash          TEXT
);

CREATE TABLE IF NOT EXISTS undogate.row_changes (
    id            BIGSERIAL PRIMARY KEY,
    checkpoint_id BIGINT NOT NULL REFERENCES undogate.checkpoints(id) ON DELETE CASCADE,
    seq           BIGINT NOT NULL,
    table_schema  TEXT NOT NULL,
    table_name    TEXT NOT NULL,
    op            CHAR(1) NOT NULL, -- 'I', 'U', 'D'
    pk            JSONB,
    old_row       JSONB,
    new_row       JSONB
);

CREATE TABLE IF NOT EXISTS undogate.registered_tables (
    table_oid     OID PRIMARY KEY,
    schema_name   TEXT NOT NULL,
    table_name    TEXT NOT NULL,
    pk_column     TEXT NOT NULL,
    UNIQUE(schema_name, table_name)
);

CREATE SEQUENCE IF NOT EXISTS undogate.seq_row_changes START 1;



-- MIGRATION: Update columns for capability-based execution
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='undogate' AND table_name='checkpoints' AND column_name='capability_token') THEN
        ALTER TABLE undogate.checkpoints ADD COLUMN capability_token UUID UNIQUE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='undogate' AND table_name='checkpoints' AND column_name='exec_txid') THEN
        ALTER TABLE undogate.checkpoints ADD COLUMN exec_txid BIGINT;
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS undogate.undo_operations (
    id                   BIGSERIAL PRIMARY KEY,
    source_checkpoint_id BIGINT NOT NULL UNIQUE REFERENCES undogate.checkpoints(id),
    undo_checkpoint_id   BIGINT NOT NULL UNIQUE REFERENCES undogate.checkpoints(id),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
