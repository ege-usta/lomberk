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
    table_oid     OID,
    op            CHAR(1) NOT NULL, -- 'I', 'U', 'D'
    pk            JSONB,
    old_row       JSONB,
    new_row       JSONB,
    schema_snapshot JSONB
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

DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='undogate' AND table_name='row_changes' AND column_name='table_oid') THEN
        ALTER TABLE undogate.row_changes ADD COLUMN table_oid OID;
    END IF;
END $$;

DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='undogate' AND table_name='row_changes' AND column_name='schema_snapshot') THEN
        ALTER TABLE undogate.row_changes ADD COLUMN schema_snapshot JSONB;
    END IF;
END $$;

DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='undogate' AND table_name='checkpoints' AND column_name='operation_id') THEN
        ALTER TABLE undogate.checkpoints ADD COLUMN operation_id TEXT;
        CREATE UNIQUE INDEX idx_checkpoints_idempotency ON undogate.checkpoints (agent_label, operation_id) WHERE operation_id IS NOT NULL;
    END IF;
END $$;


DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='undogate' AND table_name='checkpoints' AND column_name='principal') THEN
        ALTER TABLE undogate.checkpoints ADD COLUMN principal TEXT NOT NULL DEFAULT 'system';
        DROP INDEX IF EXISTS undogate.idx_checkpoints_idempotency;
        CREATE UNIQUE INDEX idx_checkpoints_idempotency ON undogate.checkpoints (principal, operation_id) WHERE operation_id IS NOT NULL;
    END IF;
END $$;

-- MIGRATION: tamper-evident ledger ordering (chain position, assigned under a lock)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='undogate' AND table_name='checkpoints' AND column_name='chain_seq') THEN
        ALTER TABLE undogate.checkpoints ADD COLUMN chain_seq BIGINT UNIQUE;
    END IF;
END $$;

-- Slack approval outbox: one row per pending checkpoint posted to Slack.
-- The (team, channel, ts) binding is the ONLY thing that authorizes a button click.
CREATE TABLE IF NOT EXISTS undogate.slack_messages (
    public_id   TEXT PRIMARY KEY REFERENCES undogate.checkpoints(public_id),
    team_id     TEXT,
    channel_id  TEXT NOT NULL,
    message_ts  TEXT,
    state       TEXT NOT NULL CHECK (state IN ('publishing', 'bound', 'unknown')),
    claimed_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (channel_id, message_ts)
);
