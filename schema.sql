-- Create the srp_users table
CREATE TABLE IF NOT EXISTS srp_users (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username   TEXT        UNIQUE NOT NULL CHECK (length(username) BETWEEN 3 AND 64),
    salt       TEXT        NOT NULL CHECK (length(salt) <= 256),
    verifier   TEXT        NOT NULL CHECK (length(verifier) <= 1024),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create the e2ee_messages table
-- FK references srp_users.id (not username) for referential stability
CREATE TABLE IF NOT EXISTS e2ee_messages (
    id             UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID        NOT NULL REFERENCES srp_users(id) ON DELETE CASCADE,
    encrypted_data TEXT        NOT NULL,
    iv             TEXT        NOT NULL,
    auth_tag       TEXT        NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for the primary access pattern: fetch messages by owner, newest first
CREATE INDEX IF NOT EXISTS idx_e2ee_messages_user_created
    ON e2ee_messages(user_id, created_at DESC);

-- Enable Row Level Security (required for production)
-- All access goes through the Node.js server using the Service Role Key,
-- so RLS acts as a safety net against accidental direct client access.
ALTER TABLE srp_users     ENABLE ROW LEVEL SECURITY;
ALTER TABLE e2ee_messages ENABLE ROW LEVEL SECURITY;

-- Auto-update updated_at on srp_users
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE OR REPLACE TRIGGER trg_srp_users_updated_at
    BEFORE UPDATE ON srp_users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
