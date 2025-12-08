-- Customers table
CREATE TABLE IF NOT EXISTS customers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_hash VARCHAR(64) UNIQUE NOT NULL,
    owner VARCHAR(255) NOT NULL,
    mcp_upstream_url TEXT NOT NULL,
    policy_name VARCHAR(255) NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_key_hash_active ON customers(api_key_hash) WHERE revoked_at IS NULL;

-- Policies table
CREATE TABLE IF NOT EXISTS policies (
    name VARCHAR(255) PRIMARY KEY,
    static_rules JSONB NOT NULL,
    taint_rules JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit log table
CREATE TABLE IF NOT EXISTS auth_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_hash VARCHAR(64),
    event_type VARCHAR(50) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    session_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_api_key ON auth_audit_log(api_key_hash);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON auth_audit_log(created_at);