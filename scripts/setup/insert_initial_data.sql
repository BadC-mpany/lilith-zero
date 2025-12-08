-- Insert customer (replace HASH_VALUE with actual hash from generate_api_key_hash.ps1)
-- Run: .\scripts\generate_api_key_hash.ps1 first to get the hash
INSERT INTO customers (api_key_hash, owner, mcp_upstream_url, policy_name)
VALUES (
    'HASH_VALUE',  -- Replace with actual SHA-256 hash from api_key_hash.txt
    'demo_user',
    'http://localhost:9000',
    'default_policy'
)
ON CONFLICT (api_key_hash) DO NOTHING;

-- Insert default policy
INSERT INTO policies (name, static_rules, taint_rules)
VALUES (
    'default_policy',
    '{"read_file": "ALLOW", "write_file": "DENY", "execute_command": "DENY"}'::jsonb,
    '[]'::jsonb
)
ON CONFLICT (name) DO NOTHING;

-- Verify data
SELECT 'Customers:' as info;
SELECT api_key_hash, owner, policy_name FROM customers WHERE revoked_at IS NULL;

SELECT 'Policies:' as info;
SELECT name, static_rules FROM policies;

