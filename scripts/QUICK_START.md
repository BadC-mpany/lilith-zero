# Quick Start Guide

## One-Page Quick Reference

### Prerequisites Check

```powershell
# PostgreSQL
Get-Service postgresql*

# Redis/Memurai
& "C:\Program Files\Memurai\redis-cli.exe" ping

# Rust
cargo --version

# Python
python --version
```

### Setup (One-Time)

```powershell
# 1. Create database
$env:PGPASSWORD = "your_password"
psql -U postgres -f scripts/setup_database.sql

# 2. Generate API key hash
.\scripts\generate_api_key_hash.ps1

# 3. Insert initial data
.\scripts\insert_initial_data_with_hash.ps1 -PostgresPassword "your_password"

# 4. Generate crypto keys
.\scripts\generate_keys.ps1
.\scripts\copy_public_key_to_mcp.ps1

# 5. Setup tool registry
.\scripts\setup_tool_registry.ps1

# 6. Create .env files (see docs/LOCAL_INTEGRATION.md)
```

### Start Services

```powershell
# Option 1: Automated
.\scripts\start_all.ps1

# Option 2: Manual (3 terminals)
# Terminal 1:
cd sentinel_core/interceptor/rust && cargo run --bin sentinel-interceptor

# Terminal 2:
cd sentinel_core/mcp && python -m uvicorn src.mcp_server:app --port 9000

# Terminal 3:
cd sentinel_agent && python examples/conversational_agent.py
```

### Verify

```powershell
.\scripts\verify_services.ps1
```

### Common Commands

```powershell
# Check database
psql -U postgres -d sentinel_interceptor -c "SELECT * FROM customers;"

# Check Redis
& "C:\Program Files\Memurai\redis-cli.exe" KEYS session:*

# Test API
Invoke-RestMethod -Uri "http://localhost:8000/health"

# View logs
# Check Rust interceptor terminal for structured logs
# Check MCP server terminal for request logs
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| PostgreSQL not running | `Start-Service postgresql-x64-15` |
| Redis not running | `Start-Service Memurai` |
| Port 8000 in use | Change `PORT` in `.env` |
| Port 9000 in use | Change MCP server port |
| API key not found | Regenerate hash and update database |
| Tool registry missing | Run `.\scripts\setup_tool_registry.ps1` |

### Service URLs

- Rust Interceptor: http://localhost:8000
- MCP Server: http://localhost:9000
- Health: http://localhost:8000/health
- Metrics: http://localhost:8000/metrics

### Configuration Files

- Rust Interceptor: `sentinel_core/interceptor/rust/.env`
- Python Agent: `sentinel_agent/.env`

### Key Paths

- Private Key: `sentinel_core/interceptor/rust/keys/interceptor_private_key.pem`
- Public Key: `sentinel_core/mcp/keys/interceptor_public_key.pem`
- Tool Registry: `sentinel_core/interceptor/rust/config/tool_registry.yaml`

