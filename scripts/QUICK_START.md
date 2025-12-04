# Sentinel Quick Start Guide

## One-Command Setup

### Start All Services
```powershell
.\scripts\start_all.ps1
```

This will:
- Start PostgreSQL (if not running)
- Start Rust Interceptor (in new window)
- Start MCP Server (in new window)
- Wait for services to be ready (up to 90 seconds)
- Verify all services are running

**Note:** First run of Rust Interceptor may take 30-60 seconds for compilation.

### Start Conversational Agent
```powershell
.\scripts\start_agent.ps1
```

This will:
- Verify services are running
- Start the conversational agent (in new window)

## Manual Commands

If you prefer to start services manually:

### 1. Start Rust Interceptor
```powershell
cd sentinel_core\interceptor\rust
cargo run --bin sentinel-interceptor
```

### 2. Start MCP Server
```powershell
cd sentinel_core\mcp
python -m uvicorn src.mcp_server:app --host 0.0.0.0 --port 9000
```

### 3. Start Conversational Agent
```powershell
cd sentinel_agent
python examples\conversational_agent.py
```

## Service URLs

- **Rust Interceptor:** http://localhost:8000
- **MCP Server:** http://localhost:9000
- **Health Check:** http://localhost:8000/health

## Troubleshooting

### Services Not Starting
1. Check PostgreSQL is running: `Get-Service postgresql*`
2. Check Redis is running: `wsl redis-cli ping`
3. Verify ports are not in use: `netstat -an | findstr "8000 9000"`

### Verification Fails
- Services may need more time to start (especially Rust compilation)
- Check the service windows for error messages
- Run `.\scripts\verify_services.ps1` manually

### Agent Won't Start
- Ensure services are running first: `.\scripts\start_all.ps1`
- Check `.env` file exists with `OPENROUTER_API_KEY` set
- Verify `SENTINEL_URL` points to `http://localhost:8000`
