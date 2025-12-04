# How to Run Everything

## Quick Start (2 Commands)

### 1. Start All Services
```powershell
.\scripts\start_all.ps1
```

This will:
- Check WSL health (auto-recover if needed)
- Start PostgreSQL
- Start Rust Interceptor (in new window)
- Start MCP Server (in new window)
- Wait for services to be ready (up to 90 seconds)
- Verify all services are running

**Note:** First run may take 30-60 seconds for Rust compilation.

### 2. Start Conversational Agent
```powershell
.\scripts\start_agent.ps1
```

This will:
- Verify services are running
- Start the conversational agent (in new window)

## What Each Service Does

- **PostgreSQL**: Stores API keys, policies, and audit logs
- **Redis (WSL)**: Stores session state (taints, history)
- **Rust Interceptor** (port 8000): Main security proxy, handles authentication and policy enforcement
- **MCP Server** (port 9000): Executes tools securely
- **Conversational Agent**: Python agent that uses the interceptor

## Service URLs

- **Rust Interceptor:** http://localhost:8000
- **MCP Server:** http://localhost:9000
- **Health Check:** http://localhost:8000/health

## Troubleshooting

### Services Won't Start
1. Check WSL: `.\scripts\wsl_health_check.ps1`
2. Check Redis: `wsl redis-cli ping`
3. Check port forwarding: `netsh interface portproxy show all`

### WSL Resource Issues
Run once to configure permanently:
```powershell
.\scripts\configure_wsl_resources.ps1
```

This limits WSL to 3GB RAM and prevents resource exhaustion.

### Redis Connection Issues
The interceptor now handles Redis connection failures gracefully:
- Health endpoint reports "disconnected" instead of crashing
- Server continues running even if Redis breaks
- Check logs for connection errors

## Manual Startup (if scripts fail)

### Start Rust Interceptor
```powershell
cd sentinel_core\interceptor\rust
cargo run --bin sentinel-interceptor
```

### Start MCP Server
```powershell
cd sentinel_core\mcp
python -m uvicorn src.mcp_server:app --host 0.0.0.0 --port 9000
```

### Start Agent
```powershell
cd sentinel_agent
python examples\conversational_agent.py
```

