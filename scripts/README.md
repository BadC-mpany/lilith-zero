# Sentinel Scripting Environment

This directory contains the operational scripts for the Sentinel system. They are designed to be system-agnostic (Windows/WSL/Linux) and robust against environment variations.

## Prerequisites

Ensure the following dependnecies are installed and accessible in your PATH:

*   **Python 3.10+**: Core language for Agent and MCP.
*   **Rust (Cargo)**: Required for compiling and running the Interceptor.
*   **Docker Desktop**: For hosting Redis (or a local Redis instance).
*   **PostgreSQL**: Database for Sentinel Core.
*   **OpenSSL**: Optional, but recommended (though key generation is now Python-native).

## Quick Start

Follow these steps to initialize and run the full Sentinel stack.

### 1. Generate Secure Keys
Before first run, generate the Ed25519 key pair for secure communication between Interceptor and MCP. This uses a system-agnostic Python script.

```powershell
.\scripts\setup\generate_keys.ps1
```

### 2. Start Backend Services
Starts Redis (Docker), PostgreSQL, Rust Interceptor (Zone B), and MCP Server (Zone C).
*   Validates environment and configuration.
*   Launches services in new terminal windows.
*   Performs health checks before returning.

```powershell
.\scripts\start_all.ps1
```

### 3. Start Conversational Agent
Once services are healthy, launch the user-facing agent.

```powershell
.\scripts\start_agent.ps1
```

---

## Manual Operation

If you need to run components individually for debugging:

### Rust Interceptor (Zone B)
Located in `sentinel_core/interceptor/rust`.
```powershell
# Usage via wrapper (handles paths)
.\scripts\backend\run_interceptor_wrapper.ps1
```

### MCP Server (Zone C)
Located in `sentinel_core/mcp`.
```powershell
# Usage via wrapper (handles venv & paths)
.\scripts\backend\run_mcp_wrapper.ps1
```

---

## Troubleshooting

### Verification
Run the comprehensive health check if services behave unexpectedly.
```powershell
.\scripts\utils\verify_services.ps1
```

### Common Issues
*   **"Invalid Signature"**: Ensure you have run `generate_keys.ps1`. The Interceptor and MCP server must use the matching key pair in `sentinel_core/secrets/`.
*   **"Service Unavailable"**: Check if the Interceptor is running (`http://localhost:8000/health`).
*   **Redis Connection**: Check Docker status. Use `.\scripts\utils\check_redis_availability.ps1`.

## Directory Structure

*   `agent/`: Scripts for the Conversational Agent.
*   `backend/`: Wrappers for Interceptor, MCP, and Redis/Docker management.
*   `setup/`: Database initialization, key generation, and seeding.
*   `utils/`: Shared libraries (`env_utils.ps1`), health checks, and diagnostics.
