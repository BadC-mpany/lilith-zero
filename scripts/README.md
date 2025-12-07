# Sentinel Scripts

This directory contains all executable scripts for running Sentinel services.

## Workflow

### Prerequisites

- PostgreSQL 15+ service running
- Docker Desktop (Docker mode) OR WSL2 with Redis (WSL mode)
- Rust toolchain (`cargo` in PATH)
- Python 3.9+ with `sentinel_env` virtual environment
- Ed25519 keys: `sentinel_core/interceptor/rust/keys/interceptor_private_key.pem`
- Database schema: `scripts/setup_database_tables.sql` executed
- API key hash in database matching `SENTINEL_API_KEY` in `sentinel_agent/.env`

### Configuration

Set `REDIS_MODE` in `sentinel_core/interceptor/rust/.env`:

- `docker` (default) - Uses `docker-compose.local.yml`
- `wsl` - Requires WSL Redis + port forwarding
- `auto` - Docker first, WSL fallback

### Automated Startup

```powershell
# Start all services (PostgreSQL, Redis, Interceptor, MCP)
.\scripts\start_all.ps1

# Start agent (separate terminal)
.\scripts\start_agent.ps1
```

`start_all.ps1` handles:

- Redis mode detection (`REDIS_MODE` env var)
- Docker Redis startup (if `docker` or `auto`)
- WSL health check + port forwarding (if `wsl`)
- Service verification with progressive readiness checks

### Manual Startup: Docker Mode

```powershell
# Terminal 1: Redis
.\scripts\start_redis_docker.ps1

# Terminal 2: Interceptor
cd sentinel_core\interceptor\rust
cargo run --bin sentinel-interceptor

# Terminal 3: MCP Server
cd sentinel_core\mcp
python -m uvicorn src.mcp_server:app --host 0.0.0.0 --port 9000

# Terminal 4: Agent
cd sentinel_agent
python examples\conversational_agent.py
```

### Manual Startup: WSL Mode

```powershell
# Set mode (or in .env: REDIS_MODE=wsl)
$env:REDIS_MODE = "wsl"

# Terminal 1: WSL Redis + port forwarding
wsl redis-server --daemonize yes
.\scripts\fix_wsl_redis_connection.ps1

# Terminal 2: Interceptor
cd sentinel_core\interceptor\rust
cargo run --bin sentinel-interceptor

# Terminal 3: MCP Server
cd sentinel_core\mcp
python -m uvicorn src.mcp_server:app --host 0.0.0.0 --port 9000

# Terminal 4: Agent
cd sentinel_agent
python examples\conversational_agent.py
```

### Verification

```powershell
# Full service check
.\scripts\verify_services.ps1

# Redis mode detection
.\scripts\check_redis_mode.ps1

# Individual health checks
Invoke-WebRequest http://localhost:8000/health  # Interceptor
Invoke-WebRequest http://localhost:9000/health   # MCP
```

### Service Endpoints

| Service          | Endpoint                | Health Check                                      |
| ---------------- | ----------------------- | ------------------------------------------------- |
| Rust Interceptor | `http://localhost:8000` | `GET /health`                                     |
| MCP Server       | `http://localhost:9000` | `GET /health`                                     |
| PostgreSQL       | `localhost:5432`        | `psql -U postgres -c "SELECT 1"`                  |
| Redis (Docker)   | `localhost:6379`        | `docker exec sentinel-redis-local redis-cli ping` |
| Redis (WSL)      | WSL IP:6379             | `wsl redis-cli ping`                              |

## Service Dependencies

```
PostgreSQL (Windows Service)
    ↓
Redis (Docker/WSL) ← Rust Interceptor ← Agent
    ↓                    ↓
    └─────────→ MCP Server
```

**Startup order:**

1. PostgreSQL (Windows service, auto-started)
2. Redis (Docker container or WSL daemon)
3. Rust Interceptor (compiles on first run, ~30-60s)
4. MCP Server (Python FastAPI, ~2s)
5. Agent (Python CLI, connects to Interceptor)

## Scripts

### Docker Redis Scripts

#### `start_redis_docker.ps1`

Starts Redis using Docker Compose.

- Checks if Docker is running
- Starts Redis container via `docker-compose.local.yml`
- Waits for health check
- Verifies connection with `redis-cli ping`

**Usage:**

```powershell
.\scripts\start_redis_docker.ps1
```

**Prerequisites:**

- Docker Desktop installed and running
- `docker-compose.local.yml` file exists in project root

#### `stop_redis_docker.ps1`

Stops the Docker Redis container.

**Usage:**

```powershell
.\scripts\stop_redis_docker.ps1
```

#### `check_redis_mode.ps1`

Detects and reports current Redis mode and availability.

- Checks `REDIS_MODE` environment variable
- Checks Docker container status
- Checks WSL Redis status
- Reports recommended mode

**Usage:**

```powershell
.\scripts\check_redis_mode.ps1
```

### Redis Mode Coexistence

**Important:** WSL Redis and Docker Redis can run simultaneously without conflicts. The `REDIS_MODE` environment variable determines which Redis instance the interceptor uses, not which Redis instances are running.

**How it works:**

- **Docker Redis** runs on `localhost:6379` (Windows host)
- **WSL Redis** runs on WSL IP address (e.g., `172.x.x.x:6379`) with port forwarding to `localhost:6379`
- The interceptor connects to the Redis specified by `REDIS_MODE`:
  - `docker`: Connects to Docker Redis on `localhost:6379`
  - `wsl`: Connects to WSL Redis (via WSL IP or port forwarding)
  - `auto`: Tries Docker first, falls back to WSL if Docker unavailable

**Troubleshooting:**

- If Docker Redis fails, you can manually switch to WSL by setting `REDIS_MODE=wsl` in `.env` and restarting the interceptor
- Both Redis instances can be running - only the one specified by `REDIS_MODE` will be used
- The `check_redis_mode.ps1` script shows status of both instances for reference

### WSL Redis Scripts

#### `start_redis.sh`

Starts the Redis server required by Sentinel services (WSL mode).

- Checks if Redis is already running
- Provides installation instructions if Redis is not found
- Works on Windows (WSL/Git Bash), macOS, and Linux

**Usage:**

**Windows (PowerShell):**

```powershell
bash scripts/start_redis.sh
# OR use PowerShell wrapper:
.\scripts\start_redis.ps1
```

**Windows (Git Bash) / macOS / Linux:**

```bash
./scripts/start_redis.sh
```

### `start_interceptor.sh`

Starts the Sentinel Interceptor service (Zone B - Policy Enforcement Point).

- Automatically detects Python virtual environment
- Sets up PYTHONPATH and environment variables
- Handles cross-platform path conversion (Windows/Unix)
- Runs on `http://localhost:8000`

**Usage:**

**Windows (PowerShell):**

```powershell
# Make sure virtual environment is activated first
.\sentinel_env\Scripts\Activate.ps1
bash scripts/start_interceptor.sh
# OR use PowerShell wrapper:
.\scripts\start_interceptor.ps1
```

**Windows (Git Bash) / macOS / Linux:**

```bash
# Make sure virtual environment is activated first
source sentinel_env/bin/activate  # or: . sentinel_env/bin/activate
./scripts/start_interceptor.sh
```

**Prerequisites:**

- Virtual environment activated (or `sentinel_env` directory exists)
- Redis running
- Cryptographic keys generated (`sentinel_core/secrets/interceptor_private.pem`)

### `start_mcp.sh`

Starts the Sentinel MCP Server (Zone C - Secure Execution Environment).

- Automatically detects Python virtual environment
- Sets up PYTHONPATH and environment variables
- Handles cross-platform path conversion (Windows/Unix)
- Runs on `http://localhost:9000`

**Usage:**

**Windows (PowerShell):**

```powershell
# Make sure virtual environment is activated first
.\sentinel_env\Scripts\Activate.ps1
bash scripts/start_mcp.sh
# OR use PowerShell wrapper:
.\scripts\start_mcp.ps1
```

**Windows (Git Bash) / macOS / Linux:**

```bash
# Make sure virtual environment is activated first
source sentinel_env/bin/activate  # or: . sentinel_env/bin/activate
./scripts/start_mcp.sh
```

**Prerequisites:**

- Virtual environment activated (or `sentinel_env` directory exists)
- Redis running
- Cryptographic keys generated (`sentinel_core/secrets/mcp_public.pem`)

## Wrapper Scripts

### `run_interceptor.py`

Python wrapper script for `interceptor_service.py`.

- Sets up `sys.path` for module imports
- Configures environment variables
- Handles path normalization for cross-platform compatibility
- Called automatically by `start_interceptor.sh`

### `run_mcp.py`

Python wrapper script for `mcp_server.py`.

- Sets up `sys.path` for module imports
- Configures environment variables
- Handles path normalization for cross-platform compatibility
- Called automatically by `start_mcp.sh`

## Cross-Platform Support

All scripts are designed to work on:

- **Windows**: Git Bash, WSL, PowerShell
- **macOS**: Terminal, zsh, bash
- **Linux**: bash, sh

The scripts automatically detect the operating system and Python environment, converting paths as needed for Windows Python executables.

## Environment Variables

The scripts set the following environment variables (can be overridden):

### Redis Configuration

- `REDIS_MODE`: Redis deployment mode - `docker` (default), `wsl`, or `auto`
- `REDIS_URL`: Redis connection URL (default: `redis://localhost:6379/0`)
- `REDIS_HOST`: Redis server hostname (default: `localhost`) - legacy, use `REDIS_URL`
- `REDIS_PORT`: Redis server port (default: `6379`) - legacy, use `REDIS_URL`
- `REDIS_DB`: Redis database number (default: `0` for Interceptor, `1` for MCP) - legacy, use `REDIS_URL`

### Redis Pool Configuration (Docker-optimized defaults)

- `REDIS_POOL_MAX_SIZE`: Maximum pool size (default: `10`)
- `REDIS_POOL_MIN_IDLE`: Minimum idle connections (default: `0` for Docker, `2` for WSL)
- `REDIS_CONNECTION_TIMEOUT_SECS`: Connection timeout (default: `5` for Docker, `15` for WSL)
- `REDIS_OPERATION_TIMEOUT_SECS`: Operation timeout (default: `2` for Docker, `5` for WSL)
- `REDIS_POOL_MAX_LIFETIME_SECS`: Connection max lifetime (default: `1800` for Docker, `300` for WSL)
- `REDIS_POOL_IDLE_TIMEOUT_SECS`: Idle timeout (default: `300` for Docker, `60` for WSL)

### Other Configuration

- `SENTINEL_SCRIPT_DIR`: Project root directory
- `INTERCEPTOR_PRIVATE_KEY_PATH`: Path to interceptor private key
- `MCP_PUBLIC_KEY_PATH`: Path to MCP public key
- `POLICIES_YAML_PATH`: Path to policies configuration file
- `TOOL_REGISTRY_PATH`: Path to tool registry YAML file

## Troubleshooting

### Redis Connection Issues

**Docker Mode:**

```powershell
# Check Docker is running
docker ps

# Check Redis container
docker ps --filter name=sentinel-redis-local

# View Redis logs
docker logs sentinel-redis-local

# Restart Redis
.\scripts\stop_redis_docker.ps1
.\scripts\start_redis_docker.ps1
```

**WSL Mode:**

```powershell
# Check WSL Redis
wsl redis-cli ping

# Check port forwarding
netsh interface portproxy show all

# Fix port forwarding
.\scripts\fix_wsl_redis_connection.ps1

# Restart WSL Redis
wsl redis-cli shutdown
wsl redis-server --daemonize yes
```

### Interceptor Startup Issues

- **Compilation errors**: Check Rust toolchain (`rustc --version`)
- **Redis connection timeout**: Verify Redis is running and `REDIS_MODE` matches
- **Database connection failed**: Check PostgreSQL service and `DATABASE_URL` in `.env`
- **Key file not found**: Run `.\scripts\generate_keys.ps1`

### MCP Server Issues

- **Module not found**: Activate virtual environment (`.\sentinel_env\Scripts\Activate.ps1`)
- **Port 9000 in use**: Check for existing MCP server process
- **Public key not found**: Copy from `sentinel_core/interceptor/rust/keys/interceptor_public_key.pem` to `sentinel_core/mcp/keys/`

## Migration from WSL to Docker

1. Set `REDIS_MODE=docker` in `sentinel_core/interceptor/rust/.env`
2. Start Docker Desktop
3. Run `.\scripts\start_redis_docker.ps1`
4. Verify: `.\scripts\check_redis_mode.ps1`
5. Restart interceptor - it will use Docker Redis automatically

To revert to WSL: Set `REDIS_MODE=wsl` in `.env` and restart services.
