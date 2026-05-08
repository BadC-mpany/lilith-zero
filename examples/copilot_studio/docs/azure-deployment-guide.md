# Lilith Zero: Azure & Power Platform Deployment Guide

This document serves as the technical "Source of Truth" for deploying Lilith Zero as a real-time security webhook for Microsoft Power Platform (Copilot Studio). It documents the architecture, the "walls" encountered during the initial deployment, and the final working configuration.

## 1. The Core Objective
Deploy a deterministic, sub-millisecond security middleware (Lilith Zero) to intercept and evaluate autonomous agent actions in Microsoft Copilot Studio via the **Threat Detection Webhook** interface.

---

## 2. Infrastructure Architecture

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Hosting** | Azure App Service (Linux) | Stateless/Stateful compute for the webhook server. |
| **Registry** | Azure Container Registry (ACR) | Hosting the Lilith Docker image. |
| **Identity** | Microsoft Entra ID | Handling OAuth2/OIDC and Federated Identity. |
| **Domain** | Namecheap (Custom DNS) | Bypassing Entra's "Unverified Domain" restrictions. |
| **Persistence** | App Service `/home` | Local JSON-based session state (taint tracking). |

---

## 3. The "Walls" & Technical Gotchas

### A. The "Unverified Domain" Restriction (Entra ID)
**Problem:** Entra ID requires that any URL used as an `Identifier URI` (Audience) for security tokens must be on a domain verified in the tenant.
- **Failed Attempt:** Using `ngrok-free.dev` or `azurewebsites.net`.
- **The Solution:** Use a custom domain you own (e.g., `badcompany.xyz`). Verify the root domain in Entra ID, then use a subdomain (`lilith-zero.badcompany.xyz`) for the App Service.

### B. GLIBC Version Mismatch
**Problem:** The Lilith binary was built on a modern host (Fedora/Debian testing) with `GLIBC 2.39+`. The default `debian:bookworm-slim` Docker image uses `GLIBC 2.36`.
- **Error:** `/app/lilith-zero: /lib/x86_64-linux-gnu/libc.so.6: version 'GLIBC_2.39' not found`.
- **The Solution:** Use `ubuntu:24.04` as the base image for the Dockerfile, which supports the newer GLIBC requirements.

### C. The Power Platform "Subject" Assertion
**Problem:** Power Platform uses Workload Identity Federation (FIC). The "Subject" of the token request must **exactly** match the record in Entra ID.
- **The Catch:** Power Platform constructs the subject using a base64url encoding of the *Endpoint URL*. It typically strips the trailing slash and does NOT include sub-paths like `/validate` in the subject if you configured the base URL.
- **Correct Subject Format:** `/eid1/c/pub/t/<TenantId_B64>/a/<AppId_B64>/<EndpointURL_B64>`

### D. Tool ID Mismatch (Slugification)
**Problem:** Custom tools (e.g., 'Send-an-Email') were blocked because the auto-generated Cedar policies did not include the specific, slugified `toolDefinition.id` used in the runtime payload.
- **The Discovery:** Copilot Studio generates tool IDs using the format `<prefix>.action.<slugified_name>`. The `name` field in the payload is often just a human-readable display string, not the identifier matched by the runtime.
- **The Solution:** Use `toolDefinition.id` as the primary identifier for policy evaluation. Update `extract_tools.py` to robustly derive these IDs from the bot template by extracting the publisher prefix and applying the correct slugification logic.

---

## 4. Deployment Workflow (The Working Recipe)

### Phase 1: Docker Prep
Avoid "Disk Quota" issues by using a `.dockerignore` to exclude the massive Rust `target/` directory.

**Build Command:**
Always build with the `webhook` feature enabled:
```bash
cd lilith-zero && cargo build --release --features webhook
```

**Dockerfile:**
```dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y ca-certificates
WORKDIR /app
COPY lilith-zero/target/release/lilith-zero /app/lilith-zero
# Pointing to a directory enables multi-tenant routing
COPY examples/copilot_studio/policies /app/policies
RUN chmod +x /app/lilith-zero && mkdir -p /home/.lilith/sessions /home/LogFiles
ENV PORT=8080
ENV RUST_LOG=info
# CRITICAL: point session storage at /home — Azure App Service mounts /home as
# persistent Azure Files. Without this the app writes to /root/.lilith/sessions
# (ephemeral container storage) and all taint state is lost on every cold start.
ENV LILITH_ZERO_SESSION_STORAGE_DIR=/home/.lilith/sessions
CMD ["/app/lilith-zero", "serve", "--bind", "0.0.0.0:8080", "--auth-mode", "none", "--policy", "/app/policies"]
```

### Phase 2: Azure CLI Setup
1. **Managed Identity:** Don't use passwords for ACR. Grant the App Service's Managed Identity the `AcrPull` role on your ACR.
2. **Custom Domain Binding:**
   - Add a CNAME in DNS pointing to `your-app.azurewebsites.net`.
   - Add a TXT record `asuid.<subdomain>` for Azure ownership verification.
   - Run `az webapp config hostname add`.
3. **SSL Certificate:** Create a Free Managed Certificate via `az webapp config ssl create` and **bind it** with SNI. Power Platform requires valid HTTPS.

### Phase 3: Federated Identity Credential (FIC)
Update the FIC in your Entra App Registration:
```bash
# Calculate the subject by base64url encoding your custom domain URL
# (No trailing slash, no /validate subpath)
SUBJECT="/eid1/c/pub/t/<TENANT_B64>/a/<APP_ID_B64>/<URL_B64>"
```

---

## 5. Tool Extraction & Policy Generation (Robustness)

Copilot Studio tool definitions are extracted from bot templates. The `extract_tools.py` script ensures robust matching by:
1. **Filtering for `TaskDialog`**: Only extracting actual external actions/connectors, ignoring internal system topics (Greeting, Goodbye, etc.).
2. **Multi-Alias Generation**: Automatically creating permits for `modelDisplayName`, `operationId`, and "slugified" names (e.g., `Create-table` vs `Create table`) to ensure the policy always matches the webhook payload.

Run extraction before building the image:
```bash
python3 examples/copilot_studio/extract_tools.py --environment <ENV_ID>
```

---

## 8. Policy Updates and Hot Reload

### Initial Setup: Enable Hot Reload

Set the admin token once in Azure App Settings (required to use `/admin/reload-policies`):

```bash
az webapp config appsettings set \
  --name lilith-zero-webhook \
  --resource-group lilith-zero-rg \
  --settings LILITH_ZERO_ADMIN_TOKEN="$(openssl rand -hex 32)"
```

Store the token value — you need it to call the reload endpoint. Get the token from the Azure App Setting LILITH_ZERO_ADMIN_TOKEN.

Also configure the policy directory to use Azure Files (survives restarts, no rebuild needed):

```bash
az webapp config appsettings set \
  --name lilith-zero-webhook \
  --resource-group lilith-zero-rg \
  --settings LILITH_ZERO_POLICY_DIR=/home/policies
```

### Fast Path: Policy-Only Update (No Docker rebuild, ~5 seconds)

When only policy files change:

```bash
# 1. Extract tools and generate Cedar policies
python3 examples/copilot_studio/extract_tools.py --environment <ENV_ID>

# 2. Copy new policy files to Azure Files (persistent /home mount)
az webapp ssh --name lilith-zero-webhook --resource-group lilith-zero-rg \
  --command "mkdir -p /home/policies"
# Upload via az storage or SCP depending on your setup:
az storage file upload \
  --account-name <STORAGE_ACCOUNT> \
  --share-name <FILE_SHARE> \
  --source examples/copilot_studio/policies/policy_<AGENT_ID>.cedar \
  --path policies/policy_<AGENT_ID>.cedar

# 3. Trigger in-memory reload (zero downtime, ~5-20ms)
curl -X POST https://lilith-zero.badcompany.xyz/admin/reload-policies \
  -H "X-Admin-Token: $LILITH_ZERO_ADMIN_TOKEN"
# Response: {"reloaded":2,"elapsed_ms":8,"has_legacy":false}
```

**Result**: New policy is active immediately. No restart, no dropped requests.

### Full Rebuild: Binary or Config Changes

Only needed when the Rust source changes (not for policy updates):

```bash
# 1. Rebuild the Rust core with webhook features
cd lilith-zero && cargo build --release --features webhook && cd ..

# 2. Build and Login to ACR
docker build -t lilithzerocr.azurecr.io/lilith-zero:latest .
az acr login --name lilithzerocr

# 3. Push to ACR
docker push lilithzerocr.azurecr.io/lilith-zero:latest

# 4. Restart Azure Web App
az webapp restart --name lilith-zero-webhook --resource-group lilith-zero-rg
```

### Optional: Automatic Policy Refresh

To pick up file changes automatically on a timer (no manual reload needed):

```bash
az webapp config appsettings set \
  --name lilith-zero-webhook \
  --resource-group lilith-zero-rg \
  --settings LILITH_ZERO_POLICY_REFRESH_SECS=3600   # refresh every hour
```

### Admin Endpoints Reference

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/admin/reload-policies` | POST | `X-Admin-Token` | Atomically reload all policy files from disk |
| `/admin/status` | GET | `X-Admin-Token` | Policy count, last reload time, elapsed ms |

**Security**: Admin endpoints return HTTP 403 when `LILITH_ZERO_ADMIN_TOKEN` is not set.
The header `X-Admin-Token` is separate from the Copilot Studio Bearer token.

### Optional: Lazy Loading

When many agents share one deployment but only a subset are active:

```bash
az webapp config appsettings set \
  --name lilith-zero-webhook \
  --resource-group lilith-zero-rg \
  --settings LILITH_ZERO_POLICY_LAZY_LOAD=true
```

With lazy loading, unknown agent IDs trigger a disk read on first access. Subsequent requests use the cached in-memory copy.

---

## 9. Persistence & Scaling

### Session storage

Taint state is persisted to `LILITH_ZERO_SESSION_STORAGE_DIR` (default `/home/.lilith/sessions` — set by the Dockerfile). In Azure App Service Linux, `/home` is mounted as persistent Azure Files and survives container restarts. **Do not change this to any path outside `/home`** — other paths are ephemeral and taint state will reset on every cold start (`alwaysOn=false` means cold starts happen after idle periods).

The App Service setting `WEBSITES_ENABLE_APP_SERVICE_STORAGE=true` must be set (it is by default; only disable it if you deliberately want ephemeral storage).

Session files are named `{conversation_id}.json` and cleaned up at server startup when older than `LILITH_ZERO_SESSION_TTL_SECS` (default 86400 = 24 h).

### How policy and taint loading works per request

| What | Keyed by | Loaded |
|------|----------|--------|
| Cedar policy (`*.cedar`) | `agent_id` (filename) | Once at startup |
| Session state (taints) | `conversation_id` | Per request from disk |

Taints are append-only within a session. Nothing removes a taint once set unless an explicit `remove_taint:` Cedar rule fires.

### Required App Service settings

| Setting | Value | Why |
|---------|-------|-----|
| `WEBSITES_PORT` | `8080` | Routes traffic to the container port |
| `WEBSITES_ENABLE_APP_SERVICE_STORAGE` | `true` | Mounts `/home` as persistent storage |
| `LILITH_ZERO_SESSION_STORAGE_DIR` | `/home/.lilith/sessions` | Belt-and-suspenders over Dockerfile ENV |
| `RUST_LOG` | `info` (or `debug` for diagnostics) | Controls log verbosity |

### Debugging taint persistence

To verify sessions are being written to Azure, SSH into the container:

```bash
az webapp ssh --name lilith-zero-webhook --resource-group lilith-zero-rg
ls -la /home/.lilith/sessions/
cat /home/.lilith/sessions/<conversation_id>.json
```

To verify a specific session has the expected taints, check the `taints` array in the JSON. If the directory is empty or missing, check that `LILITH_ZERO_SESSION_STORAGE_DIR` is set correctly and the container has write permission.

### Port Mapping
Ensure the App Setting `WEBSITES_PORT=8080` is set so Azure correctly routes traffic to the container.

### Structured Logs
By default, logs show clean one-line entries for each tool call. Set `LILITH_ZERO_WEBHOOK_DEBUG=true` to see raw payloads.

### Real-time Monitoring
```bash
az webapp log tail --name <APP_NAME> --resource-group <RG_NAME>
```
> [!TIP]
> If the logs repeat the same entries, Azure is showing the recent buffer. Trigger a new tool call to push the buffer forward.






### Build and push to Azure
cd lilith-zero && cargo build --release --features webhook && cd ..
docker build -t lilithzerocr.azurecr.io/lilith-zero:latest .    
az acr login --name lilithzerocr                                                                                                                                       
docker push lilithzerocr.azurecr.io/lilith-zero:latest       
az webapp config appsettings set --name lilith-zero-webhook --resource-group lilith-zero-rg --settings LILITH_ZERO_ADMIN_TOKEN="$ADMIN_TOKEN"                          

### Trigger reload (should return {"reloaded":N,"elapsed_ms":M,...})                                                                                                  
curl -X POST https://lilith-zero.badcompany.xyz/admin/reload-policies -H "X-Admin-Token: $ADMIN_TOKEN"
### Check status                                                                                                                                                      
curl https://lilith-zero.badcompany.xyz/admin/status -H "X-Admin-Token: $ADMIN_TOKEN"