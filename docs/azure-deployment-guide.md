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
RUN chmod +x /app/lilith-zero
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

## 8. Redeployment Workflow (Updating Tools)

When you update tools in Copilot Studio, follow this exact sequence to regenerate policies and update the Azure deployment:

```bash
# 1. Extract tools and generate Cedar policies
# Replace <ENV_ID> with your Power Platform Environment ID
python3 examples/copilot_studio/extract_tools.py --environment <ENV_ID>

# 2. Rebuild the Rust core with webhook features
cd lilith-zero && cargo build --release --features webhook && cd ..

# 3. Build and Login to ACR
docker build -t lilithzerocr.azurecr.io/lilith-zero:latest .
az acr login --name lilithzerocr

# 4. Push to ACR
docker push lilithzerocr.azurecr.io/lilith-zero:latest

# 5. Restart Azure Web App to apply changes
az webapp restart --name lilith-zero-webhook --resource-group lilith-zero-rg
```

---

## 9. Persistence & Scaling

- **State Persistence**: Taint tracking state is stored in `/home/.lilith/sessions`. In Azure App Service Linux, the `/home` directory is persistent across container restarts, ensuring security context is not lost.
- **Port Mapping**: Ensure the App Setting `WEBSITES_PORT=8080` is set so Azure correctly routes traffic to the container.
- **Structured Logs**: By default, logs show clean, one-line entries for each tool call. Set `LILITH_ZERO_WEBHOOK_DEBUG=true` to see raw payloads.
- **Real-time Monitoring**: Use `az webapp log tail --name <APP_NAME> --resource-group <RG_NAME>`.
  > [!TIP]
  > If the logs repeat the same entries, it's because Azure is showing the recent buffer. Trigger a new tool call to push the buffer forward, or use `az webapp log tail --offset 0` to see only new events.
