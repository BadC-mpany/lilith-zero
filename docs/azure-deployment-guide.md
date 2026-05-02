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

---

## 4. Deployment Workflow (The Working Recipe)

### Phase 1: Docker Prep
Avoid "Disk Quota" issues by using a `.dockerignore` to exclude the massive Rust `target/` directory, including only the release binary.

```dockerfile
# Minimal Dockerfile
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y ca-certificates
WORKDIR /app
COPY lilith-zero/target/release/lilith-zero /app/lilith-zero
COPY examples/copilot_studio/copilot_studio_policy.yaml /app/policy.yaml
RUN chmod +x /app/lilith-zero
CMD ["/app/lilith-zero", "serve", "--bind", "0.0.0.0:8080", "--auth-mode", "none", "--policy", "/app/policy.yaml"]
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

## 5. Final Power Platform Configuration

In **Power Platform Admin Center** > **Security** > **Threat detection**:

1. **App ID:** Your Entra App Client ID.
2. **Endpoint URL:** `https://lilith-zero.badcompany.xyz` (Your custom domain).
3. **Handshake:** On "Save", Power Platform calls `GET /validate`. Lilith must return:
   ```json
   {"isSuccessful": true, "status": "OK"}
   ```

## 6. Maintenance & Scaling
- **Persistence:** Lilith stores taints in `/home/.lilith/sessions`. In Azure App Service Linux, the `/home` directory is persistent across restarts.
- **Port:** Ensure `WEBSITES_PORT=8080` (or your app's port) is set in App Settings.
- **Logs:** Use `az webapp log tail` for real-time debugging of policy evaluations.

## 7. Multi-Tenant Edge Routing
Lilith Zero handles multi-tenancy at the webhook edge rather than inside the core engine.
- Configure `--policy` to point to a directory of `.cedar` files.
- Name each file with the convention `policy_<agent_id>.cedar` (e.g., `policy_77236ced-1146-f111-bec6-7ced8d71fac9.cedar`).
- The webhook automatically parses the `agent.id` from the Copilot Studio `AnalyzeToolExecutionRequest` payload and routes the evaluation to the matching isolated policy.
