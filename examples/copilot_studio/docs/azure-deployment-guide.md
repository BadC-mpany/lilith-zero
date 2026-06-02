# Lilith Zero: Azure & Power Platform Deployment Guide

This document serves as the technical source of truth for deploying Lilith Zero as a real-time security webhook for Microsoft Power Platform (Copilot Studio). It documents the setup steps, API testing commands, and technical resolutions for advanced Entra ID and Power Platform gotchas.

---

## 1. Pre-Flight Exploration & Discovery
Before deploying to any subscription (especially a guest environment or a colleague's workspace), run these commands to understand the existing topology:

```bash
# 1. Check current logged-in identity and default subscription
az account show --output json

# 2. List all accessible subscriptions
az account list --output table

# 3. List existing resource groups in the selected subscription
az group list --output table

# 4. List existing Web Apps to check for name conflicts
az webapp list --query "[].{name:name, resourceGroup:resourceGroup}" --output table

# 5. List existing Container Registries
az acr list --query "[].{name:name, resourceGroup:resourceGroup, loginServer:loginServer}" --output table
```

---

## 2. Technical Gotchas & Solutions (The "Walls")

### Gotcha A: B1 Linux App Service Capacity Issues
* **Problem**: Attempting to create a B1 SKU Linux App Service Plan in highly saturated regions (like `eastus`) can fail with a *"No available instances"* capacity error.
* **Solution**: Create the App Service Plan in an adjacent region with separate capacity pools (e.g. `eastus2`) inside the same resource group. Resource groups can contain resources located in different regions.

### Gotcha B: Contributor Permissions vs. Managed Identity
* **Problem**: If you have `Contributor` access but not `Owner` or `User Access Administrator` permissions, you cannot create Role Assignments. Granting the Web App's Managed Identity the `AcrPull` role on the Container Registry will fail.
* **Solution**: Enable admin credentials on the registry and configure the Web App to use them:
  ```bash
  az acr update --name <registry_name> --admin-enabled true
  ```

### Gotcha C: Multitenant App Registrations & Service Principals (AADSTS7000229)
* **Problem**: If your App Registration is created in Tenant A, but the Power Platform environment calling it is in Tenant B, Entra ID requires a Service Principal instance to exist in Tenant B. If missing, it throws `AADSTS7000229`.
* **Solution**: Since `adminconsent` URLs fail on clean App Registrations (due to empty API permissions), trigger a basic user-consent flow using a browser to instantiate the service principal in Tenant B:
  ```
  https://login.microsoftonline.com/{tenant_b_id}/oauth2/v2.0/authorize?client_id={app_id}&response_type=code&redirect_uri={redirect_uri}&response_mode=query&scope=openid
  ```

### Gotcha D: B2B Guest Admin Limits in Power Platform
* **Problem**: B2B Guest Users cannot switch tenant directory contexts in the Power Platform Admin Center. You will only see environments from your home tenant.
* **Solution**: If the target environment is in your colleague's tenant, either the native tenant admin must save the settings, or you must update the Federated Identity Credential to trust your home tenant and run the Copilot agent there.

### Gotcha E: Federated Subject Mismatch (AADSTS7002137)
* **Problem**: Power Platform constructs the assertion subject using the exact URL typed in the UI (e.g. `https://lilith-zero.badcompany.xyz`). It does not include trailing slashes or subpaths like `/validate`.
* **Subject Structure**: `/eid1/c/pub/t/{tenant_id_b64}/a/{copilot_app_id_b64}/{endpoint_url_b64}`
* **Copilot App ID**: The globally static Microsoft App ID for Copilot Studio token exchange is `9d8f559b-5984-46a4-902a-ad4271e83efa`.

---

## 3. Step-by-Step Deployment Recipe

### 1. Compile the Binary Locally
Build the Rust binary with webhook support enabled:
```bash
cd lilith-zero
cargo build --release --features webhook
cd ..
```

### 2. Build and Push the Container
To prevent Docker from scanning the huge compilation `target/` directory (which can exceed 20GB and freeze the CLI), copy the binary to a root path and exclude `target/` in `.dockerignore`:
```bash
# Copy binary out
cp lilith-zero/target/release/lilith-zero ./lilith-zero-bin

# Build on Azure Container Registry
az acr build --registry "lilithzeromzcr" --image "lilith-zero:latest" --file Dockerfile .

# Clean up
rm -f ./lilith-zero-bin
```

### 3. Web App Creation
Create the Web App and configure it to pull from the registry using registry credentials:
```bash
# Get the registry password
ACR_PASSWORD=$(az acr credential show --name "lilithzeromzcr" --query "passwords[0].value" -o tsv)

# Create the Web App
az webapp create \
    --resource-group "BadCompany" \
    --plan "lilith-zero-plan-new" \
    --name "lilith-zero-webhook-mz" \
    --deployment-container-image-name "lilithzeromzcr.azurecr.io/lilith-zero:latest" \
    --docker-registry-server-url "https://lilithzeromzcr.azurecr.io" \
    --docker-registry-server-user "lilithzeromzcr" \
    --docker-registry-server-password "$ACR_PASSWORD" \
    --startup-file "/app/lilith-zero serve --bind 0.0.0.0:8080 --auth-mode entra"
```

### 4. Configure Environment Settings
```bash
az webapp config appsettings set \
    --name "lilith-zero-webhook-mz" \
    --resource-group "BadCompany" \
    --settings \
        RUST_LOG=info \
        WEBSITES_ENABLE_APP_SERVICE_STORAGE=true \
        WEBSITES_PORT=8080 \
        LILITH_ZERO_ENTRA_TENANT_ID="98e2f7d2-c1d3-4410-b87f-2396f157975f" \
        LILITH_ZERO_ENTRA_AUDIENCE="api://02280932-064c-459e-86d6-0dcfe07bd99f" \
        POLICIES_YAML_PATH="/app/policies"
```

### 5. Custom Domain and SSL Binding
1. Add CNAME record pointing `lilith-zero` to `lilith-zero-webhook-mz.azurewebsites.net`.
2. Add TXT record `asuid.lilith-zero` pointing to the Web App's `customDomainVerificationId`.
3. Bind the domain and SSL:
   ```bash
   # Add Domain
   az webapp config hostname add \
       --webapp-name "lilith-zero-webhook-mz" \
       --resource-group "BadCompany" \
       --hostname "lilith-zero.badcompany.xyz"

   # Create and Bind SSL Certificate
   az webapp config ssl create \
       --resource-group "BadCompany" \
       --name "lilith-zero-webhook-mz" \
       --hostname "lilith-zero.badcompany.xyz"
   
   # Retrieve certificate thumbprint and bind
   THUMBPRINT=$(az webapp config ssl show -g "BadCompany" --certificate-name "lilith-zero.badcompany.xyz" --query "thumbprint" -o tsv)
   az webapp config ssl bind \
       --resource-group "BadCompany" \
       --name "lilith-zero-webhook-mz" \
       --certificate-thumbprint "$THUMBPRINT" \
       --ssl-type SNI
   ```

---

## 4. Troubleshooting and Testing Commands

### Testing Webhook Validation (Bypassing Local DNS Cache)
If you recently updated DNS records but local caches haven't propagated, force curl to use the Web App's new IP address to verify status:
```bash
# Verify new Web App is responding (bypassing DNS cache)
curl -X POST https://lilith-zero.badcompany.xyz/validate \
  --resolve lilith-zero.badcompany.xyz:443:20.119.144.24 \
  -H "Content-Type: application/json" \
  -d '{}'

# Response should be:
# {"isSuccessful":true,"status":"OK"}
```

### Querying Logs and Active Container Status
```bash
# Get live logs
az webapp log tail --name "lilith-zero-webhook-mz" --resource-group "BadCompany"

# Restart the application to reload container/settings
az webapp restart --name "lilith-zero-webhook-mz" --resource-group "BadCompany"
```