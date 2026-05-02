#!/usr/bin/env bash
# Lilith Zero — Azure App Service deploy script
# Run from repo root: bash scripts/azure-deploy.sh
set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────
RESOURCE_GROUP="lilith-zero-rg"
LOCATION="westeurope"
APP_SERVICE_PLAN="lilith-zero-plan"
APP_NAME="lilith-zero-webhook"           # → lilith-zero-webhook.azurewebsites.net
REGISTRY_NAME="lilithzerocr"             # Azure Container Registry (must be globally unique)
IMAGE_NAME="lilith-zero"
IMAGE_TAG="latest"
SUBSCRIPTION="278ef486-791b-47a4-b61b-decefe29f308"
TENANT_ID="98e2f7d2-c1d3-4410-b87f-2396f157975f"
APP_ID="b74dfc6e-544a-4ae1-89f7-6597ebf79edc"

echo "=== Lilith Zero Azure Deploy ==="
echo ""

# ── 0. Set subscription ─────────────────────────────────────────────────────
az account set --subscription "$SUBSCRIPTION"
echo "✓ Subscription: $SUBSCRIPTION"

# ── 1. Resource Group ───────────────────────────────────────────────────────
echo ""
echo "Creating resource group $RESOURCE_GROUP in $LOCATION..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
echo "✓ Resource group ready"

# ── 2. Container Registry ───────────────────────────────────────────────────
echo ""
echo "Creating Azure Container Registry $REGISTRY_NAME..."
az acr create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$REGISTRY_NAME" \
    --sku Basic \
    --admin-enabled true \
    --output none
echo "✓ Container registry ready"

# ── 3. Build & push Docker image ─────────────────────────────────────────────
echo ""
echo "Building and pushing Docker image..."
az acr build \
    --registry "$REGISTRY_NAME" \
    --image "${IMAGE_NAME}:${IMAGE_TAG}" \
    --file Dockerfile \
    . 
echo "✓ Image pushed: ${REGISTRY_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}"

# ── 4. App Service Plan (B1 = cheapest with custom domain + SSL) ─────────────
echo ""
echo "Creating App Service Plan (B1)..."
az appservice plan create \
    --name "$APP_SERVICE_PLAN" \
    --resource-group "$RESOURCE_GROUP" \
    --is-linux \
    --sku B1 \
    --output none
echo "✓ App Service Plan ready (B1 Linux)"

# ── 5. Web App ───────────────────────────────────────────────────────────────
echo ""
echo "Creating Web App $APP_NAME..."
ACR_LOGIN_SERVER="${REGISTRY_NAME}.azurecr.io"
ACR_PASSWORD=$(az acr credential show --name "$REGISTRY_NAME" --query "passwords[0].value" -o tsv)

az webapp create \
    --resource-group "$RESOURCE_GROUP" \
    --plan "$APP_SERVICE_PLAN" \
    --name "$APP_NAME" \
    --deployment-container-image-name "${ACR_LOGIN_SERVER}/${IMAGE_NAME}:${IMAGE_TAG}" \
    --docker-registry-server-url "https://${ACR_LOGIN_SERVER}" \
    --docker-registry-server-user "$REGISTRY_NAME" \
    --docker-registry-server-password "$ACR_PASSWORD" \
    --output none
echo "✓ Web app created: https://${APP_NAME}.azurewebsites.net"

# ── 6. App Settings (env vars for the container) ─────────────────────────────
echo ""
echo "Configuring app settings..."
az webapp config appsettings set \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --settings \
        RUST_LOG=info \
        WEBSITES_ENABLE_APP_SERVICE_STORAGE=true \
        WEBSITES_PORT=8080 \
    --output none
echo "✓ App settings configured"

# ── 7. Persistent storage for session taint files ────────────────────────────
# Azure App Service /home is already persistent across restarts for Linux containers.
# The binary writes to /home/.lilith/sessions/ which maps to persistent storage.
echo "✓ Session persistence: /home/.lilith/sessions (Azure persistent /home)"

# ── 8. Custom domain: lilith-zero.badcompany.xyz ─────────────────────────────
echo ""
echo "Adding custom domain lilith-zero.badcompany.xyz..."
echo ""
echo "  ⚠  ACTION REQUIRED IN NAMECHEAP:"
echo "  Change the CNAME for 'lilith-zero' from:"
echo "    lingo-popsicle-bulgur.ngrok-free.dev"
echo "  To:"
echo "    ${APP_NAME}.azurewebsites.net"
echo ""
echo "  After you update it, press ENTER to continue..."
read -r

az webapp config hostname add \
    --webapp-name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --hostname "lilith-zero.badcompany.xyz" \
    --output none
echo "✓ Custom hostname added"

# ── 9. Managed certificate (free SSL for custom domain) ──────────────────────
echo ""
echo "Creating free managed SSL certificate for lilith-zero.badcompany.xyz..."
az webapp config ssl create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$APP_NAME" \
    --hostname "lilith-zero.badcompany.xyz" \
    --output none 2>/dev/null || echo "(cert may take a few minutes to provision — DNS propagation)"
echo "✓ SSL certificate requested"

# ── 10. Update Entra App Identifier URI ──────────────────────────────────────
echo ""
echo "Updating Entra App Identifier URI..."
# The identifier URI stays as https://lilith-zero.badcompany.xyz (already set and verified)
echo "✓ Identifier URI already set: https://lilith-zero.badcompany.xyz"

# ── 11. Update Federated Identity Credential subject ─────────────────────────
echo ""
echo "Updating Federated Identity Credential..."
# The subject must be the base64url of the validate endpoint URL as Power Platform sees it.
# Power Platform encodes: https://lilith-zero.badcompany.xyz/validate
VALIDATE_URL="https://lilith-zero.badcompany.xyz/validate"
B64_URL=$(echo -n "$VALIDATE_URL" | base64 | tr '+/' '-_' | tr -d '=')
NEW_SUBJECT="/eid1/c/pub/t/0vfimNPBEES4fyOW8VeXXw/a/m1WPnYRZpEaQKq1Cceg--g/${B64_URL}"

echo "  New subject: $NEW_SUBJECT"

# Get existing FIC id
FIC_ID=$(az ad app federated-credential list --id "$APP_ID" --query "[0].id" -o tsv)

az ad app federated-credential update \
    --id "$APP_ID" \
    --federated-credential-id "$FIC_ID" \
    --parameters "{
        \"name\": \"LilithZeroFIC\",
        \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
        \"subject\": \"${NEW_SUBJECT}\",
        \"description\": \"Azure App Service deployment\",
        \"audiences\": [\"api://AzureADTokenExchange\"]
    }"
echo "✓ Federated credential updated"

# ── 12. Final status ──────────────────────────────────────────────────────────
echo ""
echo "=== DEPLOY COMPLETE ==="
echo ""
echo "  App URL:       https://${APP_NAME}.azurewebsites.net"
echo "  Custom domain: https://lilith-zero.badcompany.xyz"
echo "  Validate:      https://lilith-zero.badcompany.xyz/validate"
echo "  Analyze:       https://lilith-zero.badcompany.xyz/analyze-tool-execution"
echo ""
echo "Next step: Go to Power Platform Admin Center > Security > Threat detection"
echo "  Entra App ID:   $APP_ID"
echo "  Endpoint URL:   https://lilith-zero.badcompany.xyz"
echo ""
echo "Then hit 'Save' — it will call /validate and should return isSuccessful: true"
