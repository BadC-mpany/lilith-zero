#!/usr/bin/env bash
# Lilith Zero — Azure App Service deploy script (Colleague Environment)
# Run from repo root: bash scripts/azure-deploy.sh
set -euo pipefail

# ── Config ─────────────────────────────────────────────────────────────────
RESOURCE_GROUP="BadCompany"
LOCATION="eastus2" # Changed from eastus to eastus2 to avoid capacity limitations
APP_SERVICE_PLAN="lilith-zero-plan-new"
APP_NAME="lilith-zero-webhook-mz"           # → lilith-zero-webhook-mz.azurewebsites.net
REGISTRY_NAME="lilithzeromzcr"              # Azure Container Registry (globally unique)
IMAGE_NAME="lilith-zero"
IMAGE_TAG="latest"
SUBSCRIPTION="4d062d5a-28e9-473b-8eb6-8c0a88ce41a4"
TENANT_ID="26f834b9-3844-4b6a-8305-fbec7a80cb95"
APP_ID="02280932-064c-459e-86d6-0dcfe07bd99f"

echo "=== Lilith Zero Azure Deploy ==="
echo ""

# ── 0. Set subscription ─────────────────────────────────────────────────────
az account set --subscription "$SUBSCRIPTION"
echo "✓ Subscription set to $SUBSCRIPTION"

# ── 1. Resource Group ───────────────────────────────────────────────────────
echo ""
echo "Verifying or creating resource group $RESOURCE_GROUP in $LOCATION..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
echo "✓ Resource group ready"

# ── 2. Container Registry ───────────────────────────────────────────────────
echo ""
echo "Creating Azure Container Registry $REGISTRY_NAME (admin enabled)..."
# Admin enabled is required because Contributor subscription permissions prevent role assignments for Managed Identity
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

# Copy pre-built binary to local bin to prevent scanning massive target/ folder
cp lilith-zero/target/release/lilith-zero ./lilith-zero-bin

az acr build \
    --registry "$REGISTRY_NAME" \
    --image "${IMAGE_NAME}:${IMAGE_TAG}" \
    --file Dockerfile \
    . 

# Clean up local binary
rm -f ./lilith-zero-bin
echo "✓ Image pushed: ${REGISTRY_NAME}.azurecr.io/${IMAGE_NAME}:${IMAGE_TAG}"

# ── 4. App Service Plan (B1 = cheapest with custom domain + SSL) ─────────────
echo ""
echo "Creating App Service Plan ($APP_SERVICE_PLAN)..."
# Check if plan already exists
if ! az appservice plan show --name "$APP_SERVICE_PLAN" --resource-group "$RESOURCE_GROUP" --output none 2>/dev/null; then
    az appservice plan create \
        --name "$APP_SERVICE_PLAN" \
        --resource-group "$RESOURCE_GROUP" \
        --location "$LOCATION" \
        --is-linux \
        --sku B1 \
        --output none
    echo "✓ App Service Plan created (B1 Linux)"
else
    echo "✓ App Service Plan already exists"
fi

# ── 5. Web App with Registry Admin Credentials ────────────────────────────────
echo ""
echo "Creating Web App $APP_NAME..."
ACR_LOGIN_SERVER="${REGISTRY_NAME}.azurecr.io"
ACR_PASSWORD=$(az acr credential show --name "$REGISTRY_NAME" --query "passwords[0].value" -o tsv)

# Create Web App with container configuration
if ! az webapp show --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" --output none 2>/dev/null; then
    az webapp create \
        --resource-group "$RESOURCE_GROUP" \
        --plan "$APP_SERVICE_PLAN" \
        --name "$APP_NAME" \
        --deployment-container-image-name "${ACR_LOGIN_SERVER}/${IMAGE_NAME}:${IMAGE_TAG}" \
        --docker-registry-server-url "https://${ACR_LOGIN_SERVER}" \
        --docker-registry-server-user "$REGISTRY_NAME" \
        --docker-registry-server-password "$ACR_PASSWORD" \
        --startup-file "/app/lilith-zero serve --bind 0.0.0.0:8080 --auth-mode entra" \
        --output none
    echo "✓ Web app created"
else
    echo "✓ Web app already exists"
fi

# Configure Web App to pull using the registry credentials
az webapp config container set \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --docker-custom-image-name "${ACR_LOGIN_SERVER}/${IMAGE_NAME}:${IMAGE_TAG}" \
    --docker-registry-server-url "https://${ACR_LOGIN_SERVER}" \
    --docker-registry-server-user "$REGISTRY_NAME" \
    --docker-registry-server-password "$ACR_PASSWORD" \
    --output none

# ── 6. Configure App Settings ────────────────────────────────────────────────
echo ""
echo "Configuring App Settings..."
az webapp config appsettings set \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --settings \
        RUST_LOG=info \
        WEBSITES_ENABLE_APP_SERVICE_STORAGE=true \
        WEBSITES_PORT=8080 \
        LILITH_ZERO_ENTRA_TENANT_ID="$TENANT_ID" \
        LILITH_ZERO_ENTRA_AUDIENCE="api://$APP_ID" \
        POLICIES_YAML_PATH="/app/policies" \
    --output none
echo "✓ App settings configured"

# ── 7. Custom domain verification ───────────────────────────────────────────
echo ""
echo "Adding custom domain lilith-zero.badcompany.xyz..."

# Get Web App custom domain verification ID
VERIFICATION_ID=$(az webapp show \
    --name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query "customDomainVerificationId" \
    -o tsv)

echo ""
echo "  ⚠  ACTION REQUIRED IN YOUR DNS MANAGER (e.g. Namecheap):"
echo "  Configure the following DNS records:"
echo ""
echo "  1. TXT Record (for ownership verification):"
echo "     Host:  asuid.lilith-zero"
echo "     Value: $VERIFICATION_ID"
echo ""
echo "  2. CNAME Record (for routing traffic):"
echo "     Host:  lilith-zero"
echo "     Value: ${APP_NAME}.azurewebsites.net"
echo ""
echo "  After configuring these records in Namecheap, press ENTER to verify and add domain..."
read -r

az webapp config hostname add \
    --webapp-name "$APP_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --hostname "lilith-zero.badcompany.xyz" \
    --output none
echo "✓ Custom hostname added"

# ── 8. Managed certificate (free SSL for custom domain) ──────────────────────
echo ""
echo "Creating and binding free managed SSL certificate..."
THUMBPRINT=$(az webapp config ssl create \
    --resource-group "$RESOURCE_GROUP" \
    --name "$APP_NAME" \
    --hostname "lilith-zero.badcompany.xyz" \
    --query "thumbprint" \
    -o tsv || echo "")

if [ -n "$THUMBPRINT" ]; then
    echo "Binding SSL certificate to lilith-zero.badcompany.xyz..."
    az webapp config ssl bind \
        --resource-group "$RESOURCE_GROUP" \
        --name "$APP_NAME" \
        --certificate-thumbprint "$THUMBPRINT" \
        --ssl-type SNI \
        --output none
    echo "✓ SSL certificate bound successfully"
else
    echo "⚠ SSL Certificate thumbprint not returned. Verify DNS propagation and bind manually in Portal if needed."
fi

# ── 9. Update Federated Identity Credential subject ─────────────────────────
echo ""
echo "Configuring Federated Identity Credential..."
ENDPOINT_URL="https://lilith-zero.badcompany.xyz"
NEW_SUBJECT=$(python3 -c "
import base64, uuid
tenant_id = '${TENANT_ID}'
copilot_app_id = '9d8f559b-5984-46a4-902a-ad4271e83efa'
endpoint_url = '${ENDPOINT_URL}'

def b64url_uuid(u_str):
    return base64.urlsafe_b64encode(uuid.UUID(u_str).bytes_le).decode().rstrip('=')

def b64url_str(s):
    return base64.urlsafe_b64encode(s.encode()).decode().rstrip('=')

print(f'/eid1/c/pub/t/{b64url_uuid(tenant_id)}/a/{b64url_uuid(copilot_app_id)}/{b64url_str(endpoint_url)}')
")

echo "Subject string: $NEW_SUBJECT"

# Check if federated credential already exists
FIC_ID=$(az ad app federated-credential list --id "$APP_ID" --query "[?name=='LilithZeroFIC'].id" -o tsv)

if [ -z "$FIC_ID" ]; then
    echo "Creating federated credential..."
    az ad app federated-credential create \
        --id "$APP_ID" \
        --parameters "{
            \"name\": \"LilithZeroFIC\",
            \"issuer\": \"https://login.microsoftonline.com/${TENANT_ID}/v2.0\",
            \"subject\": \"${NEW_SUBJECT}\",
            \"description\": \"Azure App Service deployment\",
            \"audiences\": [\"api://AzureADTokenExchange\"]
        }"
else
    echo "Updating federated credential $FIC_ID..."
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
fi
echo "✓ Federated credential configured"

# ── 10. Final status ──────────────────────────────────────────────────────────
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
