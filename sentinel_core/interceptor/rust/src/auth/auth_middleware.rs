// Axum authentication middleware

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{Json, Response},
};
use std::sync::Arc;
use tracing::error;
use crate::api::{CustomerStore, PolicyStore};
use crate::auth::api_key::ApiKey;
use crate::auth::audit_logger::{AuditLogger, AuthEvent};
use crate::loader::policy_loader::PolicyLoader;
use crate::api::responses::ErrorResponse;

/// Authentication state containing all dependencies
#[derive(Clone)]
pub struct AuthState {
    pub customer_store: Arc<dyn CustomerStore + Send + Sync>,
    pub policy_store: Arc<dyn PolicyStore + Send + Sync>,
    pub audit_logger: Arc<AuditLogger>,
    pub yaml_fallback: Option<Arc<PolicyLoader>>,
}

/// Authentication middleware function
/// 
/// Extracts API key from `X-API-Key` header, validates it, loads customer and policy,
/// and sets them in request extensions for handlers to use.
pub async fn auth_middleware(
    State(auth_state): State<Arc<AuthState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // 1. Extract API key from header
    let api_key_str = extract_api_key(request.headers())
        .ok_or_else(|| {
            let error = ErrorResponse {
                error: "Missing API key".to_string(),
                request_id: None,
            };
            (StatusCode::UNAUTHORIZED, Json(error))
        })?;

    // 2. Hash API key
    let api_key = ApiKey::new(&api_key_str);
    let api_key_hash = api_key.hash();

    // 3. Lookup customer (try database, fallback to YAML)
    let customer_config = match auth_state.customer_store.lookup_customer(api_key_hash.as_str()).await {
        Ok(Some(config)) => config,
        Ok(None) => {
            // Try YAML fallback if configured
            if let Some(ref loader) = auth_state.yaml_fallback {
                if let Some(config) = loader.get_customer_config(&api_key_str) {
                    config.clone()
                } else {
                    auth_state.audit_logger.log_auth_event(
                        AuthEvent::AuthFailure { reason: "Invalid API key".to_string() },
                        Some(&api_key_hash),
                        extract_ip_address(&request).as_deref(),
                        extract_user_agent(&request).as_deref(),
                    );
                    return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                        error: "Invalid API key".to_string(),
                        request_id: None,
                    })));
                }
            } else {
                auth_state.audit_logger.log_auth_event(
                    AuthEvent::AuthFailure { reason: "Invalid API key".to_string() },
                    Some(&api_key_hash),
                    extract_ip_address(&request).as_deref(),
                    extract_user_agent(&request).as_deref(),
                );
                return Err((StatusCode::UNAUTHORIZED, Json(ErrorResponse {
                    error: "Invalid API key".to_string(),
                    request_id: None,
                })));
            }
        }
        Err(e) => {
            error!(error = %e, "Customer lookup failed");
            let status = axum::http::StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return Err((status, Json(ErrorResponse {
                error: e.user_message(),
                request_id: None,
            })));
        }
    };

    // 4. Load policy
    let policy = match auth_state.policy_store.load_policy(&customer_config.policy_name).await {
        Ok(Some(p)) => (*p).clone(), // Clone Arc contents
        Ok(None) => {
            error!(policy = %customer_config.policy_name, "Policy not found");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse {
                error: format!("Policy '{}' not found", customer_config.policy_name),
                request_id: None,
            })));
        }
        Err(e) => {
            error!(error = %e, "Policy loading failed");
            let status = axum::http::StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            return Err((status, Json(ErrorResponse {
                error: e.user_message(),
                request_id: None,
            })));
        }
    };

    // 5. Log success
    auth_state.audit_logger.log_auth_event(
        AuthEvent::AuthSuccess,
        Some(&api_key_hash),
        extract_ip_address(&request).as_deref(),
        extract_user_agent(&request).as_deref(),
    );

    // 6. Set extensions for handler
    request.extensions_mut().insert(customer_config);
    request.extensions_mut().insert(policy);

    // 7. Continue to next middleware/handler
    Ok(next.run(request).await)
}

/// Extract API key from request headers
fn extract_api_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract IP address from request headers
/// 
/// Checks `X-Forwarded-For` first (for proxied requests), then `X-Real-IP`.
fn extract_ip_address(request: &Request) -> Option<String> {
    request.headers()
        .get("X-Forwarded-For")
        .or_else(|| request.headers().get("X-Real-IP"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Extract user agent from request headers
fn extract_user_agent(request: &Request) -> Option<String> {
    request.headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// Note: auth_middleware_layer helper removed - middleware is applied directly in router
// using from_fn_with_state for better control over route-specific application

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_api_key() {
        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", "test_key_123".parse().unwrap());
        
        let key = extract_api_key(&headers);
        assert_eq!(key, Some("test_key_123".to_string()));
    }

    #[test]
    fn test_extract_api_key_missing() {
        let headers = HeaderMap::new();
        let key = extract_api_key(&headers);
        assert_eq!(key, None);
    }
}
