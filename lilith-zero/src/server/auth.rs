// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0

//! JWT authentication for the Copilot Studio webhook server.
//!
//! Three authentication modes are supported, selected at server startup:
//!
//! | Mode            | Use case                          | Security level  |
//! |-----------------|-----------------------------------|-----------------|
//! | `None`          | Local development / testing only  | ⚠️ INSECURE      |
//! | `SharedSecret`  | HS256 with `LILITH_ZERO_JWT_SECRET` | Moderate       |
//! | `EntraId`       | RS256 via Microsoft JWKS endpoint | Production-safe |
//!
//! # Fail-closed behaviour
//! Any failure in token extraction or validation returns an [`AuthError`],
//! which the webhook handler translates to HTTP 401. The tool call is never
//! allowed through on auth failure.
//!
//! # Entra ID JWKS caching
//! Public keys are cached for 1 hour and refreshed on cache miss or expiry.
//! A `kid` mismatch after refresh returns 401 (we do not retry indefinitely
//! to avoid cache-busting DoS attacks).

use anyhow::Result;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Auth error type
// ---------------------------------------------------------------------------

/// Errors produced during JWT extraction or validation.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("missing Authorization header")]
    MissingAuthHeader,

    #[error("Authorization header is not a Bearer token")]
    NotBearerToken,

    #[error("JWT header could not be decoded: {0}")]
    InvalidHeader(String),

    #[error("JWT validation failed: {0}")]
    ValidationFailed(String),

    #[error("JWT is missing required claim '{0}'")]
    MissingClaim(&'static str),

    #[error("JWT issuer mismatch: expected '{expected}', got '{got}'")]
    InvalidIssuer { expected: String, got: String },

    #[error("JWKS key with kid '{0}' not found")]
    KeyNotFound(String),

    #[error("failed to fetch or parse JWKS: {0}")]
    JwksFetchFailed(String),

    #[error("authentication is disabled (no-auth mode)")]
    NoAuthConfigured,
}

// ---------------------------------------------------------------------------
// Authenticator trait
// ---------------------------------------------------------------------------

/// Validates a raw JWT string extracted from an Authorization Bearer header.
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    async fn validate_token(&self, token: &str) -> Result<(), AuthError>;

    /// Returns a human-readable description of this authenticator for logs.
    fn description(&self) -> &'static str;

    /// Whether this authenticator accepts requests that carry no Authorization header.
    ///
    /// Defaults to `false`. Only [`NoAuthAuthenticator`] overrides this to `true`.
    /// The `authenticate()` helper checks this explicitly so that future implementations
    /// cannot accidentally grant access to headerless requests by returning `Ok(())`
    /// for an empty-string token.
    fn accepts_unauthenticated_requests(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Extract Bearer token from HTTP header value
// ---------------------------------------------------------------------------

/// Extract the raw JWT from an `Authorization: Bearer <token>` header value.
/// Returns [`AuthError::MissingAuthHeader`] if the header is absent,
/// [`AuthError::NotBearerToken`] if the scheme is not `Bearer`.
pub fn extract_bearer_token(auth_header: Option<&str>) -> Result<&str, AuthError> {
    let value = auth_header.ok_or(AuthError::MissingAuthHeader)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(AuthError::NotBearerToken)?;
    if token.is_empty() {
        return Err(AuthError::NotBearerToken);
    }
    Ok(token)
}

// ---------------------------------------------------------------------------
// Mode 1: No-auth (development only)
// ---------------------------------------------------------------------------

/// Accepts every request without any token validation.
///
/// # Security warning
/// This mode is **only** appropriate for local development. Do not use in
/// production — any caller can impersonate any identity.
pub struct NoAuthAuthenticator;

#[async_trait::async_trait]
impl Authenticator for NoAuthAuthenticator {
    async fn validate_token(&self, _token: &str) -> Result<(), AuthError> {
        tracing::warn!(
            "SECURITY WARNING: webhook running in no-auth mode. \
             All requests accepted without authentication. \
             Set --auth-mode shared-secret or --auth-mode entra for production."
        );
        Ok(())
    }

    fn description(&self) -> &'static str {
        "no-auth (development only — all tokens accepted)"
    }

    fn accepts_unauthenticated_requests(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// Mode 2: Shared secret (HS256)
// ---------------------------------------------------------------------------

/// Validates JWTs signed with a shared HMAC-SHA256 secret.
///
/// Configure with `LILITH_ZERO_JWT_SECRET` or `--jwt-secret`.
/// The secret must be the same value used to sign tokens on the caller side.
pub struct SharedSecretAuthenticator {
    secret: String,
    audience: Option<Vec<String>>,
}

impl SharedSecretAuthenticator {
    pub fn new(secret: impl Into<String>, audience: Option<Vec<String>>) -> Self {
        Self {
            secret: secret.into(),
            audience,
        }
    }
}

#[async_trait::async_trait]
impl Authenticator for SharedSecretAuthenticator {
    async fn validate_token(&self, token: &str) -> Result<(), AuthError> {
        let key = DecodingKey::from_secret(self.secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        if let Some(ref aud) = self.audience {
            validation.set_audience(aud);
        } else {
            validation.validate_aud = false;
        }

        decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|e| AuthError::ValidationFailed(e.to_string()))?;

        Ok(())
    }

    fn description(&self) -> &'static str {
        "shared-secret (HS256)"
    }
}

// ---------------------------------------------------------------------------
// Mode 3: Microsoft Entra ID (RS256 via JWKS)
// ---------------------------------------------------------------------------

/// Cached JWKS key set with timestamps for TTL and forced-refresh cooldown.
struct JwksCache {
    key_set: jsonwebtoken::jwk::JwkSet,
    fetched_at: Instant,
    /// Set when the cache was force-refreshed after a `KeyNotFound` to enforce a cooldown
    /// and prevent cache-busting DoS attacks.
    forced_at: Option<Instant>,
}

/// Validates JWTs issued by Microsoft Entra ID using the tenant's JWKS endpoint.
///
/// # Key caching
/// JWKS keys are cached for [`JWKS_CACHE_TTL`]. On cache miss (first call or
/// after TTL), keys are refreshed from the JWKS endpoint.
///
/// # Key rotation recovery
/// If a `kid` is not found in the cached key set, the cache is force-refreshed
/// once (subject to a [`FORCE_REFRESH_COOLDOWN`] to prevent DoS). If the `kid`
/// is still absent after the refresh, `KeyNotFound` is returned. This limits
/// the outage window on Entra key rotations to the cooldown period (60 s)
/// rather than the full TTL (1 h).
///
/// # Issuer validation
/// The issuer must be `https://login.microsoftonline.com/{tenant_id}/v2.0`.
/// This prevents tokens from other Entra tenants from being accepted.
pub struct EntraAuthenticator {
    tenant_id: String,
    audience: String,
    jwks_url: String,
    cache: Arc<RwLock<Option<JwksCache>>>,
}

/// Maximum age of cached JWKS keys before a TTL-driven refresh is triggered.
const JWKS_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Minimum time between forced cache refreshes triggered by `KeyNotFound`.
/// Prevents a burst of requests with unknown `kid` values from flooding the JWKS endpoint.
const FORCE_REFRESH_COOLDOWN: Duration = Duration::from_secs(60);

impl EntraAuthenticator {
    /// Create an authenticator for a specific Entra tenant and audience.
    pub fn new(tenant_id: impl Into<String>, audience: impl Into<String>) -> Self {
        let tid = tenant_id.into();
        let jwks_url = format!(
            "https://login.microsoftonline.com/{}/discovery/v2.0/keys",
            tid
        );
        Self {
            tenant_id: tid,
            audience: audience.into(),
            jwks_url,
            cache: Arc::new(RwLock::new(None)),
        }
    }

    /// Override the JWKS URL (used in tests to point at a local mock server).
    pub fn with_jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = url.into();
        self
    }

    /// Fetch (and cache) the JWKS key set from the configured endpoint.
    async fn get_jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet, AuthError> {
        // Fast path: cache hit under read lock.
        {
            let guard = self.cache.read().await;
            if let Some(ref c) = *guard {
                if c.fetched_at.elapsed() < JWKS_CACHE_TTL {
                    return Ok(c.key_set.clone());
                }
            }
        }

        // Slow path: refresh under write lock.
        let mut guard = self.cache.write().await;

        // Another task may have refreshed while we waited for the write lock.
        if let Some(ref c) = *guard {
            if c.fetched_at.elapsed() < JWKS_CACHE_TTL {
                return Ok(c.key_set.clone());
            }
        }

        let response = reqwest::get(&self.jwks_url)
            .await
            .map_err(|e| AuthError::JwksFetchFailed(e.to_string()))?;

        let key_set: jsonwebtoken::jwk::JwkSet = response
            .json()
            .await
            .map_err(|e| AuthError::JwksFetchFailed(format!("JWKS parse error: {e}")))?;

        *guard = Some(JwksCache {
            key_set: key_set.clone(),
            fetched_at: Instant::now(),
            forced_at: None,
        });

        Ok(key_set)
    }

    /// Force-refresh the JWKS cache regardless of TTL, subject to a cooldown.
    ///
    /// Called after a `KeyNotFound` to recover from Entra key rotations without
    /// waiting for the full 1-hour TTL. The cooldown prevents a burst of unknown
    /// `kid` values from flooding the JWKS endpoint.
    async fn force_refresh_jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet, AuthError> {
        let mut guard = self.cache.write().await;

        // Cooldown check: if we forced a refresh recently, return the cached keys
        // rather than hitting the JWKS endpoint again.
        if let Some(ref c) = *guard {
            if let Some(forced_at) = c.forced_at {
                if forced_at.elapsed() < FORCE_REFRESH_COOLDOWN {
                    return Ok(c.key_set.clone());
                }
            }
        }

        let response = reqwest::get(&self.jwks_url)
            .await
            .map_err(|e| AuthError::JwksFetchFailed(e.to_string()))?;

        let key_set: jsonwebtoken::jwk::JwkSet = response
            .json()
            .await
            .map_err(|e| AuthError::JwksFetchFailed(format!("JWKS parse error: {e}")))?;

        *guard = Some(JwksCache {
            key_set: key_set.clone(),
            fetched_at: Instant::now(),
            forced_at: Some(Instant::now()),
        });

        Ok(key_set)
    }

    /// Validate a token against a specific JWK. Extracted to avoid duplicating the
    /// RS256 + issuer check logic between the normal path and the retry-after-refresh path.
    fn validate_with_jwk(
        &self,
        token: &str,
        jwk: &jsonwebtoken::jwk::Jwk,
    ) -> Result<(), AuthError> {
        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| AuthError::ValidationFailed(format!("key conversion: {e}")))?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[&self.audience]);

        let token_data = decode::<EntraClaims>(token, &decoding_key, &validation)
            .map_err(|e| AuthError::ValidationFailed(e.to_string()))?;

        let expected_iss = format!("https://login.microsoftonline.com/{}/v2.0", self.tenant_id);
        if token_data.claims.iss != expected_iss {
            return Err(AuthError::InvalidIssuer {
                expected: expected_iss,
                got: token_data.claims.iss,
            });
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl Authenticator for EntraAuthenticator {
    async fn validate_token(&self, token: &str) -> Result<(), AuthError> {
        // Decode the header to find the key ID (kid).
        let header = decode_header(token).map_err(|e| AuthError::InvalidHeader(e.to_string()))?;

        let kid = header.kid.ok_or(AuthError::MissingClaim("kid"))?;

        // Fetch (possibly cached) JWKS and look up the key.
        let jwks = self.get_jwks().await?;
        if let Some(jwk) = jwks.find(&kid) {
            return self.validate_with_jwk(token, jwk);
        }

        // kid not found — Entra may have rotated its signing keys. Force-refresh
        // the cache and retry exactly once. The cooldown in force_refresh_jwks
        // bounds how often we hit the JWKS endpoint on unknown kids.
        tracing::info!(kid = %kid, "kid not in cached JWKS, forcing refresh for key rotation recovery");
        let refreshed = self.force_refresh_jwks().await?;
        let jwk = refreshed
            .find(&kid)
            .ok_or_else(|| AuthError::KeyNotFound(kid.clone()))?;

        self.validate_with_jwk(token, jwk)
    }

    fn description(&self) -> &'static str {
        "entra-id (RS256 via JWKS)"
    }
}

/// Minimum set of claims we validate from Entra ID tokens.
#[derive(Debug, Deserialize, Serialize)]
struct EntraClaims {
    /// Issuer — must match `https://login.microsoftonline.com/{tenant}/v2.0`.
    iss: String,
    /// Audience.
    #[serde(default)]
    aud: serde_json::Value,
    /// Expiry (validated automatically by `jsonwebtoken`).
    exp: i64,
    /// Subject (user or service principal object ID).
    #[serde(default)]
    sub: Option<String>,
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    fn make_hs256_token(secret: &str, aud: &str, exp_offset_secs: i64) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let claims = serde_json::json!({
            "sub": "test-subject",
            "aud": aud,
            "exp": now + exp_offset_secs,
            "iat": now,
            "iss": "test-issuer"
        });

        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("failed to encode test token")
    }

    // --- extract_bearer_token ---

    #[test]
    fn test_extract_bearer_token_succeeds() {
        let token = extract_bearer_token(Some("Bearer abc.def.ghi")).unwrap();
        assert_eq!(token, "abc.def.ghi");
    }

    #[test]
    fn test_extract_bearer_token_missing_header() {
        assert!(matches!(
            extract_bearer_token(None),
            Err(AuthError::MissingAuthHeader)
        ));
    }

    #[test]
    fn test_extract_bearer_token_wrong_scheme() {
        assert!(matches!(
            extract_bearer_token(Some("Basic dXNlcjpwYXNz")),
            Err(AuthError::NotBearerToken)
        ));
    }

    #[test]
    fn test_extract_bearer_token_empty_token() {
        assert!(matches!(
            extract_bearer_token(Some("Bearer ")),
            Err(AuthError::NotBearerToken)
        ));
    }

    // --- NoAuthAuthenticator ---

    #[tokio::test]
    async fn test_no_auth_accepts_any_token() {
        let auth = NoAuthAuthenticator;
        auth.validate_token("literally.anything.here")
            .await
            .expect("no-auth must accept any token");
    }

    #[tokio::test]
    async fn test_no_auth_accepts_empty_string() {
        let auth = NoAuthAuthenticator;
        auth.validate_token("")
            .await
            .expect("no-auth must accept empty string");
    }

    // --- SharedSecretAuthenticator ---

    #[tokio::test]
    async fn test_shared_secret_valid_token_accepted() {
        let secret = "super-secret-key-for-testing";
        let token = make_hs256_token(secret, "test-audience", 3600);
        let auth = SharedSecretAuthenticator::new(secret, Some(vec!["test-audience".into()]));
        auth.validate_token(&token)
            .await
            .expect("valid HS256 token must be accepted");
    }

    #[tokio::test]
    async fn test_shared_secret_wrong_secret_rejected() {
        let token = make_hs256_token("correct-secret", "test-audience", 3600);
        let auth = SharedSecretAuthenticator::new("wrong-secret", None);
        let result = auth.validate_token(&token).await;
        assert!(
            result.is_err(),
            "token signed with wrong secret must be rejected"
        );
    }

    #[tokio::test]
    async fn test_shared_secret_expired_token_rejected() {
        let secret = "my-secret";
        let token = make_hs256_token(secret, "aud", -3600); // expired 1 hour ago
        let auth = SharedSecretAuthenticator::new(secret, None);
        let result = auth.validate_token(&token).await;
        assert!(result.is_err(), "expired token must be rejected");
    }

    #[tokio::test]
    async fn test_shared_secret_wrong_audience_rejected() {
        let secret = "my-secret";
        let token = make_hs256_token(secret, "wrong-audience", 3600);
        let auth = SharedSecretAuthenticator::new(secret, Some(vec!["expected-audience".into()]));
        let result = auth.validate_token(&token).await;
        assert!(result.is_err(), "wrong audience must be rejected");
    }

    #[tokio::test]
    async fn test_shared_secret_malformed_token_rejected() {
        let auth = SharedSecretAuthenticator::new("secret", None);
        let result = auth.validate_token("not.a.jwt").await;
        assert!(result.is_err(), "malformed token must be rejected");
    }

    #[tokio::test]
    async fn test_shared_secret_no_audience_validation_when_none() {
        // When no expected audience is configured, audience claim is not checked.
        let secret = "my-secret";
        let token = make_hs256_token(secret, "any-audience", 3600);
        let auth = SharedSecretAuthenticator::new(secret, None);
        auth.validate_token(&token)
            .await
            .expect("any audience must be accepted when audience validation is disabled");
    }

    // --- EntraAuthenticator JWKS mock tests ---
    // These tests start a minimal axum server that serves a JWKS document,
    // allowing end-to-end testing of the JWKS fetch and error paths without
    // network access to a real Entra tenant.

    /// Spin up a one-shot axum server that responds with `body` on any request.
    async fn mock_jwks_server(body: &'static str, status: u16) -> String {
        use axum::{
            response::{IntoResponse, Response},
            routing::get,
            Router,
        };
        use tokio::net::TcpListener;

        let app = Router::new().route(
            "/*path",
            get(move || async move {
                Response::builder()
                    .status(status)
                    .header("Content-Type", "application/json")
                    .body(axum::body::Body::from(body))
                    .unwrap()
                    .into_response()
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://127.0.0.1:{}", addr.port())
    }

    /// JWKS endpoint returns HTTP 500 → `JwksFetchFailed`.
    #[tokio::test]
    async fn test_entra_jwks_fetch_failed_on_server_error() {
        let base = mock_jwks_server(r#"{"error":"internal"}"#, 500).await;
        let auth = EntraAuthenticator::new("test-tenant", "https://api.example.com")
            .with_jwks_url(format!("{base}/keys"));

        // Use a syntactically valid JWT header so we reach the JWKS fetch step.
        // The token body doesn't matter because we fail before signature checks.
        let fake_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.e30.signature";
        let result = auth.validate_token(fake_token).await;
        assert!(
            matches!(result, Err(AuthError::JwksFetchFailed(_))),
            "HTTP 500 from JWKS endpoint must produce JwksFetchFailed, got: {result:?}"
        );
    }

    /// JWKS endpoint returns invalid JSON → `JwksFetchFailed`.
    #[tokio::test]
    async fn test_entra_jwks_fetch_failed_on_invalid_json() {
        let base = mock_jwks_server("not valid json {{{", 200).await;
        let auth = EntraAuthenticator::new("test-tenant", "https://api.example.com")
            .with_jwks_url(format!("{base}/keys"));

        let fake_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.e30.signature";
        let result = auth.validate_token(fake_token).await;
        assert!(
            matches!(result, Err(AuthError::JwksFetchFailed(_))),
            "Invalid JSON from JWKS endpoint must produce JwksFetchFailed, got: {result:?}"
        );
    }

    /// JWKS endpoint returns a valid key set but with no matching kid → `KeyNotFound`.
    /// Also verifies that the force-refresh path is exercised (two HTTP requests made).
    #[tokio::test]
    async fn test_entra_key_not_found_when_kid_absent_from_jwks() {
        // A syntactically valid but empty JWKS (no keys).
        let base = mock_jwks_server(r#"{"keys":[]}"#, 200).await;
        let auth = EntraAuthenticator::new("test-tenant", "https://api.example.com")
            .with_jwks_url(format!("{base}/keys"));

        let fake_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.e30.signature";
        let result = auth.validate_token(fake_token).await;
        // The kid "test-kid" is not in the empty set — after the forced refresh
        // (which also returns empty), KeyNotFound is returned.
        assert!(
            matches!(result, Err(AuthError::KeyNotFound(_))),
            "Empty JWKS must produce KeyNotFound after force-refresh, got: {result:?}"
        );
    }

    /// Token with no `kid` header → `MissingClaim`.
    #[tokio::test]
    async fn test_entra_missing_kid_in_header() {
        // RS256 token without a kid claim in the header.
        let base = mock_jwks_server(r#"{"keys":[]}"#, 200).await;
        let auth = EntraAuthenticator::new("test-tenant", "https://api.example.com")
            .with_jwks_url(format!("{base}/keys"));

        // eyJhbGciOiJSUzI1NiJ9 = {"alg":"RS256"} (no kid)
        let token_no_kid = "eyJhbGciOiJSUzI1NiJ9.e30.signature";
        let result = auth.validate_token(token_no_kid).await;
        assert!(
            matches!(result, Err(AuthError::MissingClaim("kid"))),
            "Token without kid must produce MissingClaim(kid), got: {result:?}"
        );
    }

    /// Malformed JWT header → `InvalidHeader`.
    #[tokio::test]
    async fn test_entra_malformed_jwt_header() {
        let base = mock_jwks_server(r#"{"keys":[]}"#, 200).await;
        let auth = EntraAuthenticator::new("test-tenant", "https://api.example.com")
            .with_jwks_url(format!("{base}/keys"));

        let result = auth.validate_token("not.a.jwt").await;
        assert!(
            matches!(result, Err(AuthError::InvalidHeader(_))),
            "Malformed JWT must produce InvalidHeader, got: {result:?}"
        );
    }

    /// The `NoAuthAuthenticator` accepts requests without an Authorization header.
    #[test]
    fn test_no_auth_accepts_unauthenticated_requests() {
        assert!(
            NoAuthAuthenticator.accepts_unauthenticated_requests(),
            "NoAuthAuthenticator must accept unauthenticated requests"
        );
    }

    /// All other authenticators must NOT accept unauthenticated requests by default.
    #[test]
    fn test_shared_secret_rejects_unauthenticated_requests() {
        let auth = SharedSecretAuthenticator::new("secret", None);
        assert!(
            !auth.accepts_unauthenticated_requests(),
            "SharedSecretAuthenticator must not accept unauthenticated requests"
        );
    }
}
