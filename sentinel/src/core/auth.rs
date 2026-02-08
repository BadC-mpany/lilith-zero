//! Authentication utilities.
//!
//! Provides JWT validation for audience binding ("The client is who they say they are").
//! Enforces strict cryptographic checks if a JWT secret/key is provided.

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: Option<serde_json::Value>, // Audience can be single string or array
    // Standard claims
    exp: usize,
    iat: Option<usize>,
    iss: Option<String>,
}

/// Validates that the provided JWT token is:
/// 1. Cryptographically valid (signed by our secret)
/// 2. Has an 'aud' claim containing at least one of the expected audiences
///
/// Returns Ok(()) if valid, Err otherwise.
pub fn validate_audience_claim(
    token: &str,
    expected_audiences: &[String],
    jwt_secret: Option<&str>,
) -> Result<()> {
    // 1. If we have a secret, enforce signature validation.
    // "Google-grade": If auth is required (expected_audiences exist), we MUST have a secret.
    let secret = jwt_secret.ok_or_else(|| anyhow!("Authentication required (audiences set) but SENTINEL_JWT_SECRET is missing. Cannot validate token."))?;

    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256); // Default to HS256 for now. logic can expand.

    validation.validate_aud = false; // We check manually.

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| anyhow!("Invalid JWT signature or structure: {}", e))?;

    let claims = token_data.claims;

    // 2. Check Audience
    if let Some(aud_val) = claims.aud {
        let token_auds: Vec<String> = match aud_val {
            serde_json::Value::String(s) => vec![s],
            serde_json::Value::Array(arr) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            _ => {
                return Err(anyhow!(
                    "Invalid 'aud' claim type (must be string or array of strings)"
                ))
            }
        };

        let mut found = false;
        for expected in expected_audiences {
            if token_auds.contains(expected) {
                found = true;
                break;
            }
        }
        if !found {
            return Err(anyhow!(
                "Token audience {:?} does not match expected {:?}",
                token_auds,
                expected_audiences
            ));
        }
        if !found {
            return Err(anyhow!(
                "Token audience {:?} does not match expected {:?}",
                token_auds,
                expected_audiences
            ));
        }
    } else {
        return Err(anyhow!("Token missing 'aud' claim"));
    }

    Ok(())
}
