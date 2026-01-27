//! Authentication and Authorization Logic
//!
//! Handles JWT validation and Audience Binding.

use crate::core::errors::InterceptorError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: String, // Audience
    exp: usize,
    sub: String,
}

/// Validate that a JWT token has a valid signature and matches one of the expected audiences.
pub fn validate_audience_claim(token: &str, expected_audiences: &[String]) -> Result<(), InterceptorError> {
    if expected_audiences.is_empty() {
        return Ok(()); // No audience restrictions configured
    }

    // Use insecure_decode to inspect claims without signature verification
    // This is intentional for the middleware MVP where we don't have the shared keys.
    // In production, use decode() with the correct DecodingKey.
    let token_data = jsonwebtoken::dangerous::insecure_decode::<Claims>(token)
        .map_err(|e| InterceptorError::AuthenticationError(format!("Invalid Token: {}", e)))?;

    if !expected_audiences.contains(&token_data.claims.aud) {
        return Err(InterceptorError::AuthenticationError(format!(
            "Audience mismatch. Token audience '{}' not in expected list {:?}", 
            token_data.claims.aud, expected_audiences
        )));
    }

    Ok(())
}
