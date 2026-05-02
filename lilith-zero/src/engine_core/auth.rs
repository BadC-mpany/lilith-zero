// Copyright 2026 BadCompany
// Licensed under the Apache License, Version 2.0 (the "License");
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and

use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    aud: Option<serde_json::Value>, // Audience can be single string or array
    exp: usize,
    iat: Option<usize>,
    iss: Option<String>,
}

/// Validate the JWT `aud` claim against the list of `expected_audiences`.
///
/// Returns `Ok(())` if the token is valid and contains at least one of the expected audiences.
/// Returns an error if the token is missing, malformed, expired, or carries an unexpected audience.
///
/// # Errors
/// - If `jwt_secret` is `None` and audiences are configured.
/// - If the token cannot be decoded or its signature is invalid.
/// - If the `aud` claim is absent or does not match any expected audience.
pub fn validate_audience_claim(
    token: &str,
    expected_audiences: &[String],
    jwt_secret: Option<&str>,
) -> Result<()> {
    let secret = jwt_secret.ok_or_else(|| anyhow!("Authentication required (audiences set) but lilith-zero_JWT_SECRET is missing. Cannot validate token."))?;

    let (decoding_key, algorithm) = if secret.starts_with("-----BEGIN") {
        (
            DecodingKey::from_rsa_pem(secret.as_bytes())
                .map_err(|e| anyhow!("Invalid RSA PEM: {}", e))?,
            Algorithm::RS256,
        )
    } else {
        (
            DecodingKey::from_secret(secret.as_bytes()),
            Algorithm::HS256,
        )
    };

    let mut validation = Validation::new(algorithm); // Use detected algorithm

    validation.validate_aud = false; // We check manually.

    let token_data = decode::<Claims>(token, &decoding_key, &validation)
        .map_err(|e| anyhow!("Invalid JWT signature or structure: {}", e))?;

    let claims = token_data.claims;

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
    } else {
        return Err(anyhow!("Token missing 'aud' claim"));
    }

    Ok(())
}
