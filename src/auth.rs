use crate::models::Claims;
use tracing::warn;

pub fn verify_jwt(token: &str, secret: &str, expected_sub: &str) -> bool {
    if secret.is_empty() || expected_sub.is_empty() {
        return false;
    }
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 60;
    
    match jsonwebtoken::decode::<Claims>(
        token,
        &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(token_data) => token_data.claims.sub == expected_sub,
        Err(e) => {
            warn!("JWT validation failed: {}", e);
            false
        }
    }
}
