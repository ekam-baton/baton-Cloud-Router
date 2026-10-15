use axum::{http::StatusCode, response::IntoResponse, Json};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac, KeyInit};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::models::{Claims, TurnCredentialsResponse};

pub async fn turn_credentials_handler(
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let token = headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "));
    let is_valid_token = if let Some(t) = token {
        let secret = std::env::var("JWT_SECRET").unwrap_or_default();
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.validate_exp = true;
        jsonwebtoken::decode::<Claims>(t, &jsonwebtoken::DecodingKey::from_secret(secret.as_bytes()), &validation).is_ok()
    } else {
        false
    };

    if !is_valid_token {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let shared_secret = match std::env::var("TURN_SHARED_SECRET") {
        Ok(secret) => secret,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, "TURN_SHARED_SECRET must be set").into_response(),
    };
    
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + 86400; // 24h validity
    let username = format!("{}:{}", timestamp, uuid::Uuid::new_v4());
    
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(shared_secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(username.as_bytes());
    let password = BASE64.encode(mac.finalize().into_bytes());

    Json(TurnCredentialsResponse {
        username,
        password,
        ttl: 86400,
        uris: vec![
            "turn:router.baton.com:3478".to_string(),
            "turn:router.baton.com:3478?transport=tcp".to_string(),
        ],
    }).into_response()
}
