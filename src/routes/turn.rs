use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac, KeyInit};
use sha1::Sha1;
use std::{sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use crate::auth::decode_jwt_sub;
use crate::models::TurnCredentialsResponse;
use crate::state::AppState;

pub async fn turn_credentials_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let token = headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "));
    let sub = token.and_then(|t| decode_jwt_sub(t, &state.jwt_secret));
    if sub.is_none() {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let shared_secret = match std::env::var("TURN_SHARED_SECRET") {
        Ok(secret) if !secret.trim().is_empty() => secret.trim().to_string(),
        _ => return (StatusCode::SERVICE_UNAVAILABLE, "TURN_SHARED_SECRET must be set and non-empty").into_response(),
    };
    
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() + 86400; // 24h validity
    let username = format!("{}:{}", timestamp, uuid::Uuid::new_v4());
    
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = match HmacSha1::new_from_slice(shared_secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to initialize HMAC with TURN secret").into_response(),
    };
    mac.update(username.as_bytes());
    let password = BASE64.encode(mac.finalize().into_bytes());

    let raw_server_host = std::env::var("TURN_SERVER_HOST")
        .unwrap_or_else(|_| "router.baton.com:3478".to_string());
    let trimmed = raw_server_host.trim()
        .trim_start_matches("turn:")
        .trim_start_matches("turns:")
        .trim_end_matches('/')
        .trim();
    let server_host = if trimmed.is_empty() {
        "router.baton.com:3478"
    } else {
        trimmed
    };

    Json(TurnCredentialsResponse {
        username,
        password,
        ttl: 86400,
        uris: vec![
            format!("turn:{}?transport=udp", server_host),
            format!("turn:{}", server_host),
        ],
    }).into_response()
}
