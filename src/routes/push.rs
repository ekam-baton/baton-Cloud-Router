use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::sync::Arc;
use tracing::info;
use crate::auth::verify_jwt;
use crate::models::RegisterPushRequest;
use crate::state::AppState;

/// Endpoint: `POST /register-push`
/// Android app calls this on startup to register its FCM token.
/// The router stores it so it can fire a blank wakeup when the client is offline.
pub async fn register_push_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<RegisterPushRequest>,
) -> impl IntoResponse {
    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &payload.client_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if payload.client_id.is_empty() || payload.fcm_token.is_empty() {
        return (StatusCode::BAD_REQUEST, "client_id and fcm_token required").into_response();
    }
    state.push_tokens.insert(payload.client_id.clone(), payload.fcm_token);
    info!("📲 Registered FCM push token for client {}", payload.client_id);
    StatusCode::OK.into_response()
}
