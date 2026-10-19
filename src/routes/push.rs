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

    let client_id = payload.client_id.trim();
    let fcm_token = payload.fcm_token.trim();

    if client_id.is_empty() || client_id.len() > 128 || client_id.chars().any(|c| c.is_control()) ||
       fcm_token.is_empty() || fcm_token.len() > 4096 || fcm_token.chars().any(|c| c.is_control()) {
        return (StatusCode::BAD_REQUEST, "Invalid client_id or fcm_token bounds").into_response();
    }
    let client_id_str = client_id.to_string();
    let fcm_token_str = fcm_token.to_string();
    state.push_tokens.insert(client_id_str.clone(), fcm_token_str.clone());

    let state_clone = state.clone();
    tokio::spawn(async move {
        let db = state_clone.db.lock().await;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
        let res = db.execute(
            "INSERT INTO push_tokens (client_id, fcm_token, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(client_id) DO UPDATE SET fcm_token = excluded.fcm_token, updated_at = excluded.updated_at",
            rusqlite::params![client_id_str, fcm_token_str, now],
        );
        if let Err(e) = res {
            tracing::error!("Failed to persist push token for client {}: {}", client_id_str, e);
        }
    });

    info!("📲 Registered FCM push token for client {}", client_id);
    StatusCode::OK.into_response()
}
