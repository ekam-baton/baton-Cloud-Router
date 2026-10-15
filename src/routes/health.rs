use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use std::sync::Arc;
use crate::state::AppState;

pub async fn health_handler(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok","service":"cloud-router"}))).into_response()
}
