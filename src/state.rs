use axum::extract::ws::Message;
use dashmap::DashMap;
use reqwest::Client as HttpClient;
use std::{
    net::IpAddr,
    sync::Arc,
    time::Instant,
};
use tokio::sync::mpsc;
use crate::models::GroupInfo;

// The shared state tracking all active websocket connections and rate limiting metrics.
pub struct AppState {
    // Maps a client_id (like a phone's public key) to a Sender channel and connection UUID.
    pub connections: DashMap<String, (mpsc::Sender<Message>, String)>,
    // IP Rate Limiter: IpAddr -> (request_count, window_start_time)
    pub rate_limiter: DashMap<IpAddr, (u32, Instant)>,
    // FCM Push Token Registry: client_id -> FCM registration token (Pillar 1 — V2)
    pub push_tokens: DashMap<String, String>,
    // Group Membership Registry: group_id -> GroupInfo (Pillar 3 — V2)
    pub groups: DashMap<String, GroupInfo>,
    // Shared HTTP client for FCM API calls
    pub http: HttpClient,
    // Firebase Server Key (set via FIREBASE_SERVER_KEY env var)
    pub firebase_server_key: Option<String>,
    pub jwt_secret: String,
    pub db: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
}
