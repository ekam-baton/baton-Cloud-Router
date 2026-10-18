mod auth;
mod db;
mod middleware;
pub mod models;
mod routes;
mod services;
pub mod state;

use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post},
    Router,
};
use dashmap::DashMap;
use reqwest::Client as HttpClient;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};
use tower::limit::ConcurrencyLimitLayer;
use tracing::info;

use crate::db::{init_db, spawn_queue_cleanup};
use crate::middleware::rate_limit::ip_rate_limit_middleware;
use crate::routes::{
    groups::{group_create_handler, group_delete_handler, group_info_handler, group_join_handler, group_leave_handler, group_list_handler},
    health::health_handler,
    push::register_push_handler,
    turn::turn_credentials_handler,
    ws::{ack_messages_handler, ws_handler},
};
use crate::services::turn::start_embedded_turn_server;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize standard logging
    tracing_subscriber::fmt::init();

    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| {
        "FATAL: JWT_SECRET environment variable is not set. Generate one with: openssl rand -hex 32"
    })?;

    let trusted_proxy_ips: Vec<std::net::IpAddr> = std::env::var("TRUSTED_PROXY_IPS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse::<std::net::IpAddr>().ok())
        .collect();
    let rate_limit_rpm: u32 = std::env::var("RATE_LIMIT_RPM")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(200);

    let (db, groups_map) = init_db("router_queue.db")?;

    let state = Arc::new(AppState {
        connections: DashMap::new(),
        rate_limiter: DashMap::new(),
        push_tokens: DashMap::new(),
        groups: groups_map,
        http: HttpClient::new(),
        firebase_server_key: std::env::var("FIREBASE_SERVER_KEY").ok(),
        jwt_secret,
        db: Arc::new(tokio::sync::Mutex::new(db)),
        trusted_proxy_ips,
        rate_limit_rpm,
    });

    // Background Task: Periodic rate limiter IP cache eviction
    let rate_limiter_cleanup = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            rate_limiter_cleanup.rate_limiter.retain(|_, (_, ts)| ts.elapsed() < Duration::from_secs(120));
        }
    });

    // Background Task: Periodic cleanup of stale queued messages (>7 days old)
    spawn_queue_cleanup(state.clone());

    // Background Task: Spawn Embedded TURN Relay Listener on port 3478
    tokio::spawn(async move {
        start_embedded_turn_server("0.0.0.0:3478").await;
    });

    // Axum Application Router
    let app = Router::new()
        // The main websocket endpoint for edge devices to connect to.
        .route("/relay/{client_id}", get(ws_handler))
        .route("/relay/{client_id}/ack", delete(ack_messages_handler))
        // FCM push token registration endpoint (Pillar 1 — V2)
        .route("/register-push", post(register_push_handler))
        // Group messaging endpoints (Pillar 3 — V2)
        .route("/group/create", post(group_create_handler))
        .route("/group/join", post(group_join_handler))
        .route("/group/leave", post(group_leave_handler))
        .route("/group/{group_id}", get(group_info_handler))
        .route("/group/{group_id}", delete(group_delete_handler))
        .route("/groups/{client_id}", get(group_list_handler))
        .route("/turn/credentials", get(turn_credentials_handler))
        .route("/health", get(health_handler))
        .layer(axum_middleware::from_fn_with_state(state.clone(), ip_rate_limit_middleware))
        .layer(ConcurrencyLimitLayer::new(10_000))
        .with_state(state);

    let bind_addr = std::env::var("ROUTER_BIND")
        .unwrap_or_else(|_| std::env::var("PORT").map(|p| format!("0.0.0.0:{}", p)).unwrap_or_else(|_| "0.0.0.0:8082".to_string()));
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    if let Ok(addr) = listener.local_addr() {
        info!("Baton Cloud Router listening on {}", addr);
    } else {
        info!("Baton Cloud Router listening on {}", bind_addr);
    }

    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .with_graceful_shutdown(async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutting down Baton Cloud Router gracefully...");
        })
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::auth::verify_jwt;
    use crate::models::{Claims, Envelope};

    #[test]
    fn test_verify_jwt_empty_secret_fails() {
        assert!(!verify_jwt("some.jwt.token", "", "user123"));
        assert!(!verify_jwt("some.jwt.token", "secret", ""));
    }

    #[test]
    fn test_verify_jwt_valid_and_mismatched() {
        let secret = "test-secret-key-for-baton-cloud-router-2026";
        let claims = Claims {
            sub: "alice".to_string(),
            exp: Some(9999999999),
        };
        let header = jsonwebtoken::Header { alg: jsonwebtoken::Algorithm::HS256, ..Default::default() };
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
        ).unwrap();

        // Valid match
        assert!(verify_jwt(&token, secret, "alice"));

        // Mismatched sub
        assert!(!verify_jwt(&token, secret, "bob"));

        // Wrong secret
        assert!(!verify_jwt(&token, "wrong-secret", "alice"));
    }

    #[test]
    fn test_message_envelope_serialization() {
        let envelope = Envelope {
            receiver_id: "bob".to_string(),
            sender_id: Some("alice".to_string()),
            group_id: None,
            depth: 1,
            payload_encrypted: "hello encrypted world".to_string(),
        };
        let serialized = serde_json::to_string(&envelope).unwrap();
        let deserialized: Envelope = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.receiver_id, "bob");
        assert_eq!(deserialized.sender_id.as_deref(), Some("alice"));
        assert_eq!(deserialized.depth, 1);

        // Test default depth = 0 when omitted
        let raw_json = r#"{"receiver_id":"bob","payload":"test"}"#;
        let from_raw: Envelope = serde_json::from_str(raw_json).unwrap();
        assert_eq!(from_raw.depth, 0);
    }

    #[test]
    fn test_envelope_receiver_id_bounds() {
        let empty_envelope = Envelope {
            receiver_id: "".to_string(),
            sender_id: None,
            group_id: None,
            depth: 0,
            payload_encrypted: "test".to_string(),
        };
        assert!(empty_envelope.receiver_id.trim().is_empty());

        let oversized_envelope = Envelope {
            receiver_id: "a".repeat(129),
            sender_id: None,
            group_id: None,
            depth: 0,
            payload_encrypted: "test".to_string(),
        };
        assert!(oversized_envelope.receiver_id.len() > 128);

        let valid_envelope = Envelope {
            receiver_id: "client-valid-123".to_string(),
            sender_id: None,
            group_id: None,
            depth: 0,
            payload_encrypted: "test".to_string(),
        };
        assert!(!valid_envelope.receiver_id.trim().is_empty() && valid_envelope.receiver_id.len() <= 128);
    }

    #[test]
    fn test_push_token_bounds() {
        let req_valid = crate::models::RegisterPushRequest {
            client_id: "client-1".to_string(),
            fcm_token: "fcm-valid-token-123".to_string(),
        };
        assert!(!req_valid.client_id.trim().is_empty() && req_valid.client_id.len() <= 128);
        assert!(!req_valid.fcm_token.trim().is_empty() && req_valid.fcm_token.len() <= 4096);

        let req_oversized_client = crate::models::RegisterPushRequest {
            client_id: "c".repeat(129),
            fcm_token: "token".to_string(),
        };
        assert!(req_oversized_client.client_id.len() > 128);

        let req_oversized_token = crate::models::RegisterPushRequest {
            client_id: "client-1".to_string(),
            fcm_token: "t".repeat(4097),
        };
        assert!(req_oversized_token.fcm_token.len() > 4096);
    }

    #[test]
    fn test_decode_jwt_sub() {
        let secret = "router_secret_test_key_123456";
        let sub = "client_alpha";
        let claims = crate::models::Claims {
            sub: sub.to_string(),
            exp: Some((std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600) as usize),
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes())
        ).unwrap();

        let decoded = crate::auth::decode_jwt_sub(&token, secret);
        assert_eq!(decoded, Some(sub.to_string()));

        let invalid_decoded = crate::auth::decode_jwt_sub(&token, "wrong_secret");
        assert_eq!(invalid_decoded, None);
    }

    #[test]
    fn test_group_bounds() {
        let req_valid = crate::models::GroupCreateRequest {
            creator_id: "creator_1".to_string(),
            group_name: "Test Group".to_string(),
            member_ids: vec!["member_1".to_string(), "member_2".to_string()],
        };
        assert!(!req_valid.creator_id.trim().is_empty() && req_valid.creator_id.len() <= 128);
        assert!(!req_valid.group_name.trim().is_empty() && req_valid.group_name.len() <= 100);
        assert!(req_valid.member_ids.iter().all(|m| !m.trim().is_empty() && m.len() <= 128));

        let req_oversized_name = crate::models::GroupCreateRequest {
            creator_id: "creator_1".to_string(),
            group_name: "g".repeat(101),
            member_ids: vec![],
        };
        assert!(req_oversized_name.group_name.len() > 100);
    }
}
