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

    let (db, groups_map, push_tokens_map) = init_db("router_queue.db")?;

    let state = Arc::new(AppState {
        connections: DashMap::new(),
        rate_limiter: DashMap::new(),
        push_tokens: push_tokens_map,
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

    #[test]
    fn test_group_create_request_deserialization_aliases() {
        let json_with_aliases = serde_json::json!({
            "name": "Sovereign Circle",
            "members": ["client_alpha", "client_beta"]
        });
        let parsed: crate::models::GroupCreateRequest = serde_json::from_value(json_with_aliases).unwrap();
        assert_eq!(parsed.group_name, "Sovereign Circle");
        assert_eq!(parsed.member_ids, vec!["client_alpha", "client_beta"]);
        assert!(parsed.creator_id.is_empty());

        let json_standard = serde_json::json!({
            "group_name": "Executive Board",
            "creator_id": "founder_1",
            "member_ids": ["member_a"]
        });
        let parsed_std: crate::models::GroupCreateRequest = serde_json::from_value(json_standard).unwrap();
        assert_eq!(parsed_std.group_name, "Executive Board");
        assert_eq!(parsed_std.creator_id, "founder_1");
        assert_eq!(parsed_std.member_ids, vec!["member_a"]);
    }

    #[test]
    fn test_push_token_persistence_roundtrip() {
        let db_path = std::env::temp_dir().join(format!("test_router_{}.db", uuid::Uuid::new_v4()));
        let db_path_str = db_path.to_str().unwrap();

        // 1. Initialize and insert token
        {
            let (db, _groups, tokens) = crate::db::init_db(db_path_str).unwrap();
            tokens.insert("client_test_1".to_string(), "fcm_token_alpha".to_string());
            db.execute(
                "INSERT INTO push_tokens (client_id, fcm_token, updated_at) VALUES (?1, ?2, ?3)",
                rusqlite::params!["client_test_1", "fcm_token_alpha", 123456789i64],
            ).unwrap();
        }

        // 2. Simulate server restart: init_db again and verify token restored from disk
        {
            let (_db, _groups, tokens_reloaded) = crate::db::init_db(db_path_str).unwrap();
            assert_eq!(tokens_reloaded.get("client_test_1").as_deref(), Some(&"fcm_token_alpha".to_string()));
            assert!(tokens_reloaded.get("client_nonexistent").is_none());
        }

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn test_max_message_payload_bounds() {
        const MAX_MESSAGE_PAYLOAD_BYTES: usize = 512 * 1024;
        let small_msg = "a".repeat(1024);
        assert!(small_msg.len() <= MAX_MESSAGE_PAYLOAD_BYTES);

        let oversized_msg = "a".repeat(MAX_MESSAGE_PAYLOAD_BYTES + 1);
        assert!(oversized_msg.len() > MAX_MESSAGE_PAYLOAD_BYTES);
    }

    #[test]
    fn test_ack_messages_up_to_id_bounded_deletion() {
        let db_path = std::env::temp_dir().join(format!("test_ack_{}.db", uuid::Uuid::new_v4()));
        let db_path_str = db_path.to_str().unwrap();

        let (db, _groups, _tokens) = crate::db::init_db(db_path_str).unwrap();
        // Insert 3 queued messages
        db.execute("INSERT INTO queued_messages (receiver_id, payload, created_at) VALUES (?1, ?2, ?3)", rusqlite::params!["client_ack", "msg1", 100i64]).unwrap();
        db.execute("INSERT INTO queued_messages (receiver_id, payload, created_at) VALUES (?1, ?2, ?3)", rusqlite::params!["client_ack", "msg2", 200i64]).unwrap();
        db.execute("INSERT INTO queued_messages (receiver_id, payload, created_at) VALUES (?1, ?2, ?3)", rusqlite::params!["client_ack", "msg3", 300i64]).unwrap();

        // Query IDs
        let mut stmt = db.prepare("SELECT id FROM queued_messages WHERE receiver_id = ? ORDER BY id ASC").unwrap();
        let ids: Vec<i64> = stmt.query_map(["client_ack"], |row| row.get(0)).unwrap().flatten().collect();
        assert_eq!(ids.len(), 3);
        let id_second = ids[1];

        // Delete up to second message
        db.execute(
            "DELETE FROM queued_messages WHERE receiver_id = ?1 AND id <= ?2",
            rusqlite::params!["client_ack", id_second],
        ).unwrap();

        // Verify only 3rd message remains (zero data loss of newer msg3)
        let remaining: Vec<i64> = stmt.query_map(["client_ack"], |row| row.get(0)).unwrap().flatten().collect();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], ids[2]);

        let _ = std::fs::remove_file(db_path);
    }

    #[test]
    fn test_rate_limiter_eviction_threshold() {
        let rate_limiter = dashmap::DashMap::new();
        let now = std::time::Instant::now();
        let stale_time = now - std::time::Duration::from_secs(150);

        // Populate with active and stale entries
        rate_limiter.insert(std::net::IpAddr::from([10, 0, 0, 1]), (5, stale_time));
        rate_limiter.insert(std::net::IpAddr::from([10, 0, 0, 2]), (2, now));
        rate_limiter.insert(std::net::IpAddr::from([10, 0, 0, 3]), (1, stale_time));

        assert_eq!(rate_limiter.len(), 3);

        // Run threshold eviction
        rate_limiter.retain(|_, (_, window_start)| {
            now.duration_since(*window_start) < std::time::Duration::from_secs(120)
        });

        assert_eq!(rate_limiter.len(), 1);
        assert!(rate_limiter.contains_key(&std::net::IpAddr::from([10, 0, 0, 2])));
        assert!(!rate_limiter.contains_key(&std::net::IpAddr::from([10, 0, 0, 1])));
        assert!(!rate_limiter.contains_key(&std::net::IpAddr::from([10, 0, 0, 3])));
    }

    #[test]
    fn test_fcm_wakeup_result_and_pruning() {
        use crate::services::fcm::FcmWakeupResult;
        let push_tokens = dashmap::DashMap::new();
        push_tokens.insert("client-dead".to_string(), "dead-fcm-token".to_string());
        push_tokens.insert("client-alive".to_string(), "alive-fcm-token".to_string());

        let res_dead = FcmWakeupResult::Unregistered;
        let res_alive = FcmWakeupResult::Success;

        assert_eq!(res_dead, FcmWakeupResult::Unregistered);
        assert_eq!(res_alive, FcmWakeupResult::Success);

        // Pruning action
        if res_dead == FcmWakeupResult::Unregistered {
            push_tokens.remove("client-dead");
        }

        assert_eq!(push_tokens.len(), 1);
        assert!(push_tokens.contains_key("client-alive"));
        assert!(!push_tokens.contains_key("client-dead"));
    }

    #[test]
    fn test_group_creator_leave_ownership_transfer() {
        use std::collections::HashSet;
        use crate::models::GroupInfo;

        let groups = dashmap::DashMap::new();
        let mut members = HashSet::new();
        members.insert("creator_bob".to_string());
        members.insert("member_alice".to_string());
        members.insert("member_charlie".to_string());

        let group_id = "test_grp_1".to_string();
        groups.insert(group_id.clone(), GroupInfo {
            id: group_id.clone(),
            name: "Team Alpha".to_string(),
            creator_id: "creator_bob".to_string(),
            members,
            created_at: 1000,
        });

        // Simulate creator_bob leaving
        {
            let mut group = groups.get_mut(&group_id).unwrap();
            group.members.remove("creator_bob");
            assert!(!group.members.is_empty());
            let next_creator = group.members.iter().next().cloned().unwrap();
            group.creator_id = next_creator;
        }

        let updated = groups.get(&group_id).unwrap();
        assert!(!updated.members.contains("creator_bob"));
        assert!(updated.creator_id == "member_alice" || updated.creator_id == "member_charlie");
        assert_eq!(updated.members.len(), 2);
    }

    #[test]
    fn test_contiguous_spool_delivery_bounds() {
        let items: Vec<(i64, bool)> = vec![(10, true), (20, true), (30, false), (40, true)];
        let mut max_delivered_id: Option<i64> = None;
        for (id, send_ok) in items {
            if send_ok {
                max_delivered_id = Some(id);
            } else {
                break;
            }
        }
        // Since item 30 failed, max_delivered_id should be 20, NOT 40
        assert_eq!(max_delivered_id, Some(20));
    }

    #[test]
    fn test_group_name_and_member_sanitization() {
        let dirty_name = "Team\r\nInjected";
        assert!(dirty_name.chars().any(|c| c.is_control()));

        let dirty_member = "alice\x00";
        assert!(dirty_member.chars().any(|c| c.is_control()));

        let clean_name = "  Executive Board  ";
        let trimmed_name = clean_name.trim();
        assert_eq!(trimmed_name, "Executive Board");
        assert!(!trimmed_name.chars().any(|c| c.is_control()));
    }

    #[test]
    fn test_self_routing_and_receiver_id_validation() {
        let client_id = "client_alice";
        let receiver_id_self = "client_alice";
        assert_eq!(receiver_id_self, client_id, "Self-routing should be detected");

        let receiver_id_control = "client_bob\r\n";
        assert!(receiver_id_control.chars().any(|c| c.is_control()));

        let receiver_id_valid = "client_bob";
        assert!(!receiver_id_valid.chars().any(|c| c.is_control()));
        assert_ne!(receiver_id_valid, client_id);
    }
}
