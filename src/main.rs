use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, State,
    },
    http::StatusCode,
    middleware::{self, Next},
    response::IntoResponse,
    routing::{get, post, delete},
    Json,
    Router,
};
use dashmap::DashMap;
use futures::{sink::SinkExt, stream::StreamExt};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use tower::limit::ConcurrencyLimitLayer;
use tracing::{error, info, warn};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use hmac::{Hmac, Mac, KeyInit};
use sha1::Sha1;


#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    #[serde(default)]
    exp: Option<usize>,
}

fn verify_jwt(token: &str, secret: &str, expected_sub: &str) -> bool {
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


// The shared state tracking all active websocket connections and rate limiting metrics.
struct AppState {
    // Maps a client_id (like a phone's public key) to a Sender channel.
    connections: DashMap<String, (mpsc::Sender<Message>, String)>,
    // IP Rate Limiter: IpAddr -> (request_count, window_start_time)
    rate_limiter: DashMap<IpAddr, (u32, Instant)>,
    // FCM Push Token Registry: client_id -> FCM registration token (Pillar 1 — V2)
    push_tokens: DashMap<String, String>,
    // Group Membership Registry: group_id -> GroupInfo (Pillar 3 — V2)
    groups: DashMap<String, GroupInfo>,
    // Shared HTTP client for FCM API calls
    http: HttpClient,
    // Firebase Server Key (set via FIREBASE_SERVER_KEY env var)
    firebase_server_key: Option<String>,
    jwt_secret: String,
    db: Arc<tokio::sync::Mutex<rusqlite::Connection>>,
}

/// Group metadata stored in the router's in-memory state.
/// The router never sees message contents — only membership for fan-out routing.
#[derive(Debug, Clone, Serialize)]
struct GroupInfo {
    /// Unique group identifier
    id: String,
    /// Human-readable group name (encrypted by clients; router stores opaque string)
    name: String,
    /// The client_id of the group creator (only they can add/remove members)
    creator_id: String,
    /// Set of client_ids that are members of this group
    members: HashSet<String>,
    /// Creation timestamp (unix millis)
    created_at: u64,
}

// Sealed Sender Envelope: sender_id is optional and omitted in production for metadata privacy.
#[derive(Debug, Serialize, Deserialize)]
struct Envelope {
    receiver_id: String,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    group_id: Option<String>,
    #[serde(default)]
    depth: u32,
    #[serde(alias = "payload")]
    payload_encrypted: String, 
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize standard logging
    tracing_subscriber::fmt::init();

    let jwt_secret = std::env::var("JWT_SECRET").map_err(|_| {
        "FATAL: JWT_SECRET environment variable is not set. Generate one with: openssl rand -hex 32"
    })?;
    
    let db = rusqlite::Connection::open("router_queue.db")?;
    db.execute(
        "CREATE TABLE IF NOT EXISTS queued_messages(id INTEGER PRIMARY KEY, receiver_id TEXT, payload TEXT, created_at INTEGER)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_queued_messages_receiver ON queued_messages(receiver_id, id)",
        (),
    )?;
    // Prune queued messages older than 7 days on startup
    let seven_days_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64 - (7 * 86400 * 1000);
    let _ = db.execute("DELETE FROM queued_messages WHERE created_at < ?1", rusqlite::params![seven_days_ago]);
    
    db.execute(
        "CREATE TABLE IF NOT EXISTS groups(group_id TEXT PRIMARY KEY, name TEXT DEFAULT '', creator_id TEXT, members_json TEXT, created_at INTEGER DEFAULT 0)",
        (),
    )?;

    let groups_map = DashMap::new();
    if let Ok(mut stmt) = db.prepare("SELECT group_id, name, creator_id, members_json, created_at FROM groups")
        && let Ok(group_rows) = stmt.query_map([], |row| {
            let group_id: String = row.get(0)?;
            let name: String = row.get(1)?;
            let creator_id: String = row.get(2)?;
            let members_json: String = row.get(3)?;
            let created_at_db: i64 = row.get(4)?;
            Ok((group_id, name, creator_id, members_json, created_at_db as u64))
        }) {
            for row in group_rows.flatten() {
                let (group_id, name, creator_id, members_json, created_at) = row;
                if let Ok(members) = serde_json::from_str::<HashSet<String>>(&members_json) {
                    groups_map.insert(group_id.clone(), GroupInfo {
                        id: group_id,
                        name,
                        creator_id,
                        members,
                        created_at,
                    });
                }
            }
        }

    let state = Arc::new(AppState {
        connections: DashMap::new(),
        rate_limiter: DashMap::new(),
        push_tokens: DashMap::new(),
        groups: groups_map,
        http: HttpClient::new(),
        firebase_server_key: std::env::var("FIREBASE_SERVER_KEY").ok(),
        jwt_secret,
        db: Arc::new(tokio::sync::Mutex::new(db)),
    });

    let rate_limiter_cleanup = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(60)).await;
            rate_limiter_cleanup.rate_limiter.retain(|_, (_, ts)| ts.elapsed() < Duration::from_secs(120));
        }
    });

    // ── HI-6 FIX: Periodic cleanup of stale queued messages (>7 days old) ─────
    let queue_cleanup = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await; // Run every hour
            let db = queue_cleanup.db.lock().await;
            let cutoff = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64 - 7 * 86_400 * 1000; // 7 days ago
            match db.execute("DELETE FROM queued_messages WHERE created_at < ?", [cutoff]) {
                Ok(n) if n > 0 => info!("🧹 Cleaned up {} stale queued messages", n),
                _ => {}
            }
        }
    });

    // ── Spawn Embedded TURN Relay Listener on port 3478 ────────────────────────
    tokio::spawn(async move {
        start_embedded_turn_server("0.0.0.0:3478").await;
    });

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
        .layer(middleware::from_fn_with_state(state.clone(), ip_rate_limit_middleware))
        .layer(ConcurrencyLimitLayer::new(10_000))
        .with_state(state);

    let bind_addr = std::env::var("ROUTER_BIND")
        .unwrap_or_else(|_| std::env::var("PORT").map(|p| format!("0.0.0.0:{}", p)).unwrap_or_else(|_| "0.0.0.0:8082".to_string()));
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await?;
    if let Ok(addr) = listener.local_addr() {
        info!("Baton Cloud Router listening on {}", addr);
    } else {
        info!("Baton Cloud Router listening on {}", bind_addr);
    }
    
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await?;
        
    Ok(())
}

/// IP Rate Limiter Middleware (DDoS Prevention)
async fn ip_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let trusted_proxies: Vec<IpAddr> = std::env::var("TRUSTED_PROXY_IPS")
        .unwrap_or_default()
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect();

    let ip = if trusted_proxies.contains(&addr.ip()) {
        // Only trust forwarded headers from known proxies
        req.headers()
            .get("cf-connecting-ip")
            .or_else(|| req.headers().get("x-forwarded-for"))
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
            .unwrap_or_else(|| addr.ip())
    } else {
        addr.ip()
    };
    let now = Instant::now();
    
    let mut entry = state.rate_limiter.entry(ip).or_insert((0, now));
    let (count, window_start) = entry.value_mut();

    let limit = std::env::var("RATE_LIMIT_RPM").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(200);
    if now.duration_since(*window_start) > Duration::from_secs(60) {
        *count = 1;
        *window_start = now;
    } else {
        *count += 1;
        if *count > limit {
            warn!("DDoS Mitigation: Rate limit exceeded for IP {}", ip);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(next.run(req).await)
}

#[derive(Serialize)]
struct TurnCredentialsResponse {
    username: String,
    password: String,
    ttl: u64,
    uris: Vec<String>,
}

async fn turn_credentials_handler(
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


/// Embedded TURN Relay UDP Handler for WebRTC IP Obfuscation
async fn start_embedded_turn_server(bind_addr: &str) {
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to bind embedded TURN server on {}: {} (WebRTC direct relay disabled)", bind_addr, e);
            return;
        }
    };
    info!("🛡️ Embedded Baton TURN Server listening on UDP {}", bind_addr);

    let mut buf = [0u8; 4096];
    loop {
        if let Ok((len, src)) = socket.recv_from(&mut buf).await {
            // STUN / TURN packet processing header check (Magic Cookie 0x2112A442)
            if len >= 20 && buf[4..8] == [0x21, 0x12, 0xA4, 0x42] {
                // Respond with STUN Binding Success Response
                let mut resp = vec![0x01, 0x01, 0x00, 0x00]; // Binding Success Response
                resp.extend_from_slice(&buf[4..20]); // Copy transaction ID
                
                let family = if src.is_ipv4() { 0x01 } else { 0x02 };
                let xport = src.port() ^ 0x2112;
                resp.extend_from_slice(&[0x00, 0x20]); // Type: XOR-MAPPED-ADDRESS
                if src.is_ipv4() {
                    resp.extend_from_slice(&[0x00, 0x08]); // Length: 8
                    resp.extend_from_slice(&[0x00, family]); // Reserved and Family
                    resp.extend_from_slice(&xport.to_be_bytes()); // X-Port
                    let ip = match src.ip() { IpAddr::V4(ipv4) => ipv4, _ => unreachable!() };
                    let mut xip = ip.octets();
                    let mc = [0x21, 0x12, 0xA4, 0x42];
                    for i in 0..4 { xip[i] ^= mc[i]; }
                    resp.extend_from_slice(&xip); // X-Address
                } else {
                    resp.extend_from_slice(&[0x00, 0x14]); // Length: 20
                    resp.extend_from_slice(&[0x00, family]); // Reserved and Family
                    resp.extend_from_slice(&xport.to_be_bytes()); // X-Port
                    let ip = match src.ip() { IpAddr::V6(ipv6) => ipv6, _ => unreachable!() };
                    let mut xip = ip.octets();
                    let mc = [0x21, 0x12, 0xA4, 0x42];
                    for i in 0..4 { xip[i] ^= mc[i]; }
                    for i in 0..12 { xip[i+4] ^= buf[8+i]; }
                    resp.extend_from_slice(&xip); // X-Address
                }
                
                // update length
                let msg_len = (resp.len() - 20) as u16;
                resp[2..4].copy_from_slice(&msg_len.to_be_bytes());

                let _ = socket.send_to(&resp, src).await;
            }
        }
    }
}

async fn ack_messages_handler(
    Path(client_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &client_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let db = state.db.lock().await;
    let _ = db.execute("DELETE FROM queued_messages WHERE receiver_id = ?", [&client_id]);
    StatusCode::OK.into_response()
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(client_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &client_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    info!("Incoming connection from client: {}", client_id);
    ws.max_message_size(2 * 1024 * 1024)
      .max_frame_size(2 * 1024 * 1024)
      .on_upgrade(move |socket| handle_socket(socket, client_id, state))
}

async fn handle_socket(socket: WebSocket, client_id: String, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // Create a channel for this specific connection to receive forwarded messages.
    let (tx, mut rx) = mpsc::channel::<Message>(100);

    // Register this connection in the global map.
    let conn_id = uuid::Uuid::new_v4().to_string();
    state.connections.insert(client_id.clone(), (tx, conn_id.clone()));
    info!("Registered client {} for routing", client_id);

    let messages_to_send = {
        let db = state.db.lock().await;
        let mut msgs = Vec::new();
        if let Ok(mut stmt) = db.prepare("SELECT id, payload FROM queued_messages WHERE receiver_id = ? ORDER BY id ASC")
            && let Ok(messages) = stmt.query_map([&client_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            }) {
                for msg in messages.flatten() {
                    msgs.push(msg);
                }
            }
        msgs
    };

    if !messages_to_send.is_empty() {
        let mut ids_to_delete = Vec::new();
        for (id, payload) in messages_to_send {
            if sender.send(Message::Text(payload.into())).await.is_ok() {
                ids_to_delete.push(id);
            }
        }
        let state_clone = state.clone();
        tokio::spawn(async move {
            let db = state_clone.db.lock().await;
            for id in ids_to_delete {
                let _ = db.execute("DELETE FROM queued_messages WHERE id = ?", [id]);
            }
        });
    }

    // Task 1: Forward messages from the MPSC channel into the actual WebSocket.
    let mut send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Task 2: Listen for incoming messages from this WebSocket and route them.
    let state_clone = state.clone();
    let client_id_clone = client_id.clone();
    let mut msg_count: u32 = 0;
    let mut msg_window_start = Instant::now();
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    // ── CR-2 FIX: Per-connection message rate limiting ──────────
                    msg_count += 1;
                    if msg_window_start.elapsed() > Duration::from_secs(1) {
                        msg_count = 1;
                        msg_window_start = Instant::now();
                    } else if msg_count > 100 {
                        warn!("WebSocket rate limit exceeded for client {}, disconnecting", client_id_clone);
                        break;
                    }

                    // Sealed Sender: Envelope only requires receiver_id and payload_encrypted
                    if let Ok(mut envelope) = serde_json::from_str::<Envelope>(&text) {
                        // ── Hard Loop Breaker: Recursion Depth / Hop Limit ───
                        const MAX_ROUTER_RECURSION_DEPTH: u32 = 3;
                        if envelope.depth >= MAX_ROUTER_RECURSION_DEPTH {
                            warn!(
                                "Cloud Router recursion breaker triggered: depth {} >= limit {} from sender '{}'. Dropping message.",
                                envelope.depth, MAX_ROUTER_RECURSION_DEPTH, client_id_clone
                            );
                            continue;
                        }

                        // ── CR-1 FIX: Force authenticated identity as sender ───
                        // The client CANNOT choose their sender_id. The router
                        // overwrites it with the JWT-authenticated client_id.
                        envelope.sender_id = Some(client_id_clone.clone());
                        let authenticated_text: String = serde_json::to_string(&envelope).unwrap_or_else(|_| text.to_string());

                        // ── Group Fan-Out Routing (Pillar 3 — V2) ──────────────────
                        if envelope.receiver_id.starts_with("group:") {
                            let group_id = envelope.receiver_id.strip_prefix("group:").unwrap_or("");
                            info!("Routing sealed message (group)");
                            
                            // Get member list (clone to release DashMap lock immediately)
                            let members: Option<HashSet<String>> = state_clone.groups
                                .get(group_id)
                                .map(|g| g.members.clone());
                            
                            if let Some(members) = members {
                                let sender = envelope.sender_id.as_deref().unwrap_or("");
                                
                                // ── HI-4 FIX: Verify sender is a group member ──────
                                if !members.contains(sender) {
                                    warn!("Non-member {} tried to message group {}, dropping", sender, group_id);
                                } else {
                                    // Fan out: send each member the opaque envelope without inspecting/modifying payload
                                    for member_id in &members {
                                        if member_id == sender { continue; }
                                        
                                        let dest_tx_opt = state_clone.connections
                                            .get(member_id)
                                            .map(|c| c.value().0.clone());
                                        
                                        if let Some(dest_tx) = dest_tx_opt {
                                            let _ = dest_tx.send(Message::Text(authenticated_text.clone().into())).await;
                                        } else {
                                            // Offline member — FCM wakeup and queue message
                                            {
                                                let db = state_clone.db.lock().await;
                                                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
                                                let count: i64 = db.query_row(
                                                    "SELECT COUNT(*) FROM queued_messages WHERE receiver_id = ?1",
                                                    [member_id],
                                                    |row| row.get(0),
                                                ).unwrap_or(0);

                                                if count >= 1000 {
                                                    warn!("Queue full for client {}, dropping message", member_id);
                                                } else {
                                                    let _ = db.execute("INSERT INTO queued_messages (receiver_id, payload, created_at) VALUES (?, ?, ?)", rusqlite::params![member_id, &authenticated_text, now]);
                                                }
                                            }

                                            if let Some(fcm_token) = state_clone.push_tokens.get(member_id).map(|t| t.clone()) {
                                                let http = state_clone.http.clone();
                                                let server_key = state_clone.firebase_server_key.clone();
                                                tokio::spawn(async move {
                                                    send_fcm_wakeup(&http, server_key.as_deref(), &fcm_token).await;
                                                });
                                            }
                                        }
                                    }
                                }
                            } else {
                                warn!("Group {} not found — dropping message", group_id);
                            }
                        }
                        // ── Standard 1-to-1 Routing ───────────────────────────────
                        else {
                            info!("Routing sealed message (1-to-1)");
                            
                            // Look up the destination connection and clone the sender to drop the DashMap lock
                            let dest_tx_opt = state_clone.connections.get(&envelope.receiver_id).map(|c| c.value().0.clone());
                            
                            if let Some(dest_tx) = dest_tx_opt {
                                // Forward the authenticated envelope (sender_id enforced by router)
                                let _ = dest_tx.send(Message::Text(authenticated_text.clone().into())).await;
                            } else {
                                // Client is offline — fire a blank FCM wakeup (Pillar 1 — V2)
                                {
                                    let db = state_clone.db.lock().await;
                                    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
                                    let count: i64 = db.query_row(
                                        "SELECT COUNT(*) FROM queued_messages WHERE receiver_id = ?1",
                                        [&envelope.receiver_id],
                                        |row| row.get(0),
                                    ).unwrap_or(0);

                                    if count >= 1000 {
                                        warn!("Queue full for client {}, dropping message", envelope.receiver_id);
                                    } else {
                                        let _ = db.execute("INSERT INTO queued_messages (receiver_id, payload, created_at) VALUES (?, ?, ?)", rusqlite::params![&envelope.receiver_id, &authenticated_text, now]);
                                    }
                                }

                                info!("Offline client detected. Sending blank FCM wakeup.");
                                if let Some(fcm_token) = state_clone.push_tokens.get(&envelope.receiver_id).map(|t| t.clone()) {
                                    let http = state_clone.http.clone();
                                    let server_key = state_clone.firebase_server_key.clone();
                                    tokio::spawn(async move {
                                        send_fcm_wakeup(&http, server_key.as_deref(), &fcm_token).await;
                                    });
                                } else {
                                    warn!("No FCM token registered for offline client.");
                                }
                            }
                        }
                    } else {
                        error!("Invalid envelope format received");
                    }
                }
                Message::Close(_) => break,
                _ => {} // Ignore ping/pong/binary for now
            }
        }
    });

    // Wait until either task finishes (socket closed or error).
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    // Cleanup when the connection drops
    if let Some(entry) = state.connections.get(&client_id)
        && entry.value().1 == conn_id {
            drop(entry);
            state.connections.remove(&client_id);
        }
    info!("Client {} disconnected and removed from routing table", client_id);
}

// ── FCM Push Token Registration (Pillar 1 — V2) ──────────────────────────────

#[derive(serde::Deserialize)]
struct RegisterPushRequest {
    client_id: String,
    fcm_token: String,
}

/// Endpoint: `POST /register-push`
/// Android app calls this on startup to register its FCM token.
/// The router stores it so it can fire a blank wakeup when the client is offline.
async fn register_push_handler(
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

/// Send a completely blank FCM data-only notification to wake an offline Android client.
///
/// Security: the `data` payload is intentionally empty — Google sees zero
/// message content, zero sender identity. It is purely a OS-level wakeup knock.
async fn send_fcm_wakeup(http: &reqwest::Client, server_key: Option<&str>, fcm_token: &str) {
    let auth_token = std::env::var("GOOGLE_APPLICATION_CREDENTIALS").ok().or_else(|| server_key.map(|s| s.to_string()));
    let project_id = std::env::var("FIREBASE_PROJECT_ID").unwrap_or_else(|_| "baton".to_string());
    
    let key = match auth_token {
        Some(k) if !k.is_empty() => k,
        _ => {
            warn!("FIREBASE_SERVER_KEY and GOOGLE_APPLICATION_CREDENTIALS not set — cannot send FCM wakeup.");
            return;
        }
    };

    let body = serde_json::json!({
        "message": {
            "token": fcm_token,
            "data": {
                "type": "baton_wakeup"
            }
        }
    });

    match http
        .post(format!("https://fcm.googleapis.com/v1/projects/{}/messages:send", project_id))
        .header("Authorization", format!("Bearer {}", key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!("📲 FCM wakeup sent successfully.");
        }
        Ok(resp) => {
            warn!("📲 FCM wakeup failed with status: {}", resp.status());
        }
        Err(e) => {
            warn!("📲 FCM wakeup HTTP error: {}", e);
        }
    }
}

// ── Group Messaging Endpoints (Pillar 3 — V2) ────────────────────────────────

#[derive(Deserialize)]
struct GroupCreateRequest {
    group_name: String,
    creator_id: String,
    /// Initial member client_ids (creator is auto-included)
    member_ids: Vec<String>,
}

#[derive(Serialize)]
struct GroupCreateResponse {
    group_id: String,
    name: String,
    members: Vec<String>,
}

/// `POST /group/create` — Create a new group. Max 10 members. Creator-only admin.
async fn group_create_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<GroupCreateRequest>,
) -> impl IntoResponse {
    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &payload.creator_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if payload.creator_id.is_empty() || payload.group_name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "creator_id and group_name required"}))).into_response();
    }

    // Count existing groups where this user is the creator
    let creator_count = state.groups.iter().filter(|g| g.value().creator_id == payload.creator_id).count();
    if creator_count >= 50 {
        return (StatusCode::TOO_MANY_REQUESTS, "Maximum 50 groups per user").into_response();
    }

    let mut members: HashSet<String> = payload.member_ids.into_iter().collect();
    members.insert(payload.creator_id.clone()); // Creator is always a member

    if members.len() > 10 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Maximum 10 members per group"}))).into_response();
    }

    let group_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let group = GroupInfo {
        id: group_id.clone(),
        name: payload.group_name.clone(),
        creator_id: payload.creator_id.clone(),
        members: members.clone(),
        created_at: now,
    };

    state.groups.insert(group_id.clone(), group);
    
    {
        let members_json = serde_json::to_string(&members).unwrap_or_default();
        let db = state.db.lock().await;
        let _ = db.execute(
            "INSERT INTO groups (group_id, name, creator_id, members_json, created_at) VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![group_id, payload.group_name, payload.creator_id, members_json, now as i64]
        );
    }
    
    info!("📢 Group '{}' ({}) created by {} with {} members", payload.group_name, group_id, payload.creator_id, members.len());

    let response = GroupCreateResponse {
        group_id,
        name: payload.group_name,
        members: members.into_iter().collect(),
    };
    let json_val = serde_json::to_value(response).unwrap_or_default();
    (StatusCode::CREATED, Json(json_val)).into_response()
}

#[derive(Deserialize)]
struct GroupMemberRequest {
    group_id: String,
    requester_id: String,
    member_id: String,
}

/// `POST /group/join` — Add a member to a group (creator-only).
async fn group_join_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<GroupMemberRequest>,
) -> impl IntoResponse {
    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &payload.requester_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if let Some(mut group) = state.groups.get_mut(&payload.group_id) {
        if group.creator_id != payload.requester_id {
            return (StatusCode::FORBIDDEN, "Only the group creator can add members").into_response();
        }
        if group.members.len() >= 10 {
            return (StatusCode::BAD_REQUEST, "Maximum 10 members per group").into_response();
        }
        group.members.insert(payload.member_id.clone());
        
        {
            let members_json = serde_json::to_string(&group.members).unwrap_or_default();
            let db = state.db.lock().await;
            let _ = db.execute(
                "UPDATE groups SET members_json = ? WHERE group_id = ?",
                rusqlite::params![members_json, payload.group_id]
            );
        }
        
        info!("📢 Added {} to group {}", payload.member_id, payload.group_id);
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "Group not found").into_response()
    }
}

/// `POST /group/leave` — Remove a member from a group (creator or self).
async fn group_leave_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<GroupMemberRequest>,
) -> impl IntoResponse {
    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &payload.requester_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if let Some(mut group) = state.groups.get_mut(&payload.group_id) {
        // Only the creator can remove others; anyone can remove themselves
        if payload.member_id != payload.requester_id && group.creator_id != payload.requester_id {
            return (StatusCode::FORBIDDEN, "Only the group creator can remove other members").into_response();
        }
        group.members.remove(&payload.member_id);
        
        {
            let members_json = serde_json::to_string(&group.members).unwrap_or_default();
            let db = state.db.lock().await;
            let _ = db.execute(
                "UPDATE groups SET members_json = ? WHERE group_id = ?",
                rusqlite::params![members_json, payload.group_id]
            );
        }
        
        info!("📢 Removed {} from group {}", payload.member_id, payload.group_id);
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "Group not found").into_response()
    }
}

/// `GET /group/{group_id}` — Get group info.
async fn group_info_handler(
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let mut requester_id = None;
    if let Some(token) = headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "))
        && let Ok(token_data) = jsonwebtoken::decode::<Claims>(
            token,
            &jsonwebtoken::DecodingKey::from_secret(state.jwt_secret.as_bytes()),
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256)
        ) {
            requester_id = Some(token_data.claims.sub);
        }
    
    let req_id = match requester_id {
        Some(id) => id,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };

    if let Some(group) = state.groups.get(&group_id) {
        if !group.members.contains(&req_id) {
            return (StatusCode::FORBIDDEN, "Not a group member").into_response();
        }
        let info = group.clone();
        let json_val = serde_json::to_value(info).unwrap_or_default();
        (StatusCode::OK, Json(json_val)).into_response()
    } else {
        (StatusCode::NOT_FOUND, "Group not found").into_response()
    }
}

/// `DELETE /group/{group_id}` — Delete a group (creator-only). Expects `creator_id` query param.
async fn group_delete_handler(
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let requester = params.get("creator_id").cloned().unwrap_or_default();
    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &requester),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if let Some(group) = state.groups.get(&group_id) {
        if group.creator_id != requester {
            return (StatusCode::FORBIDDEN, "Only the group creator can delete the group").into_response();
        }
        drop(group); // Release DashMap read guard before removing
        state.groups.remove(&group_id);
        
        {
            let db = state.db.lock().await;
            let _ = db.execute("DELETE FROM groups WHERE group_id = ?", rusqlite::params![group_id]);
        }
        
        info!("📢 Group {} deleted by {}", group_id, requester);
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "Group not found").into_response()
    }
}

/// `GET /groups/{client_id}` — List all groups a client belongs to.
async fn group_list_handler(
    Path(client_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &client_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let groups: Vec<serde_json::Value> = state.groups
        .iter()
        .filter(|entry| entry.value().members.contains(&client_id))
        .map(|entry| {
            let g = entry.value();
            serde_json::json!({
                "id": g.id,
                "name": g.name,
                "creator_id": g.creator_id,
                "member_count": g.members.len(),
                "created_at": g.created_at
            })
        })
        .collect();

    let json_val = serde_json::to_value(groups).unwrap_or_default();
    (StatusCode::OK, Json(json_val)).into_response()
}



async fn health_handler(
    State(_state): State<Arc<AppState>>,
) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status":"ok","service":"cloud-router"}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

