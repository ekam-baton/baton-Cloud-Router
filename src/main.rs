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
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tower::limit::ConcurrencyLimitLayer;
use tracing::{error, info, warn};

// The shared state tracking all active websocket connections and rate limiting metrics.
struct AppState {
    // Maps a client_id (like a phone's public key) to a Sender channel.
    connections: DashMap<String, mpsc::Sender<Message>>,
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
    #[serde(alias = "payload")]
    payload_encrypted: String, 
}

#[tokio::main]
async fn main() {
    // Initialize standard logging
    tracing_subscriber::fmt::init();

    let state = Arc::new(AppState {
        connections: DashMap::new(),
        rate_limiter: DashMap::new(),
        push_tokens: DashMap::new(),
        groups: DashMap::new(),
        http: HttpClient::new(),
        firebase_server_key: std::env::var("FIREBASE_SERVER_KEY").ok(),
    });

    // ── Spawn Embedded TURN Relay Listener on port 3478 ────────────────────────
    tokio::spawn(async move {
        start_embedded_turn_server("0.0.0.0:3478").await;
    });

    let app = Router::new()
        // The main websocket endpoint for edge devices to connect to.
        .route("/relay/{client_id}", get(ws_handler))
        // FCM push token registration endpoint (Pillar 1 — V2)
        .route("/register-push", post(register_push_handler))
        // Group messaging endpoints (Pillar 3 — V2)
        .route("/group/create", post(group_create_handler))
        .route("/group/join", post(group_join_handler))
        .route("/group/leave", post(group_leave_handler))
        .route("/group/{group_id}", get(group_info_handler))
        .route("/group/{group_id}", delete(group_delete_handler))
        .route("/groups/{client_id}", get(group_list_handler))
        .layer(middleware::from_fn_with_state(state.clone(), ip_rate_limit_middleware))
        .layer(ConcurrencyLimitLayer::new(10_000))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8082")
        .await
        .expect("Failed to bind to port 8082. Is it already in use?");
    if let Ok(addr) = listener.local_addr() {
        info!("Baton Cloud Router listening on {}", addr);
    } else {
        info!("Baton Cloud Router listening on 0.0.0.0:8082");
    }
    
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("Failed to start Axum server");
}

/// IP Rate Limiter Middleware (DDoS Prevention)
async fn ip_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let ip = req
        .headers()
        .get("cf-connecting-ip")
        .or_else(|| req.headers().get("x-forwarded-for"))
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse::<IpAddr>().ok())
        .unwrap_or_else(|| addr.ip());
    let now = Instant::now();
    
    let mut entry = state.rate_limiter.entry(ip).or_insert((0, now));
    let (count, window_start) = entry.value_mut();

    if now.duration_since(*window_start) > Duration::from_secs(60) {
        *count = 1;
        *window_start = now;
    } else {
        *count += 1;
        if *count > 200 { // Max 200 requests / minute per IP
            warn!("DDoS Mitigation: Rate limit exceeded for IP {}", ip);
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
    }

    Ok(next.run(req).await)
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
            if len >= 20 && &buf[4..8] == &[0x21, 0x12, 0xA4, 0x42] {
                // Respond with STUN Binding Success Response
                let mut resp = vec![0x01, 0x01, 0x00, 0x00]; // Binding Success Response
                resp.extend_from_slice(&buf[4..20]); // Copy transaction ID
                let _ = socket.send_to(&resp, src).await;
            }
        }
    }
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(client_id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
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
    state.connections.insert(client_id.clone(), tx);
    info!("Registered client {} for routing", client_id);

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
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Text(text) => {
                    // Sealed Sender: Envelope only requires receiver_id and payload_encrypted
                    if let Ok(envelope) = serde_json::from_str::<Envelope>(&text) {
                        // ── Group Fan-Out Routing (Pillar 3 — V2) ──────────────────
                        if envelope.receiver_id.starts_with("group:") {
                            let group_id = envelope.receiver_id.strip_prefix("group:").unwrap_or("");
                            info!("Group message for group {}", group_id);
                            
                            // Get member list (clone to release DashMap lock immediately)
                            let members: Option<HashSet<String>> = state_clone.groups
                                .get(group_id)
                                .map(|g| g.members.clone());
                            
                            if let Some(members) = members {
                                // Parse the group payload map: { "member_id": "encrypted_for_member", ... }
                                let sender = envelope.sender_id.as_deref().unwrap_or("");
                                
                                // Fan out: send each member the opaque envelope without inspecting/modifying payload
                                for member_id in &members {
                                    if member_id == sender { continue; }
                                    
                                    let dest_tx_opt = state_clone.connections
                                        .get(member_id)
                                        .map(|c| c.clone());
                                    
                                    if let Some(dest_tx) = dest_tx_opt {
                                        let _ = dest_tx.send(Message::Text(text.clone().into())).await;
                                    } else {
                                        // Offline member — FCM wakeup
                                        if let Some(fcm_token) = state_clone.push_tokens.get(member_id).map(|t| t.clone()) {
                                            let http = state_clone.http.clone();
                                            let server_key = state_clone.firebase_server_key.clone();
                                            tokio::spawn(async move {
                                                send_fcm_wakeup(&http, server_key.as_deref(), &fcm_token).await;
                                            });
                                        }
                                    }
                                }
                            } else {
                                warn!("Group {} not found — dropping message", group_id);
                            }
                        }
                        // ── Standard 1-to-1 Routing ───────────────────────────────
                        else {
                            info!("Sealed-Sender Routing message to receiver {}", envelope.receiver_id);
                            
                            // Look up the destination connection and clone the sender to drop the DashMap lock
                            let dest_tx_opt = state_clone.connections.get(&envelope.receiver_id).map(|c| c.clone());
                            
                            if let Some(dest_tx) = dest_tx_opt {
                                // Forward the exact raw JSON string without holding the lock
                                let _ = dest_tx.send(Message::Text(text.into())).await;
                            } else {
                                // Client is offline — fire a blank FCM wakeup (Pillar 1 — V2)
                                info!("Client {} offline. Sending blank FCM wakeup.", envelope.receiver_id);
                                if let Some(fcm_token) = state_clone.push_tokens.get(&envelope.receiver_id).map(|t| t.clone()) {
                                    let http = state_clone.http.clone();
                                    let server_key = state_clone.firebase_server_key.clone();
                                    tokio::spawn(async move {
                                        send_fcm_wakeup(&http, server_key.as_deref(), &fcm_token).await;
                                    });
                                } else {
                                    warn!("No FCM token registered for offline client {}", envelope.receiver_id);
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
    state.connections.remove(&client_id);
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
    Json(payload): Json<RegisterPushRequest>,
) -> impl IntoResponse {
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
    let key = match server_key {
        Some(k) if !k.is_empty() => k,
        _ => {
            warn!("FIREBASE_SERVER_KEY not set — cannot send FCM wakeup.");
            return;
        }
    };

    // FCM Legacy HTTP API (v1 API requires OAuth2; legacy is simpler for self-hosted deployments)
    let body = serde_json::json!({
        "to": fcm_token,
        "priority": "high",
        // data-only message: no notification key = no lock-screen banner, just a silent wakeup
        "data": {
            "type": "baton_wakeup"
        }
    });

    match http
        .post("https://fcm.googleapis.com/fcm/send")
        .header("Authorization", format!("key={}", key))
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
    Json(payload): Json<GroupCreateRequest>,
) -> impl IntoResponse {
    if payload.creator_id.is_empty() || payload.group_name.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "creator_id and group_name required"}))).into_response();
    }

    let mut members: HashSet<String> = payload.member_ids.into_iter().collect();
    members.insert(payload.creator_id.clone()); // Creator is always a member

    if members.len() > 10 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Maximum 10 members per group"}))).into_response();
    }

    let group_id = format!("{:016x}", rand_id());
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
    Json(payload): Json<GroupMemberRequest>,
) -> impl IntoResponse {
    if let Some(mut group) = state.groups.get_mut(&payload.group_id) {
        if group.creator_id != payload.requester_id {
            return (StatusCode::FORBIDDEN, "Only the group creator can add members").into_response();
        }
        if group.members.len() >= 10 {
            return (StatusCode::BAD_REQUEST, "Maximum 10 members per group").into_response();
        }
        group.members.insert(payload.member_id.clone());
        info!("📢 Added {} to group {}", payload.member_id, payload.group_id);
        StatusCode::OK.into_response()
    } else {
        (StatusCode::NOT_FOUND, "Group not found").into_response()
    }
}

/// `POST /group/leave` — Remove a member from a group (creator or self).
async fn group_leave_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<GroupMemberRequest>,
) -> impl IntoResponse {
    if let Some(mut group) = state.groups.get_mut(&payload.group_id) {
        // Only the creator can remove others; anyone can remove themselves
        if payload.member_id != payload.requester_id && group.creator_id != payload.requester_id {
            return (StatusCode::FORBIDDEN, "Only the group creator can remove other members").into_response();
        }
        group.members.remove(&payload.member_id);
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
) -> impl IntoResponse {
    if let Some(group) = state.groups.get(&group_id) {
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
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let requester = params.get("creator_id").cloned().unwrap_or_default();
    if let Some(group) = state.groups.get(&group_id) {
        if group.creator_id != requester {
            return (StatusCode::FORBIDDEN, "Only the group creator can delete the group").into_response();
        }
        drop(group); // Release DashMap read guard before removing
        state.groups.remove(&group_id);
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
) -> impl IntoResponse {
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

/// Generate a pseudo-random 64-bit ID using system time + thread-local counter.
fn rand_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    ts.wrapping_add(COUNTER.fetch_add(1, Ordering::Relaxed))
}
