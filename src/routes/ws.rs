use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    http::StatusCode,
    response::IntoResponse,
};
use futures::{sink::SinkExt, stream::StreamExt};
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::auth::verify_jwt;
use crate::models::Envelope;
use crate::services::fcm::send_fcm_wakeup;
use crate::state::AppState;

pub async fn ack_messages_handler(
    Path(client_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
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

    let up_to_id = params.get("up_to_id").and_then(|s| s.parse::<i64>().ok());

    let db = state.db.lock().await;
    if let Some(id_bound) = up_to_id {
        let _ = db.execute(
            "DELETE FROM queued_messages WHERE receiver_id = ?1 AND id <= ?2",
            rusqlite::params![&client_id, id_bound],
        );
    } else {
        let _ = db.execute("DELETE FROM queued_messages WHERE receiver_id = ?1", [&client_id]);
    }
    StatusCode::OK.into_response()
}

pub async fn ws_handler(
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

pub async fn handle_socket(socket: WebSocket, client_id: String, state: Arc<AppState>) {
    let (mut sender, mut receiver) = socket.split();

    // Create a channel for this specific connection to receive forwarded messages.
    let (tx, mut rx) = mpsc::channel::<Message>(100);

    // Register this connection in the global map.
    let conn_id = uuid::Uuid::new_v4().to_string();
    state.connections.insert(client_id.clone(), (tx.clone(), conn_id.clone()));
    info!("Registered client {} for routing", client_id);

    let messages_to_send = {
        let db = state.db.lock().await;
        let mut msgs = Vec::new();
        if let Ok(mut stmt) = db.prepare("SELECT id, payload FROM queued_messages WHERE receiver_id = ? ORDER BY id ASC LIMIT 250")
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
        if let Some(&max_id) = ids_to_delete.last() {
            let state_clone = state.clone();
            let client_id_del = client_id.clone();
            tokio::spawn(async move {
                let db = state_clone.db.lock().await;
                let _ = db.execute(
                    "DELETE FROM queued_messages WHERE receiver_id = ?1 AND id <= ?2",
                    rusqlite::params![&client_id_del, max_id],
                );
            });
        }
    }

    // Task 1: Forward messages from the MPSC channel into the actual WebSocket,
    // and send periodic 30s ping heartbeats to detect and reap ghost connections.
    let mut send_task = tokio::spawn(async move {
        let mut ping_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(30),
            Duration::from_secs(30),
        );
        ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                msg = rx.recv() => {
                    match msg {
                        Some(msg) => {
                            if sender.send(msg).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = ping_interval.tick() => {
                    if sender.send(Message::Ping(Vec::new().into())).await.is_err() {
                        break;
                    }
                }
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
                    // Enforce maximum payload size limit (512 KB max) to prevent memory & DB exhaustion
                    const MAX_MESSAGE_PAYLOAD_BYTES: usize = 512 * 1024;
                    if text.len() > MAX_MESSAGE_PAYLOAD_BYTES {
                        warn!(
                            "Oversized WebSocket message payload ({} bytes > {} max) from client {}. Dropping.",
                            text.len(), MAX_MESSAGE_PAYLOAD_BYTES, client_id_clone
                        );
                        continue;
                    }

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
                        // Validate receiver_id format and bounds
                        if envelope.receiver_id.trim().is_empty() || envelope.receiver_id.len() > 128 {
                            warn!(
                                "Malformed or oversized receiver_id '{}' from sender '{}'. Dropping message.",
                                envelope.receiver_id, client_id_clone
                            );
                            continue;
                        }

                        // ── Hard Loop Breaker: Recursion Depth / Hop Limit ───
                        const MAX_ROUTER_RECURSION_DEPTH: u32 = 3;
                        if envelope.depth >= MAX_ROUTER_RECURSION_DEPTH {
                            warn!(
                                "Cloud Router recursion breaker triggered: depth {} >= limit {} from sender '{}'. Dropping message.",
                                envelope.depth, MAX_ROUTER_RECURSION_DEPTH, client_id_clone
                            );
                            continue;
                        }

                        // ── Hard Loop Breaker: Increment and Enforce Hop Limit ───
                        envelope.depth += 1;

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
                                        
                                        let delivered = if let Some(dest_tx) = dest_tx_opt {
                                            dest_tx.try_send(Message::Text(authenticated_text.clone().into())).is_ok()
                                        } else {
                                            false
                                        };

                                        if !delivered {
                                            // Offline member or channel buffer full — FCM wakeup and queue message
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
                            
                            let delivered = if let Some(dest_tx) = dest_tx_opt {
                                dest_tx.try_send(Message::Text(authenticated_text.clone().into())).is_ok()
                            } else {
                                false
                            };

                            if !delivered {
                                // Client is offline or buffer full — fire a blank FCM wakeup (Pillar 1 — V2)
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

                                info!("Offline client or saturated channel detected. Sending blank FCM wakeup.");
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
                Message::Ping(data) => {
                    let _ = tx.try_send(Message::Pong(data));
                }
                _ => {} // Ignore unhandled frames
            }
        }
    });

    // Wait until either task finishes (socket closed or error).
    tokio::select! {
        _ = (&mut send_task) => recv_task.abort(),
        _ = (&mut recv_task) => send_task.abort(),
    };

    // Cleanup when the connection drops (atomic remove_if avoids race condition with fast reconnects)
    let removed = state.connections.remove_if(&client_id, |_, val| val.1 == conn_id);
    if removed.is_some() {
        info!("Client {} connection {} disconnected and removed from routing table", client_id, conn_id);
    } else {
        info!("Client {} connection {} disconnected (newer connection retained in routing table)", client_id, conn_id);
    }
}
