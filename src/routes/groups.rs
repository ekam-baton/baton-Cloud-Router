use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::{collections::HashSet, sync::Arc};
use tracing::info;
use crate::auth::verify_jwt;
use crate::models::{Claims, GroupCreateRequest, GroupCreateResponse, GroupInfo, GroupMemberRequest};
use crate::state::AppState;

/// `POST /group/create` — Create a new group. Max 10 members. Creator-only admin.
pub async fn group_create_handler(
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

/// `POST /group/join` — Add a member to a group (creator-only).
pub async fn group_join_handler(
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

    let members_json = if let Some(mut group) = state.groups.get_mut(&payload.group_id) {
        if group.creator_id != payload.requester_id {
            return (StatusCode::FORBIDDEN, "Only the group creator can add members").into_response();
        }
        if group.members.len() >= 10 {
            return (StatusCode::BAD_REQUEST, "Maximum 10 members per group").into_response();
        }
        group.members.insert(payload.member_id.clone());
        let json = serde_json::to_string(&group.members).unwrap_or_default();
        drop(group); // Release DashMap lock before async SQLite I/O
        json
    } else {
        return (StatusCode::NOT_FOUND, "Group not found").into_response();
    };

    {
        let db = state.db.lock().await;
        let _ = db.execute(
            "UPDATE groups SET members_json = ? WHERE group_id = ?",
            rusqlite::params![members_json, payload.group_id]
        );
    }

    info!("📢 Added {} to group {}", payload.member_id, payload.group_id);
    StatusCode::OK.into_response()
}

/// `POST /group/leave` — Remove a member from a group (creator or self).
pub async fn group_leave_handler(
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

    let members_json = if let Some(mut group) = state.groups.get_mut(&payload.group_id) {
        // Only the creator can remove others; anyone can remove themselves
        if payload.member_id != payload.requester_id && group.creator_id != payload.requester_id {
            return (StatusCode::FORBIDDEN, "Only the group creator can remove other members").into_response();
        }
        group.members.remove(&payload.member_id);
        let json = serde_json::to_string(&group.members).unwrap_or_default();
        drop(group); // Release DashMap lock before async SQLite I/O
        json
    } else {
        return (StatusCode::NOT_FOUND, "Group not found").into_response();
    };

    {
        let db = state.db.lock().await;
        let _ = db.execute(
            "UPDATE groups SET members_json = ? WHERE group_id = ?",
            rusqlite::params![members_json, payload.group_id]
        );
    }

    info!("📢 Removed {} from group {}", payload.member_id, payload.group_id);
    StatusCode::OK.into_response()
}

/// `GET /group/{group_id}` — Get group info.
pub async fn group_info_handler(
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
pub async fn group_delete_handler(
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
pub async fn group_list_handler(
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
