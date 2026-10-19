use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use std::{collections::HashSet, sync::Arc};
use tracing::info;
use crate::auth::{decode_jwt_sub, verify_jwt};
use crate::models::{GroupCreateRequest, GroupCreateResponse, GroupInfo, GroupMemberRequest};
use crate::state::AppState;

/// `POST /group/create` — Create a new group. Max 10 members. Creator-only admin.
pub async fn group_create_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<GroupCreateRequest>,
) -> impl IntoResponse {
    let token_sub = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|t| decode_jwt_sub(t, &state.jwt_secret));

    let creator_id = if !payload.creator_id.trim().is_empty() {
        payload.creator_id.trim().to_string()
    } else if let Some(ref sub) = token_sub {
        sub.trim().to_string()
    } else {
        String::new()
    };

    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &creator_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    let group_name = payload.group_name.trim().to_string();
    if creator_id.is_empty() || creator_id.len() > 128 || creator_id.chars().any(|c| c.is_control()) ||
       group_name.is_empty() || group_name.len() > 100 || group_name.chars().any(|c| c.is_control()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "creator_id (max 128) and group_name (max 100, no control characters) required"}))).into_response();
    }

    if payload.member_ids.iter().any(|m| m.trim().is_empty() || m.len() > 128 || m.chars().any(|c| c.is_control())) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid member_id format in group"}))).into_response();
    }

    // Count existing groups where this user is the creator
    let creator_count = state.groups.iter().filter(|g| g.value().creator_id == creator_id).count();
    if creator_count >= 50 {
        return (StatusCode::TOO_MANY_REQUESTS, "Maximum 50 groups per user").into_response();
    }

    let mut members: HashSet<String> = payload.member_ids.into_iter().map(|m| m.trim().to_string()).collect();
    members.insert(creator_id.clone()); // Creator is always a member

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
        name: group_name.clone(),
        creator_id: creator_id.clone(),
        members: members.clone(),
        created_at: now,
    };

    state.groups.insert(group_id.clone(), group);
    
    {
        let members_json = serde_json::to_string(&members).unwrap_or_default();
        let db = state.db.lock().await;
        let _ = db.execute(
            "INSERT INTO groups (group_id, name, creator_id, members_json, created_at) VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![group_id, group_name, creator_id, members_json, now as i64]
        );
    }
    
    info!("📢 Group '{}' ({}) created by {} with {} members", group_name, group_id, creator_id, members.len());

    let response = GroupCreateResponse {
        group_id,
        name: group_name,
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
    let requester_id = payload.requester_id.trim().to_string();
    let member_id = payload.member_id.trim().to_string();
    let group_id = payload.group_id.trim().to_string();

    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &requester_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if member_id.is_empty() || member_id.len() > 128 || member_id.chars().any(|c| c.is_control()) ||
       group_id.is_empty() || group_id.len() > 128 || group_id.chars().any(|c| c.is_control()) ||
       requester_id.is_empty() || requester_id.len() > 128 || requester_id.chars().any(|c| c.is_control()) {
        return (StatusCode::BAD_REQUEST, "Invalid member_id, group_id, or requester_id").into_response();
    }

    let members_json = if let Some(mut group) = state.groups.get_mut(&group_id) {
        if group.creator_id != requester_id {
            return (StatusCode::FORBIDDEN, "Only the group creator can add members").into_response();
        }
        if group.members.contains(&member_id) {
            return (StatusCode::OK, "Member already in group").into_response();
        }
        if group.members.len() >= 10 {
            return (StatusCode::BAD_REQUEST, "Maximum 10 members per group").into_response();
        }
        group.members.insert(member_id.clone());
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
            rusqlite::params![members_json, group_id]
        );
    }

    info!("📢 Added {} to group {}", member_id, group_id);
    StatusCode::OK.into_response()
}

/// `POST /group/leave` — Remove a member from a group (creator or self).
pub async fn group_leave_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(payload): Json<GroupMemberRequest>,
) -> impl IntoResponse {
    let requester_id = payload.requester_id.trim().to_string();
    let member_id = payload.member_id.trim().to_string();
    let group_id = payload.group_id.trim().to_string();

    let is_valid = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(token) => verify_jwt(token, &state.jwt_secret, &requester_id),
        None => false,
    };
    if !is_valid {
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }

    if member_id.is_empty() || member_id.len() > 128 || member_id.chars().any(|c| c.is_control()) ||
       group_id.is_empty() || group_id.len() > 128 || group_id.chars().any(|c| c.is_control()) ||
       requester_id.is_empty() || requester_id.len() > 128 || requester_id.chars().any(|c| c.is_control()) {
        return (StatusCode::BAD_REQUEST, "Invalid member_id, group_id, or requester_id").into_response();
    }

    let (members_json, is_empty, new_creator_opt) = if let Some(mut group) = state.groups.get_mut(&group_id) {
        // Only the creator can remove others; anyone can remove themselves
        if member_id != requester_id && group.creator_id != requester_id {
            return (StatusCode::FORBIDDEN, "Only the group creator can remove other members").into_response();
        }
        group.members.remove(&member_id);
        let empty = group.members.is_empty();
        let mut new_creator = None;
        if member_id == group.creator_id && !empty {
            // Creator left, transfer ownership to the next remaining member so the group is not orphaned
            if let Some(next_creator) = group.members.iter().next().cloned() {
                group.creator_id = next_creator.clone();
                new_creator = Some(next_creator);
            }
        }
        let json = serde_json::to_string(&group.members).unwrap_or_default();
        drop(group); // Release DashMap lock before async SQLite I/O
        (json, empty, new_creator)
    } else {
        return (StatusCode::NOT_FOUND, "Group not found").into_response();
    };

    if is_empty {
        state.groups.remove(&group_id);
        let db = state.db.lock().await;
        if let Err(e) = db.execute("DELETE FROM groups WHERE group_id = ?", rusqlite::params![group_id]) {
            tracing::error!("Failed to delete empty group {} from db: {}", group_id, e);
        }
        info!("📢 Group {} is now empty — automatically deleted", group_id);
    } else {
        let db = state.db.lock().await;
        if let Some(new_creator) = new_creator_opt {
            if let Err(e) = db.execute(
                "UPDATE groups SET creator_id = ?, members_json = ? WHERE group_id = ?",
                rusqlite::params![new_creator, members_json, group_id]
            ) {
                tracing::error!("Failed to update group {} creator & members in db: {}", group_id, e);
            }
            info!("📢 Creator left; transferred group {} ownership to {}", group_id, new_creator);
        } else {
            if let Err(e) = db.execute(
                "UPDATE groups SET members_json = ? WHERE group_id = ?",
                rusqlite::params![members_json, group_id]
            ) {
                tracing::error!("Failed to update group {} members in db: {}", group_id, e);
            }
            info!("📢 Removed {} from group {}", member_id, group_id);
        }
    }
    StatusCode::OK.into_response()
}

/// `GET /group/{group_id}` — Get group info.
pub async fn group_info_handler(
    Path(group_id): Path<String>,
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let group_id = group_id.trim().to_string();
    if group_id.is_empty() || group_id.len() > 128 || group_id.chars().any(|c| c.is_control()) {
        return (StatusCode::BAD_REQUEST, "Invalid group_id").into_response();
    }

    let token = match headers.get("Authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer ")) {
        Some(t) => t,
        None => return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response(),
    };
    
    let req_id = match decode_jwt_sub(token, &state.jwt_secret) {
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
    let requester = if let Some(c) = params.get("creator_id").filter(|s| !s.trim().is_empty()) {
        c.trim().to_string()
    } else if let Some(sub) = headers.get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .and_then(|t| decode_jwt_sub(t, &state.jwt_secret)) {
        sub.trim().to_string()
    } else {
        String::new()
    };

    let group_id = group_id.trim().to_string();
    if requester.is_empty() || requester.len() > 128 || requester.chars().any(|c| c.is_control()) ||
       group_id.is_empty() || group_id.len() > 128 || group_id.chars().any(|c| c.is_control()) {
        return (StatusCode::BAD_REQUEST, "Invalid parameters").into_response();
    }

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
            if let Err(e) = db.execute("DELETE FROM groups WHERE group_id = ?", rusqlite::params![group_id]) {
                tracing::error!("Failed to delete group {} from db: {}", group_id, e);
            }
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
    let client_id = client_id.trim().to_string();
    if client_id.is_empty() || client_id.len() > 128 || client_id.chars().any(|c| c.is_control()) {
        return (StatusCode::BAD_REQUEST, "Invalid client_id").into_response();
    }

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
