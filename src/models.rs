use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    #[serde(default)]
    pub exp: Option<usize>,
}

/// Group metadata stored in the router's in-memory state.
/// The router never sees message contents — only membership for fan-out routing.
#[derive(Debug, Clone, Serialize)]
pub struct GroupInfo {
    /// Unique group identifier
    pub id: String,
    /// Human-readable group name (encrypted by clients; router stores opaque string)
    pub name: String,
    /// The client_id of the group creator (only they can add/remove members)
    pub creator_id: String,
    /// Set of client_ids that are members of this group
    pub members: HashSet<String>,
    /// Creation timestamp (unix millis)
    pub created_at: u64,
}

// Sealed Sender Envelope: sender_id is optional and omitted in production for metadata privacy.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub receiver_id: String,
    #[serde(default)]
    pub sender_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub depth: u32,
    #[serde(alias = "payload")]
    pub payload_encrypted: String, 
}

#[derive(Serialize)]
pub struct TurnCredentialsResponse {
    pub username: String,
    pub password: String,
    pub ttl: u64,
    pub uris: Vec<String>,
}

#[derive(Deserialize)]
pub struct RegisterPushRequest {
    pub client_id: String,
    pub fcm_token: String,
}

#[derive(Deserialize)]
pub struct GroupCreateRequest {
    pub group_name: String,
    pub creator_id: String,
    /// Initial member client_ids (creator is auto-included)
    pub member_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct GroupCreateResponse {
    pub group_id: String,
    pub name: String,
    pub members: Vec<String>,
}

#[derive(Deserialize)]
pub struct GroupMemberRequest {
    pub group_id: String,
    pub requester_id: String,
    pub member_id: String,
}
