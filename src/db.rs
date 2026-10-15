use dashmap::DashMap;
use rusqlite::Connection;
use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::info;
use crate::models::GroupInfo;
use crate::state::AppState;

pub fn init_db(db_path: &str) -> Result<(Connection, DashMap<String, GroupInfo>), Box<dyn std::error::Error>> {
    let db = Connection::open(db_path)?;
    let _ = db.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;",
    );
    db.execute(
        "CREATE TABLE IF NOT EXISTS queued_messages(id INTEGER PRIMARY KEY, receiver_id TEXT, payload TEXT, created_at INTEGER)",
        (),
    )?;
    db.execute(
        "CREATE INDEX IF NOT EXISTS idx_queued_messages_receiver ON queued_messages(receiver_id, id)",
        (),
    )?;
    
    // Prune queued messages older than 7 days on startup
    let seven_days_ago = SystemTime::now()
        .duration_since(UNIX_EPOCH)
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

    Ok((db, groups_map))
}

pub fn spawn_queue_cleanup(state: Arc<AppState>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await; // Run every hour
            let db = state.db.lock().await;
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
}
