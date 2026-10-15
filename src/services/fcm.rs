use reqwest::Client as HttpClient;
use tracing::{info, warn};

/// Send a completely blank FCM data-only notification to wake an offline Android client.
///
/// Security: the `data` payload is intentionally empty — Google sees zero
/// message content, zero sender identity. It is purely an OS-level wakeup knock.
pub async fn send_fcm_wakeup(http: &HttpClient, server_key: Option<&str>, fcm_token: &str) {
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
