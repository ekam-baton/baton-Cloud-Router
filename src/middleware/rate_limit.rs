use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    middleware::Next,
    response::IntoResponse,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::warn;
use crate::state::AppState;

/// IP Rate Limiter Middleware (DDoS Prevention)
pub async fn ip_rate_limit_middleware(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: axum::extract::Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let ip = if state.trusted_proxy_ips.contains(&addr.ip()) {
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

    // Perform rate check and immediately drop the DashMap guard before any .await
    let rate_exceeded = {
        // Active memory-protection guard: prune stale IPs if map exceeds threshold under high-volume scans
        if state.rate_limiter.len() > 10_000 {
            state.rate_limiter.retain(|_, (_, window_start)| {
                now.duration_since(*window_start) < Duration::from_secs(120)
            });
        }

        let mut entry = state.rate_limiter.entry(ip).or_insert((0, now));
        let (count, window_start) = entry.value_mut();

        if now.duration_since(*window_start) > Duration::from_secs(60) {
            *count = 1;
            *window_start = now;
            false
        } else {
            *count += 1;
            *count > state.rate_limit_rpm
        }
    }; // DashMap shard lock dropped here — safe to .await below

    if rate_exceeded {
        warn!("DDoS Mitigation: Rate limit exceeded for IP {}", ip);
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    Ok(next.run(req).await)
}
