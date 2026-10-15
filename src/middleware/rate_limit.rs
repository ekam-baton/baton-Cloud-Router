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
