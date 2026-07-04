//! Authentication middleware — Token-based auth for Smart HTTP and REST API
//!
//! P2: Uses `base64` crate for proper decoding, works with RwLock<IdentityStore>
//! P8.1: Added rate limiting middleware

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};

use opengit_core::rate_limiter::{RateLimitKind, RateLimitResult};

use crate::api::SharedState;

/// The authenticated identity name (stored in request extensions)
#[derive(Clone, Debug)]
pub struct IdentityName(pub String);

/// Extract token from request headers or query parameters
pub fn extract_token(request: &Request) -> Option<String> {
    // 1. Check Authorization header (Bearer token)
    if let Some(auth) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
            // Basic auth: decode and use password as token
            if let Some(encoded) = auth_str.strip_prefix("Basic ") {
                if let Ok(decoded) = base64_decode(encoded) {
                    // Format: "username:password" — use password as token
                    if let Some((_user, pass)) = decoded.split_once(':') {
                        return Some(pass.to_string());
                    }
                }
            }
        }
    }

    // 2. Check query parameter (for git clone URLs like ?token=xxx)
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            if let Some(token) = pair.strip_prefix("token=") {
                return Some(token.to_string());
            }
        }
    }

    None
}

/// Base64 decode using the base64 crate
fn base64_decode(input: &str) -> Result<String, ()> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(input.trim_end_matches('='))
        .map_err(|_| ())?;
    String::from_utf8(decoded).map_err(|_| ())
}

/// Auth middleware for Smart HTTP endpoints
///
/// Optional auth — allows anonymous access for read operations.
/// The Smart HTTP handlers do their own fine-grained permission checks.
pub async fn smart_http_auth(
    State(state): State<SharedState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Try to extract and validate token
    if let Some(token) = extract_token(&request) {
        let store = state.identity_store.read().await;
        if let Some(identity) = store.find_by_token(&token) {
            tracing::debug!("Authenticated as: {}", identity.name);
            request
                .extensions_mut()
                .insert(IdentityName(identity.name.clone()));
            return Ok(next.run(request).await);
        }
    }

    // No valid token — allow through as anonymous
    // For push, the receive_pack handler will reject with 401
    Ok(next.run(request).await)
}

/// Strict auth middleware — requires valid token for all requests
/// Used for REST API endpoints that need authentication
pub async fn require_auth(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(token) = extract_token(&request) {
        let store = state.identity_store.read().await;
        if let Some(identity) = store.find_by_token(&token) {
            tracing::debug!("API authenticated as: {}", identity.name);
            request
                .extensions_mut()
                .insert(IdentityName(identity.name.clone()));
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

// ══════════════════════════════════════════════════════════════════════════════
// P8.1: Rate Limiting Middleware
// ══════════════════════════════════════════════════════════════════════════════

/// Rate limit middleware
/// Applies rate limits based on IP and identity
pub async fn rate_limit(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Skip if rate limiter not initialized
    let Some(rate_limiter) = &state.rate_limiter else {
        return Ok(next.run(request).await);
    };

    // Determine rate limit kind based on path
    let path = request.uri().path().to_string();
    let kind = RateLimitKind::from_path(&path);

    // Extract IP (from X-Forwarded-For or direct peer)
    let ip = extract_ip(&request);

    // Get identity (anonymous if not authenticated)
    let identity = request
        .extensions()
        .get::<IdentityName>()
        .map(|i| i.0.clone())
        .unwrap_or_else(|| "anonymous".into());

    // Check rate limit
    let result = rate_limiter.check(&ip, &identity, kind).await;

    match result {
        RateLimitResult::Allowed { remaining, reset_in } => {
            // Add rate limit headers
            let mut response = next.run(request).await;
            add_rate_limit_headers(response.headers_mut(), remaining, reset_in);
            Ok(response)
        }
        RateLimitResult::Denied { reason, retry_after: _ } => {
            tracing::warn!(
                "Rate limit exceeded: ip={}, identity={}, kind={:?}, reason={}",
                ip,
                identity,
                kind,
                reason
            );
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}

/// Extract client IP from request
fn extract_ip(request: &Request) -> String {
    // Check X-Forwarded-For header
    if let Some(xff) = request.headers().get("X-Forwarded-For") {
        if let Ok(xff_str) = xff.to_str() {
            // Take the first IP (original client)
            if let Some(ip) = xff_str.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    // Check X-Real-IP header
    if let Some(xri) = request.headers().get("X-Real-IP") {
        if let Ok(ip) = xri.to_str() {
            return ip.trim().to_string();
        }
    }

    // Fall back to peer address
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Add rate limit headers to response
fn add_rate_limit_headers(headers: &mut HeaderMap, remaining: u32, reset: u32) {
    headers.insert("X-RateLimit-Remaining", HeaderValue::from(remaining));
    headers.insert("X-RateLimit-Reset", HeaderValue::from(reset));
    headers.insert("X-RateLimit-Limit", HeaderValue::from(100)); // TODO: dynamic
}
