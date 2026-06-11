//! Authentication middleware — Token-based auth for Smart HTTP and REST API
//!
//! P2: Uses `base64` crate for proper decoding, works with RwLock<IdentityStore>

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};

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
    mut request: Request,
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
