//! Authentication middleware

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use opengit_core::identity::IdentityStore;
use std::sync::Arc;

pub type SharedIdentityStore = Arc<IdentityStore>;

/// Extract identity from request (token in Authorization header or query param)
pub fn extract_identity(request: &Request) -> Option<String> {
    // Check Authorization header
    if let Some(auth) = request.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            // Bearer token or Basic auth
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
            if let Some(token) = auth_str.strip_prefix("Basic ") {
                return Some(token.to_string());
            }
        }
    }

    // Check query parameter
    if let Some(query) = request.uri().query() {
        for pair in query.split('&') {
            if let Some(token) = pair.strip_prefix("token=") {
                return Some(token.to_string());
            }
        }
    }

    None
}

/// Auth middleware
pub async fn auth_middleware(
    State(store): State<SharedIdentityStore>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(token) = extract_identity(&request) {
        if let Some(identity) = store.find_by_token(&token) {
            // Store identity name in request extensions
            request
                .extensions_mut()
                .insert(IdentityName(identity.name.clone()));
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// The authenticated identity name
#[derive(Clone)]
pub struct IdentityName(pub String);
