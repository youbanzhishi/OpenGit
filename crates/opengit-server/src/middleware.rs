//! Authentication middleware — Token-based auth for Smart HTTP and REST API

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
            // Also support username:password in URL (git clone http://user:token@host/repo)
        }
    }

    None
}

/// Base64 decode helper
fn base64_decode(input: &str) -> Result<String, ()> {
    // Simple base64 decoder
    let decoded = base64_simd_decode(input)?;
    Ok(decoded)
}

/// Minimal base64 decode without external dependency
fn base64_simd_decode(input: &str) -> Result<String, ()> {
    const TABLE: &[u8; 128] = &{
        let mut table = [0u8; 128];
        table[b'A' as usize] = 0;
        table[b'B' as usize] = 1;
        table[b'C' as usize] = 2;
        table[b'D' as usize] = 3;
        table[b'E' as usize] = 4;
        table[b'F' as usize] = 5;
        table[b'G' as usize] = 6;
        table[b'H' as usize] = 7;
        table[b'I' as usize] = 8;
        table[b'J' as usize] = 9;
        table[b'K' as usize] = 10;
        table[b'L' as usize] = 11;
        table[b'M' as usize] = 12;
        table[b'N' as usize] = 13;
        table[b'O' as usize] = 14;
        table[b'P' as usize] = 15;
        table[b'Q' as usize] = 16;
        table[b'R' as usize] = 17;
        table[b'S' as usize] = 18;
        table[b'T' as usize] = 19;
        table[b'U' as usize] = 20;
        table[b'V' as usize] = 21;
        table[b'W' as usize] = 22;
        table[b'X' as usize] = 23;
        table[b'Y' as usize] = 24;
        table[b'Z' as usize] = 25;
        table[b'a' as usize] = 26;
        table[b'b' as usize] = 27;
        table[b'c' as usize] = 28;
        table[b'd' as usize] = 29;
        table[b'e' as usize] = 30;
        table[b'f' as usize] = 31;
        table[b'g' as usize] = 32;
        table[b'h' as usize] = 33;
        table[b'i' as usize] = 34;
        table[b'j' as usize] = 35;
        table[b'k' as usize] = 36;
        table[b'l' as usize] = 37;
        table[b'm' as usize] = 38;
        table[b'n' as usize] = 39;
        table[b'o' as usize] = 40;
        table[b'p' as usize] = 41;
        table[b'q' as usize] = 42;
        table[b'r' as usize] = 43;
        table[b's' as usize] = 44;
        table[b't' as usize] = 45;
        table[b'u' as usize] = 46;
        table[b'v' as usize] = 47;
        table[b'w' as usize] = 48;
        table[b'x' as usize] = 49;
        table[b'y' as usize] = 50;
        table[b'z' as usize] = 51;
        table[b'0' as usize] = 52;
        table[b'1' as usize] = 53;
        table[b'2' as usize] = 54;
        table[b'3' as usize] = 55;
        table[b'4' as usize] = 56;
        table[b'5' as usize] = 57;
        table[b'6' as usize] = 58;
        table[b'7' as usize] = 59;
        table[b'8' as usize] = 60;
        table[b'9' as usize] = 61;
        table[b'+' as usize] = 62;
        table[b'/' as usize] = 63;
        table
    };

    let input = input.trim_end_matches('=');
    let input_bytes = input.as_bytes();
    let mut result = Vec::with_capacity(input.len() * 3 / 4);

    let chunks = input_bytes.chunks(4);
    for chunk in chunks {
        let mut acc: u32 = 0;
        let mut bits = 0;
        for &b in chunk {
            if b >= 128 {
                return Err(());
            }
            acc = (acc << 6) | TABLE[b as usize] as u32;
            bits += 6;
        }
        while bits >= 8 {
            bits -= 8;
            result.push((acc >> bits) as u8);
        }
    }

    String::from_utf8(result).map_err(|_| ())
}

/// Auth middleware for Smart HTTP endpoints
///
/// This is an **optional** auth middleware — it allows anonymous access for
/// read operations (clone/fetch) but requires auth for write operations (push).
/// The Smart HTTP handlers do their own fine-grained permission checks.
pub async fn smart_http_auth(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Try to extract and validate token
    if let Some(token) = extract_token(&request) {
        if let Some(identity) = state.identity_store.find_by_token(&token) {
            tracing::debug!("Authenticated as: {}", identity.name);
            request
                .extensions_mut()
                .insert(IdentityName(identity.name.clone()));
            return Ok(next.run(request).await);
        }
    }

    // No valid token — allow through as anonymous (handlers will enforce permissions)
    // For push, the receive_pack handler will reject with 401
    Ok(next.run(request).await)
}

/// Strict auth middleware — requires valid token for all requests
/// Used for REST API endpoints that need authentication
#[allow(dead_code)]
pub async fn require_auth(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(token) = extract_token(&request) {
        if let Some(identity) = state.identity_store.find_by_token(&token) {
            request
                .extensions_mut()
                .insert(IdentityName(identity.name.clone()));
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
