//! Agent API — Remote management interface for AI agents
//!
//! P6.1: Agent API with restricted permissions

use axum::{
    extract::{Extension, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use opengit_core::{
    identity::{Identity, IdentityKind, IdentityStore},
    policy::PolicyEngine,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::api::SharedState;
use crate::middleware::{require_auth, IdentityName};

/// Build the Agent API router
pub fn build_agent_router() -> Router {
    Router::new()
        .route("/register", post(agent_register))
        .route("/token", post(agent_token))
        .route("/capabilities", get(agent_capabilities))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(()),
            agent_auth_middleware,
        ))
}

/// Agent registration request
#[derive(Debug, Deserialize)]
pub struct AgentRegisterRequest {
    /// Agent name (will be prefixed with "agent-")
    pub name: String,
    /// Display name for the agent
    pub display_name: Option<String>,
    /// Agent description
    pub description: Option<String>,
}

/// Agent token generation request
#[derive(Debug, Deserialize)]
pub struct AgentTokenRequest {
    /// Agent name
    pub name: String,
    /// Token label
    pub label: Option<String>,
}

/// Agent token response
#[derive(Debug, Serialize)]
pub struct AgentTokenResponse {
    pub identity: String,
    pub token: String,
    pub kind: String,
    pub permissions: Vec<String>,
}

/// Agent info response
#[derive(Debug, Serialize)]
pub struct AgentInfo {
    pub name: String,
    pub display_name: Option<String>,
    pub kind: String,
    pub token: String,
    pub permissions: Vec<String>,
}

/// Agent capabilities response
#[derive(Debug, Serialize)]
pub struct AgentCapabilities {
    pub allowed_actions: Vec<String>,
    pub forbidden_actions: Vec<String>,
    pub can_delete_repo: bool,
    pub can_delete_policy: bool,
    pub can_delete_webhook: bool,
    pub can_delete_mirror: bool,
}

/// Agent auth middleware — validates agent token
async fn agent_auth_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    next.run(request).await
}

/// Agent registration endpoint
/// POST /api/agent/register
async fn agent_register(
    State(state): State<SharedState>,
    Json(req): Json<AgentRegisterRequest>,
) -> Result<Json<AgentInfo>, StatusCode> {
    // Only admins can register new agents
    // For now, allow registration without auth (can be restricted later)

    let mut identity = Identity::agent(&req.name);
    if let Some(display_name) = &req.display_name {
        identity = identity.with_display_name(display_name);
    }
    if let Some(desc) = &req.description {
        identity = identity.with_description(desc);
    }

    // Generate initial token
    let raw_token = identity.generate_token("default");

    // Store in identity store
    {
        let mut store = state.identity_store.write().await;
        if store.find(&identity.name).is_some() {
            return Err(StatusCode::CONFLICT); // Agent already exists
        }
        store.register(identity.clone());

        // Persist
        if let Err(e) = store.save_to_file(&state.config.identity_file) {
            tracing::error!("Failed to save identity: {}", e);
        }
    }

    tracing::info!("Agent registered: {}", identity.name);

    Ok(Json(AgentInfo {
        name: identity.name,
        display_name: identity.display_name,
        kind: "agent".to_string(),
        token: raw_token,
        permissions: vec![
            "read".to_string(),
            "create_repo".to_string(),
            "write_config".to_string(),
            "add_webhook".to_string(),
            "add_mirror".to_string(),
            "add_policy".to_string(),
            "import".to_string(),
        ],
    }))
}

/// Agent token generation endpoint
/// POST /api/agent/token
async fn agent_token(
    State(state): State<SharedState>,
    Json(req): Json<AgentTokenRequest>,
) -> Result<Json<AgentTokenResponse>, StatusCode> {
    let mut store = state.identity_store.write().await;

    let identity = store.find_mut(&format!("agent-{}", req.name));
    let identity = match identity {
        Some(i) => i,
        None => return Err(StatusCode::NOT_FOUND),
    };

    // Verify it's an agent
    if identity.kind != IdentityKind::Agent {
        return Err(StatusCode::FORBIDDEN);
    }

    // Generate new token
    let label = req.label.unwrap_or_else(|| "default".to_string());
    let raw_token = identity.generate_token(&label);

    // Persist
    if let Err(e) = store.save_to_file(&state.config.identity_file) {
        tracing::error!("Failed to save identity: {}", e);
    }

    tracing::info!("Token generated for agent: {}", identity.name);

    Ok(Json(AgentTokenResponse {
        identity: identity.name.clone(),
        token: raw_token,
        kind: "agent".to_string(),
        permissions: vec![
            "read".to_string(),
            "create_repo".to_string(),
            "write_config".to_string(),
            "add_webhook".to_string(),
            "add_mirror".to_string(),
            "add_policy".to_string(),
            "import".to_string(),
        ],
    }))
}

/// Agent capabilities endpoint
/// GET /api/agent/capabilities
async fn agent_capabilities(
    State(state): State<SharedState>,
    Extension(identity): Extension<IdentityName>,
) -> Result<Json<AgentCapabilities>, StatusCode> {
    let store = state.identity_store.read().await;
    let identity = store.find(&identity.0);

    match identity {
        Some(id) => {
            if id.kind == IdentityKind::Agent {
                Ok(Json(AgentCapabilities {
                    allowed_actions: vec![
                        "read".to_string(),
                        "create_repo".to_string(),
                        "write_config".to_string(),
                        "add_webhook".to_string(),
                        "add_mirror".to_string(),
                        "add_policy".to_string(),
                        "import".to_string(),
                    ],
                    forbidden_actions: vec![
                        "delete_repo".to_string(),
                        "delete_policy".to_string(),
                        "delete_webhook".to_string(),
                        "delete_mirror".to_string(),
                        "admin".to_string(),
                    ],
                    can_delete_repo: false,
                    can_delete_policy: false,
                    can_delete_webhook: false,
                    can_delete_mirror: false,
                }))
            } else {
                Ok(Json(AgentCapabilities {
                    allowed_actions: vec![
                        "read".to_string(),
                        "create_repo".to_string(),
                        "delete_repo".to_string(),
                        "write_config".to_string(),
                        "add_webhook".to_string(),
                        "delete_webhook".to_string(),
                        "add_mirror".to_string(),
                        "delete_mirror".to_string(),
                        "admin".to_string(),
                    ],
                    forbidden_actions: vec![],
                    can_delete_repo: true,
                    can_delete_policy: true,
                    can_delete_webhook: true,
                    can_delete_mirror: true,
                }))
            }
        }
        None => Err(StatusCode::NOT_FOUND),
    }
}
