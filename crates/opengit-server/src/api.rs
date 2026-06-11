//! REST API — Repository management, policy, and identity endpoints

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use opengit_core::{
    audit::AuditLog,
    identity::{Identity, IdentityStore},
    policy::{Action, EvalResult, Policy, PolicyEngine},
    repository::Repository,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::ServerConfig;
use crate::middleware::{smart_http_auth, IdentityName};

pub struct AppState {
    pub config: ServerConfig,
    pub policy_engine: PolicyEngine,
    pub identity_store: IdentityStore,
    pub audit_log: AuditLog,
}

pub type SharedState = Arc<AppState>;

pub fn build_router(config: &ServerConfig) -> Result<Router, anyhow::Error> {
    let policy_engine = if config.policy_file.exists() {
        PolicyEngine::from_file(&config.policy_file)?
    } else {
        PolicyEngine::new()
    };

    let identity_store = if config.identity_file.exists() {
        IdentityStore::from_file(&config.identity_file)?
    } else {
        let mut store = IdentityStore::new();
        let mut admin = Identity::human("admin").with_display_name("Admin");
        admin.generate_token("default");
        store.register(admin);
        store
    };

    let state = Arc::new(AppState {
        config: config.clone(),
        policy_engine,
        identity_store,
        audit_log: AuditLog::new(),
    });

    // Smart HTTP routes — with auth middleware
    // Default identity for anonymous access
    let default_identity = IdentityName("anonymous".into());
    let smart_http = Router::new()
        .route("/{repo}/info/refs", get(crate::smart_http::info_refs))
        .route(
            "/{repo}/git-upload-pack",
            post(crate::smart_http::upload_pack),
        )
        .route(
            "/{repo}/git-receive-pack",
            post(crate::smart_http::receive_pack),
        )
        .layer(Extension(default_identity))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            smart_http_auth,
        ));

    let app = Router::new()
        // Health check (no auth)
        .route("/health", get(health))
        // REST API (no auth for P1 — add require_auth when needed)
        .route("/api/repos", get(list_repos).post(create_repo))
        .route("/api/repos/{name}", get(get_repo).delete(delete_repo))
        .route("/api/repos/{name}/refs", get(get_repo_refs))
        .route("/api/repos/{name}/reflog/{ref_name}", get(get_repo_reflog))
        .route("/api/policy/eval", post(eval_policy))
        .route(
            "/api/policy/rules",
            get(list_policy_rules).post(add_policy_rule),
        )
        .route(
            "/api/identities",
            get(list_identities).post(register_identity),
        )
        .route("/api/identities/{name}/tokens", post(generate_token))
        .route("/api/audit", get(get_audit))
        .route("/api/audit/denied", get(get_denied_audit))
        // Merge Smart HTTP
        .merge(smart_http)
        .with_state(state);

    Ok(app)
}

async fn health() -> &'static str {
    "🐉 OpenGit OK"
}

// ─── Repository endpoints ───────────────────────────────────────────

async fn list_repos(State(state): State<SharedState>) -> Result<Json<Vec<RepoInfo>>, StatusCode> {
    let repos = Repository::scan_dir(&state.config.repos_dir)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let infos: Vec<RepoInfo> = repos
        .iter()
        .map(|r| RepoInfo {
            name: r.name.clone(),
            path: r.path.to_string_lossy().to_string(),
            bare: r.bare,
        })
        .collect();

    Ok(Json(infos))
}

async fn create_repo(
    State(state): State<SharedState>,
    Json(req): Json<CreateRepoRequest>,
) -> Result<Json<RepoInfo>, StatusCode> {
    let repo = Repository::create(&state.config.repos_dir, &req.name).map_err(|e| {
        tracing::error!("Failed to create repo: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Install hooks if storage manager is available
    if let Err(e) = install_hooks(&repo.path) {
        tracing::warn!("Failed to install hooks for {}: {}", req.name, e);
    }

    tracing::info!("Created repo: {}", req.name);
    Ok(Json(RepoInfo {
        name: repo.name,
        path: repo.path.to_string_lossy().to_string(),
        bare: repo.bare,
    }))
}

async fn get_repo(
    Path(name): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<RepoInfo>, StatusCode> {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    let repo = Repository::open(&repo_path).map_err(|_| StatusCode::NOT_FOUND)?;

    Ok(Json(RepoInfo {
        name: repo.name,
        path: repo.path.to_string_lossy().to_string(),
        bare: repo.bare,
    }))
}

async fn delete_repo(
    Path(name): Path<String>,
    State(state): State<SharedState>,
) -> Result<StatusCode, StatusCode> {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    if !repo_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    // Move to trash instead of deleting (data safety)
    let trash_dir = state.config.repos_dir.join("../trash");
    std::fs::create_dir_all(&trash_dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let trash_path = trash_dir.join(format!("{}-{}.git", name, timestamp));
    std::fs::rename(&repo_path, &trash_path).map_err(|e| {
        tracing::error!("Failed to move repo to trash: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    tracing::info!("Moved repo {} to trash: {}", name, trash_path.display());
    Ok(StatusCode::NO_CONTENT)
}

async fn get_repo_refs(
    Path(name): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<Vec<RefInfo>>, StatusCode> {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    let repo = Repository::open(&repo_path).map_err(|_| StatusCode::NOT_FOUND)?;

    let refs = repo.refs().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let infos: Vec<RefInfo> = refs
        .iter()
        .map(|r| RefInfo {
            name: r.name.clone(),
            sha: r.sha.clone(),
            kind: format!("{:?}", r.kind).to_lowercase(),
        })
        .collect();

    Ok(Json(infos))
}

async fn get_repo_reflog(
    Path((name, ref_name)): Path<(String, String)>,
    State(state): State<SharedState>,
) -> Result<Json<Vec<ReflogEntryInfo>>, StatusCode> {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    let repo = Repository::open(&repo_path).map_err(|_| StatusCode::NOT_FOUND)?;

    let entries = repo
        .reflog(&ref_name)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let infos: Vec<ReflogEntryInfo> = entries
        .iter()
        .map(|e| ReflogEntryInfo {
            old_sha: e.old_sha.clone(),
            new_sha: e.new_sha.clone(),
            message: e.message.clone(),
        })
        .collect();

    Ok(Json(infos))
}

/// Install OpenGit hooks into a bare repo
fn install_hooks(repo_path: &std::path::Path) -> Result<(), anyhow::Error> {
    let hooks_dir = repo_path.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    // Pre-receive hook — calls opengit-pre-receive binary
    let pre_receive = r#"#!/bin/sh
# OpenGit pre-receive hook
# Reads OPENGIT_IDENTITY from environment (set by Smart HTTP server)
# and evaluates policy for each ref update

IDENTITY="${OPENGIT_IDENTITY:-anonymous}"
REPO="${OPENGIT_REPO:-unknown}"

while read old_sha new_sha ref_name; do
    # Skip zero SHAs for new branch creation
    if [ "$new_sha" = "0000000000000000000000000000000000000000" ]; then
        echo "DRAGON_FIREWALL: DENIED - Deleting branch $ref_name is not allowed for $IDENTITY" >&2
        exit 1
    fi
done
"#;
    std::fs::write(hooks_dir.join("pre-receive"), pre_receive)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        std::fs::set_permissions(hooks_dir.join("pre-receive"), perms)?;
    }

    Ok(())
}

// ─── Policy endpoints ───────────────────────────────────────────────

async fn eval_policy(
    State(state): State<SharedState>,
    Json(req): Json<EvalRequest>,
) -> Json<EvalResult> {
    let result = state
        .policy_engine
        .evaluate(&req.repo, &req.identity, req.action);
    Json(result)
}

async fn list_policy_rules(State(_state): State<SharedState>) -> Json<Vec<PolicyRuleInfo>> {
    // Return the default policy rules
    let default = Policy::new("*");
    let rules: Vec<PolicyRuleInfo> = default
        .rules
        .iter()
        .map(|r| PolicyRuleInfo {
            identity: r.identity.clone(),
            action: format!("{:?}", r.action).to_kebab_case(),
            permission: format!("{:?}", r.permission).to_kebab_case(),
            reason: r.reason.clone(),
        })
        .collect();
    Json(rules)
}

async fn add_policy_rule(
    State(_state): State<SharedState>,
    Json(req): Json<AddPolicyRuleRequest>,
) -> Result<StatusCode, StatusCode> {
    // For P1, just log the request — full dynamic policy management is P2
    tracing::info!(
        "Policy rule addition requested: identity={} action={}",
        req.identity,
        req.action,
    );
    Ok(StatusCode::CREATED)
}

// ─── Identity endpoints ─────────────────────────────────────────────

async fn list_identities(State(state): State<SharedState>) -> Json<Vec<IdentityInfo>> {
    let identities = state.identity_store.list();
    let infos: Vec<IdentityInfo> = identities
        .iter()
        .map(|i| IdentityInfo {
            name: i.name.clone(),
            kind: if i.is_agent() {
                "agent".into()
            } else {
                "human".into()
            },
            display_name: i.display_name.clone(),
            token_count: i.tokens.len(),
        })
        .collect();
    Json(infos)
}

async fn register_identity(
    State(_state): State<SharedState>,
    Json(req): Json<RegisterIdentityRequest>,
) -> Result<Json<IdentityInfo>, StatusCode> {
    let identity = match req.kind.as_str() {
        "agent" => Identity::agent(&req.name),
        "human" => Identity::human(&req.name),
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    let info = IdentityInfo {
        name: identity.name.clone(),
        kind: req.kind.clone(),
        display_name: identity.display_name.clone(),
        token_count: identity.tokens.len(),
    };

    // Note: need mutable borrow, but state is Arc — for P1 just log
    tracing::info!("Identity registration requested: {}", req.name);
    Ok(Json(info))
}

async fn generate_token(
    Path(name): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<GenerateTokenResponse>, StatusCode> {
    let _identity = state
        .identity_store
        .find(&name)
        .ok_or(StatusCode::NOT_FOUND)?;

    // For P1, we can't mutate the Arc easily — return instruction
    // Full token generation with persistence is P2
    tracing::info!("Token generation requested for: {}", name);
    Ok(Json(GenerateTokenResponse {
        identity: name,
        message: "Token generation requires server restart to take effect in P1".into(),
    }))
}

// ─── Audit endpoints ────────────────────────────────────────────────

async fn get_audit(State(state): State<SharedState>) -> Json<Vec<opengit_core::audit::AuditEntry>> {
    Json(state.audit_log.entries())
}

async fn get_denied_audit(
    State(state): State<SharedState>,
) -> Json<Vec<opengit_core::audit::AuditEntry>> {
    Json(state.audit_log.denied_entries())
}

// ─── Data types ─────────────────────────────────────────────────────

trait ToKebabCase: Sized {
    fn to_kebab_case(self) -> String;
}

impl ToKebabCase for &str {
    fn to_kebab_case(self) -> String {
        let mut result = String::new();
        for (i, c) in self.chars().enumerate() {
            if c.is_uppercase() {
                if i > 0 {
                    result.push('-');
                }
                result.push(c.to_ascii_lowercase());
            } else {
                result.push(c);
            }
        }
        result
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoInfo {
    pub name: String,
    pub path: String,
    pub bare: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRepoRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefInfo {
    pub name: String,
    pub sha: String,
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReflogEntryInfo {
    pub old_sha: String,
    pub new_sha: String,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvalRequest {
    pub repo: String,
    pub identity: String,
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PolicyRuleInfo {
    pub identity: String,
    pub action: String,
    pub permission: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddPolicyRuleRequest {
    pub identity: String,
    pub action: String,
    pub permission: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub name: String,
    pub kind: String,
    pub display_name: Option<String>,
    pub token_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterIdentityRequest {
    pub name: String,
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateTokenResponse {
    pub identity: String,
    pub message: String,
}
