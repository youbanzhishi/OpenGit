//! REST API — Repository management, policy, and identity endpoints

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use opengit_core::{
    audit::AuditLog,
    identity::{Identity, IdentityKind, IdentityStore},
    policy::{Action, EvalResult, Permission, Policy, PolicyEngine, PolicyRule},
    repository::Repository,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;

use crate::config::ServerConfig;
use crate::middleware::SharedIdentityStore;

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

    let app = Router::new()
        // Health check
        .route("/health", get(health))
        // REST API
        .route("/api/repos", get(list_repos))
        .route("/api/repos/{name}", get(get_repo))
        .route("/api/repos/{name}/refs", get(get_repo_refs))
        .route("/api/policy/eval", post(eval_policy))
        .route("/api/identities", get(list_identities))
        .route("/api/audit", get(get_audit))
        // Smart HTTP (Git protocol)
        .route("/{repo}/info/refs", get(crate::smart_http::info_refs))
        .route(
            "/{repo}/git-upload-pack",
            post(crate::smart_http::upload_pack),
        )
        .route(
            "/{repo}/git-receive-pack",
            post(crate::smart_http::receive_pack),
        )
        .with_state(state);

    Ok(app)
}

async fn health() -> &'static str {
    "🐉 OpenGit OK"
}

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

async fn eval_policy(
    State(state): State<SharedState>,
    Json(req): Json<EvalRequest>,
) -> Json<EvalResult> {
    let result = state
        .policy_engine
        .evaluate(&req.repo, &req.identity, req.action);
    Json(result)
}

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

async fn get_audit(State(state): State<SharedState>) -> Json<Vec<opengit_core::audit::AuditEntry>> {
    Json(state.audit_log.entries())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoInfo {
    pub name: String,
    pub path: String,
    pub bare: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefInfo {
    pub name: String,
    pub sha: String,
    pub kind: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvalRequest {
    pub repo: String,
    pub identity: String,
    pub action: Action,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityInfo {
    pub name: String,
    pub kind: String,
    pub display_name: Option<String>,
    pub token_count: usize,
}
