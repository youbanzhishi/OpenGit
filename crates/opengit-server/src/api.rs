//! REST API — Repository management, policy, identity, webhook, and stats endpoints
//!
//! P3: Added repo size endpoint, bulk repo operations, ref-specific webhooks.
//! P5: Added mirror management endpoints.

use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    middleware,
    routing::{delete, get, post},
    Json, Router,
};
use opengit_core::{
    audit::AuditLog,
    identity::{Identity, IdentityStore},
    policy::{Action, EvalResult, Policy, PolicyEngine, PolicyRule},
    repository::Repository,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::ServerConfig;
use crate::middleware::{require_auth, smart_http_auth, IdentityName};
use crate::stats::ServerStats;
use crate::webhook::WebhookConfig;
use opengit_core::mirror::{MirrorTarget, MirrorsFile};

pub struct AppState {
    pub config: ServerConfig,
    pub policy_engine: RwLock<PolicyEngine>,
    pub identity_store: RwLock<IdentityStore>,
    pub audit_log: AuditLog,
    pub webhooks: RwLock<Vec<WebhookConfig>>,
    pub stats: ServerStats,
    pub mirrors: RwLock<MirrorsFile>,
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

    let webhooks = if config.webhook_file.exists() {
        let content = std::fs::read_to_string(&config.webhook_file).unwrap_or_default();
        serde_yaml::from_str(&content).unwrap_or_default()
    } else {
        Vec::new()
    };

    let audit_log = if !config.audit_file.to_string_lossy().is_empty() {
        AuditLog::with_file(&config.audit_file)
    } else {
        AuditLog::new()
    };

    let mirrors = if config.mirror_file.exists() {
        MirrorsFile::load(&config.mirror_file)?
    } else {
        MirrorsFile::default()
    };
    let state = Arc::new(AppState {
        config: config.clone(),
        policy_engine: RwLock::new(policy_engine),
        identity_store: RwLock::new(identity_store),
        audit_log,
        webhooks: RwLock::new(webhooks),
        stats: ServerStats::new(),
        mirrors: RwLock::new(mirrors),
    });

    // Smart HTTP routes — with optional auth middleware
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

    // REST API routes — with auth middleware
    let api_routes = Router::new()
        .route("/repos", get(list_repos).post(create_repo))
        .route("/repos/{name}", get(get_repo).delete(delete_repo))
        .route("/repos/{name}/refs", get(get_repo_refs))
        .route("/repos/{name}/reflog/{ref_name}", get(get_repo_reflog))
        .route("/repos/{name}/size", get(get_repo_size))
        .route("/repos/bulk/create", post(bulk_create_repos))
        .route("/policy/eval", post(eval_policy))
        .route(
            "/policy/rules",
            get(list_policy_rules).post(add_policy_rule),
        )
        .route("/identities", get(list_identities).post(register_identity))
        .route("/identities/{name}/tokens", post(generate_token))
        .route(
            "/identities/{name}",
            get(get_identity).delete(delete_identity),
        )
        .route("/audit", get(get_audit))
        .route("/audit/denied", get(get_denied_audit))
        .route("/webhooks", get(list_webhooks).post(add_webhook))
        .route("/webhooks/{idx}", delete(delete_webhook))
        .route("/stats", get(get_stats))
        .route("/mirrors", get(list_mirrors).post(add_mirror))
        .route("/mirrors/{idx}", delete(delete_mirror))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let app = Router::new()
        .route("/health", get(health))
        .nest("/api", api_routes)
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
    Extension(identity): Extension<IdentityName>,
    Json(req): Json<CreateRepoRequest>,
) -> Result<Json<RepoInfo>, StatusCode> {
    // Check Admin permission
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate(&req.name, &identity.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let repo = Repository::create(&state.config.repos_dir, &req.name).map_err(|e| {
        tracing::error!("Failed to create repo: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Install hooks
    if let Err(e) = install_hooks(&repo.path) {
        tracing::warn!("Failed to install hooks for {}: {}", req.name, e);
    }

    state.audit_log.log(opengit_core::audit::AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        repo: req.name.clone(),
        identity: identity.0.clone(),
        action: "CreateRepo".into(),
        ref_name: None,
        allowed: true,
        reason: None,
    });

    tracing::info!("Created repo: {} by {}", req.name, identity.0);
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
    Extension(identity): Extension<IdentityName>,
) -> Result<StatusCode, StatusCode> {
    // Check DeleteRepo permission
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate(&name, &identity.0, Action::DeleteRepo);
        if !result.is_allowed() {
            state.audit_log.log(opengit_core::audit::AuditEntry {
                timestamp: chrono::Utc::now().to_rfc3339(),
                repo: name.clone(),
                identity: identity.0.clone(),
                action: "DeleteRepo".into(),
                ref_name: None,
                allowed: false,
                reason: result.reason.clone(),
            });
            return Err(StatusCode::FORBIDDEN);
        }
    }

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

    state.audit_log.log(opengit_core::audit::AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        repo: name.clone(),
        identity: identity.0.clone(),
        action: "DeleteRepo".into(),
        ref_name: None,
        allowed: true,
        reason: Some("Moved to trash".into()),
    });

    tracing::info!("Deleted repo: {} by {} (moved to trash)", name, identity.0);
    Ok(StatusCode::NO_CONTENT)
}

// ─── Repo refs and size ────────────────────────────────────────────

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
            kind: format!("{:?}", r.kind).to_kebab_case(),
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

    let reflog = repo
        .reflog(&ref_name)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let infos: Vec<ReflogEntryInfo> = reflog
        .iter()
        .map(|e| ReflogEntryInfo {
            old_sha: e.old_sha.clone(),
            new_sha: e.new_sha.clone(),
            message: e.message.clone(),
        })
        .collect();

    Ok(Json(infos))
}

/// GET /api/repos/{name}/size — Get repository disk size
async fn get_repo_size(
    Path(name): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<RepoSizeInfo>, StatusCode> {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    if !repo_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    let repo = Repository::open(&repo_path).map_err(|_| StatusCode::NOT_FOUND)?;
    let size_bytes = repo
        .size_bytes()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(RepoSizeInfo {
        name,
        size_bytes,
        size_human: humanize_bytes(size_bytes),
    }))
}

/// POST /api/repos/bulk/create — Create multiple repositories at once
async fn bulk_create_repos(
    State(state): State<SharedState>,
    Extension(identity): Extension<IdentityName>,
    Json(req): Json<BulkCreateReposRequest>,
) -> Result<Json<BulkCreateReposResponse>, StatusCode> {
    // Check Admin permission
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &identity.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let mut created = Vec::new();
    let mut failed = Vec::new();

    for name in &req.names {
        match Repository::create(&state.config.repos_dir, name) {
            Ok(repo) => {
                if let Err(e) = install_hooks(&repo.path) {
                    tracing::warn!("Failed to install hooks for {}: {}", name, e);
                }
                created.push(name.clone());

                state.audit_log.log(opengit_core::audit::AuditEntry {
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    repo: name.clone(),
                    identity: identity.0.clone(),
                    action: "CreateRepo".into(),
                    ref_name: None,
                    allowed: true,
                    reason: None,
                });
            }
            Err(e) => {
                tracing::warn!("Failed to create repo {}: {}", name, e);
                failed.push(BulkCreateFailure {
                    name: name.clone(),
                    reason: e.to_string(),
                });
            }
        }
    }

    tracing::info!(
        "Bulk create: {} created, {} failed by {}",
        created.len(),
        failed.len(),
        identity.0
    );

    Ok(Json(BulkCreateReposResponse { created, failed }))
}

// ─── Policy endpoints ───────────────────────────────────────────────

async fn eval_policy(
    State(state): State<SharedState>,
    Json(req): Json<EvalRequest>,
) -> Result<Json<EvalResult>, StatusCode> {
    let engine = state.policy_engine.read().await;
    let result = engine.evaluate(&req.repo, &req.identity, req.action);
    Ok(Json(result))
}

async fn list_policy_rules(
    State(state): State<SharedState>,
) -> Result<Json<Vec<PolicyRuleInfo>>, StatusCode> {
    let engine = state.policy_engine.read().await;

    let mut rules = Vec::new();

    // Custom policies
    for policy in engine.custom_policies() {
        for rule in &policy.rules {
            rules.push(PolicyRuleInfo {
                repo: policy.repo.clone(),
                identity: rule.identity.clone(),
                action: format!("{:?}", rule.action).to_kebab_case(),
                permission: format!("{:?}", rule.permission).to_kebab_case(),
                reason: rule.reason.clone(),
            });
        }
    }

    // Default policy
    for rule in &engine.default_policy().rules {
        rules.push(PolicyRuleInfo {
            repo: "*".into(),
            identity: rule.identity.clone(),
            action: format!("{:?}", rule.action).to_kebab_case(),
            permission: format!("{:?}", rule.permission).to_kebab_case(),
            reason: rule.reason.clone(),
        });
    }

    Ok(Json(rules))
}

async fn add_policy_rule(
    State(state): State<SharedState>,
    Extension(caller): Extension<IdentityName>,
    Json(req): Json<AddPolicyRuleRequest>,
) -> Result<StatusCode, StatusCode> {
    // Only admins can add policy rules
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &caller.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let action = parse_action(&req.action).ok_or(StatusCode::BAD_REQUEST)?;
    let permission = parse_permission(&req.permission).ok_or(StatusCode::BAD_REQUEST)?;

    let rule = PolicyRule {
        identity: req.identity.clone(),
        action,
        permission,
        reason: req.reason.clone(),
    };

    {
        let mut engine = state.policy_engine.write().await;
        let repo = req.repo.as_deref().unwrap_or("*");

        // Find or create policy for this repo
        let found = engine
            .custom_policies_mut()
            .iter_mut()
            .find(|p| p.repo == repo);
        if let Some(policy) = found {
            policy.add_rule(rule);
        } else {
            let mut policy = Policy::new(repo);
            policy.add_rule(rule);
            engine.add_policy(policy);
        }

        // Persist
        if let Err(e) = engine.save_to_file(&state.config.policy_file) {
            tracing::error!("Failed to save policy file: {}", e);
        }
    }

    state.audit_log.log(opengit_core::audit::AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        repo: req.repo.clone().unwrap_or_else(|| "*".into()),
        identity: caller.0.clone(),
        action: "AddPolicyRule".into(),
        ref_name: None,
        allowed: true,
        reason: Some(format!(
            "Added rule: {} → {:?} → {:?}",
            req.identity, action, permission
        )),
    });

    tracing::info!("Policy rule added by {}", caller.0);
    Ok(StatusCode::CREATED)
}

// ─── Identity endpoints ─────────────────────────────────────────────

async fn list_identities(State(state): State<SharedState>) -> Json<Vec<IdentityInfo>> {
    let store = state.identity_store.read().await;
    let infos: Vec<IdentityInfo> = store
        .list()
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

async fn get_identity(
    Path(name): Path<String>,
    State(state): State<SharedState>,
) -> Result<Json<IdentityInfo>, StatusCode> {
    let store = state.identity_store.read().await;
    let identity = store.find(&name).ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(IdentityInfo {
        name: identity.name.clone(),
        kind: if identity.is_agent() {
            "agent".into()
        } else {
            "human".into()
        },
        display_name: identity.display_name.clone(),
        token_count: identity.tokens.len(),
    }))
}

async fn register_identity(
    State(state): State<SharedState>,
    Extension(caller): Extension<IdentityName>,
    Json(req): Json<RegisterIdentityRequest>,
) -> Result<Json<IdentityInfo>, StatusCode> {
    // Only admins can register identities
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &caller.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let mut identity = match req.kind.as_str() {
        "agent" => Identity::agent(&req.name),
        "human" => Identity::human(&req.name),
        _ => return Err(StatusCode::BAD_REQUEST),
    };

    if let Some(display_name) = &req.display_name {
        identity = identity.with_display_name(display_name);
    }

    let info = IdentityInfo {
        name: identity.name.clone(),
        kind: req.kind.clone(),
        display_name: identity.display_name.clone(),
        token_count: identity.tokens.len(),
    };

    {
        let mut store = state.identity_store.write().await;
        store.register(identity);
        if let Err(e) = store.save_to_file(&state.config.identity_file) {
            tracing::error!("Failed to save identity file: {}", e);
        }
    }

    state.audit_log.log(opengit_core::audit::AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        repo: "*".into(),
        identity: caller.0.clone(),
        action: "RegisterIdentity".into(),
        ref_name: None,
        allowed: true,
        reason: Some(format!("Registered {} ({})", info.name, info.kind)),
    });

    tracing::info!(
        "Identity registered: {} ({}) by {}",
        req.name,
        req.kind,
        caller.0
    );
    Ok(Json(info))
}

async fn generate_token(
    Path(name): Path<String>,
    State(state): State<SharedState>,
    Extension(caller): Extension<IdentityName>,
    Json(req): Json<GenerateTokenRequest>,
) -> Result<Json<GenerateTokenResponse>, StatusCode> {
    let is_self = caller.0 == name;
    if !is_self {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &caller.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    let secret = {
        let mut store = state.identity_store.write().await;
        let identity = store.find_mut(&name).ok_or(StatusCode::NOT_FOUND)?;
        let secret = identity.generate_token(&req.label);
        if let Err(e) = store.save_to_file(&state.config.identity_file) {
            tracing::error!("Failed to save identity file: {}", e);
        }
        secret
    };

    state.audit_log.log(opengit_core::audit::AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        repo: "*".into(),
        identity: caller.0.clone(),
        action: "GenerateToken".into(),
        ref_name: None,
        allowed: true,
        reason: Some(format!("Token '{}' generated for {}", req.label, name)),
    });

    tracing::info!("Token generated for {} by {}", name, caller.0);
    Ok(Json(GenerateTokenResponse {
        identity: name,
        token: secret,
        label: req.label,
    }))
}

async fn delete_identity(
    Path(name): Path<String>,
    State(state): State<SharedState>,
    Extension(caller): Extension<IdentityName>,
) -> Result<StatusCode, StatusCode> {
    // Only admins can delete identities
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &caller.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    {
        let mut store = state.identity_store.write().await;
        if store.find(&name).is_none() {
            return Err(StatusCode::NOT_FOUND);
        }
        store.remove(&name);
        if let Err(e) = store.save_to_file(&state.config.identity_file) {
            tracing::error!("Failed to save identity file: {}", e);
        }
    }

    state.audit_log.log(opengit_core::audit::AuditEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        repo: "*".into(),
        identity: caller.0.clone(),
        action: "DeleteIdentity".into(),
        ref_name: None,
        allowed: true,
        reason: Some(format!("Deleted identity {}", name)),
    });

    tracing::info!("Identity deleted: {} by {}", name, caller.0);
    Ok(StatusCode::NO_CONTENT)
}

// ─── Audit endpoints ────────────────────────────────────────────────

async fn get_audit(State(state): State<SharedState>) -> Json<Vec<opengit_core::audit::AuditEntry>> {
    Json(state.audit_log.recent(100))
}

async fn get_denied_audit(
    State(state): State<SharedState>,
) -> Json<Vec<opengit_core::audit::AuditEntry>> {
    Json(state.audit_log.denied_entries())
}

// ─── Webhook endpoints ──────────────────────────────────────────────

async fn list_webhooks(State(state): State<SharedState>) -> Json<Vec<WebhookConfig>> {
    let webhooks = state.webhooks.read().await;
    Json(webhooks.clone())
}

async fn add_webhook(
    State(state): State<SharedState>,
    Extension(caller): Extension<IdentityName>,
    Json(req): Json<AddWebhookRequest>,
) -> Result<StatusCode, StatusCode> {
    // Only admins can add webhooks
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &caller.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    {
        let mut webhooks = state.webhooks.write().await;
        webhooks.push(req.into_config());
        if let Ok(content) = serde_yaml::to_string(&*webhooks) {
            if let Some(parent) = state.config.webhook_file.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(&state.config.webhook_file, content);
        }
    }

    tracing::info!("Webhook added by {}", caller.0);
    Ok(StatusCode::CREATED)
}

async fn delete_webhook(
    Path(idx): Path<usize>,
    State(state): State<SharedState>,
    Extension(caller): Extension<IdentityName>,
) -> Result<StatusCode, StatusCode> {
    // Only admins can delete webhooks
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &caller.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    {
        let mut webhooks = state.webhooks.write().await;
        if idx >= webhooks.len() {
            return Err(StatusCode::NOT_FOUND);
        }
        webhooks.remove(idx);
        if let Ok(content) = serde_yaml::to_string(&*webhooks) {
            let _ = std::fs::write(&state.config.webhook_file, content);
        }
    }

    tracing::info!("Webhook {} deleted by {}", idx, caller.0);
    Ok(StatusCode::NO_CONTENT)
}

// ─── Stats endpoint ─────────────────────────────────────────────────

async fn get_stats(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let total_repos = Repository::scan_dir(&state.config.repos_dir)
        .map(|r| r.len())
        .unwrap_or(0);
    let snapshot = state.stats.snapshot();
    Json(serde_json::json!({
        "total_repos": total_repos,
        "total_pushes": snapshot.total_pushes,
        "total_clones": snapshot.total_clones,
        "total_denials": snapshot.total_denials,
        "total_webhooks_sent": snapshot.total_webhooks_sent,
        "uptime_seconds": snapshot.uptime_seconds,
    }))
}

// ─── Helpers ────────────────────────────────────────────────────────

fn install_hooks(repo_path: &std::path::Path) -> anyhow::Result<()> {
    opengit_storage::HookInstaller::install(repo_path)
}

fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
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

fn parse_action(s: &str) -> Option<Action> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "push" => Some(Action::Push),
        "force_push" | "forcepush" => Some(Action::ForcePush),
        "delete_branch" | "deletebranch" => Some(Action::DeleteBranch),
        "delete_repo" | "deleterepo" => Some(Action::DeleteRepo),
        "tag" => Some(Action::Tag),
        "merge" => Some(Action::Merge),
        "reset_staging" | "resetstaging" => Some(Action::ResetStaging),
        "add_all" | "addall" => Some(Action::AddAll),
        "stash" => Some(Action::Stash),
        "admin" => Some(Action::Admin),
        "read" => Some(Action::Read),
        _ => None,
    }
}

fn parse_permission(s: &str) -> Option<opengit_core::policy::Permission> {
    match s.to_lowercase().replace('-', "_").as_str() {
        "allow" => Some(opengit_core::policy::Permission::Allow),
        "deny" => Some(opengit_core::policy::Permission::Deny),
        "confirm" => Some(opengit_core::policy::Permission::Confirm),
        "audit_log" | "auditlog" => Some(opengit_core::policy::Permission::AuditLog),
        _ => None,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoInfo {
    pub name: String,
    pub path: String,
    pub bare: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoSizeInfo {
    pub name: String,
    pub size_bytes: u64,
    pub size_human: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRepoRequest {
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BulkCreateReposRequest {
    pub names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BulkCreateReposResponse {
    pub created: Vec<String>,
    pub failed: Vec<BulkCreateFailure>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BulkCreateFailure {
    pub name: String,
    pub reason: String,
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
    pub repo: String,
    pub identity: String,
    pub action: String,
    pub permission: String,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddPolicyRuleRequest {
    pub repo: Option<String>,
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
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateTokenRequest {
    pub label: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateTokenResponse {
    pub identity: String,
    pub token: String,
    pub label: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddWebhookRequest {
    pub url: String,
    pub secret: Option<String>,
    pub events: Option<Vec<String>>,
}

impl AddWebhookRequest {
    pub fn into_config(self) -> WebhookConfig {
        use crate::webhook::WebhookEvent;
        let events = self
            .events
            .map(|evts| {
                evts.iter()
                    .filter_map(|e| match e.as_str() {
                        "push" => Some(WebhookEvent::Push),
                        "tag" => Some(WebhookEvent::Tag),
                        "delete-branch" => Some(WebhookEvent::DeleteBranch),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_else(|| {
                vec![
                    WebhookEvent::Push,
                    WebhookEvent::Tag,
                    WebhookEvent::DeleteBranch,
                ]
            });

        WebhookConfig {
            url: self.url,
            secret: self.secret,
            events,
            active: true,
        }
    }
}

// ─── Mirror endpoints ────────────────────────────────────────────────

async fn list_mirrors(State(state): State<SharedState>) -> Json<Vec<MirrorTargetInfo>> {
    let mirrors = state.mirrors.read().await;
    let infos: Vec<MirrorTargetInfo> = mirrors
        .mirrors
        .iter()
        .map(|m| MirrorTargetInfo {
            name: m.name.clone(),
            url: m.url.clone(),
            repos: m.repos.clone(),
            refs: m.refs.clone(),
            enabled: m.enabled,
        })
        .collect();
    Json(infos)
}

async fn add_mirror(
    State(state): State<SharedState>,
    Extension(caller): Extension<IdentityName>,
    Json(req): Json<AddMirrorRequest>,
) -> Result<StatusCode, StatusCode> {
    // Only admins can add mirrors
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &caller.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    {
        let mut mirrors = state.mirrors.write().await;
        mirrors.mirrors.push(MirrorTarget {
            name: req.name,
            url: req.url,
            repos: req.repos.unwrap_or_default(),
            refs: req.refs.unwrap_or_default(),
            enabled: true,
        });
        if let Err(e) = mirrors.save_to_file(&state.config.mirror_file) {
            tracing::error!("Failed to save mirrors file: {}", e);
        }
    }

    tracing::info!("Mirror added by {}", caller.0);
    Ok(StatusCode::CREATED)
}

async fn delete_mirror(
    Path(idx): Path<usize>,
    State(state): State<SharedState>,
    Extension(caller): Extension<IdentityName>,
) -> Result<StatusCode, StatusCode> {
    // Only admins can delete mirrors
    {
        let engine = state.policy_engine.read().await;
        let result = engine.evaluate("*", &caller.0, Action::Admin);
        if !result.is_allowed() {
            return Err(StatusCode::FORBIDDEN);
        }
    }

    {
        let mut mirrors = state.mirrors.write().await;
        if idx >= mirrors.mirrors.len() {
            return Err(StatusCode::NOT_FOUND);
        }
        mirrors.mirrors.remove(idx);
        if let Err(e) = mirrors.save_to_file(&state.config.mirror_file) {
            tracing::error!("Failed to save mirrors file: {}", e);
        }
    }

    tracing::info!("Mirror {} deleted by {}", idx, caller.0);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MirrorTargetInfo {
    pub name: String,
    pub url: String,
    pub repos: Vec<String>,
    pub refs: Vec<String>,
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddMirrorRequest {
    pub name: String,
    pub url: String,
    pub repos: Option<Vec<String>>,
    pub refs: Option<Vec<String>>,
}
