//! Web UI — External interface for OpenGit
//!
//! Provides a Gitea-like web interface with:
//! - Repository list page
//! - Repository detail page with clone URLs
//! - Clone address modal (HTTP/SSH)
//! - Automation configuration (Webhooks, Mirrors, Policies)
//!
//! All HTML/CSS/JS is embedded using `include_str!` macro.

use axum::{
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use opengit_core::{
    email_notifier::EmailConfig,
    file_append::{append_file, file_exists, list_files, AppendFileRequest},
    mirror::MirrorsFile,
    repository::{RefInfo, Repository},
    webhook::WebhookConfig,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::config::ServerConfig;
use crate::middleware::IdentityName;
use crate::AppState;

// ══════════════════════════════════════════════════════════════════════════════
// Router
// ══════════════════════════════════════════════════════════════════════════════

/// Build the Web UI router
pub fn build_web_ui_router() -> Router {
    Router::new()
        .route("/", get(index_page))
        .route("/repos", get(repos_page))
        .route("/repos/{name}", get(repo_detail_page))
        .route("/repos/{name}/automation", get(automation_page))
        .route("/repos/new", get(new_repo_page))
        .route("/settings/email", get(email_settings_page))
        // API endpoints
        .route("/api/list", get(api_list_repos))
        .route("/api/repos", get(api_list_repos))
        .route("/api/repos/{name}", get(api_get_repo))
        .route("/api/repos/{name}/refs", get(api_get_refs))
        .route("/api/repos/{name}/archive", get(api_archive))
        .route("/api/repos/{name}/hooks", get(api_get_hooks))
        .route("/api/repos/{name}/mirrors", get(api_get_mirrors))
        .route("/api/mirrors", get(api_list_mirrors))
        // Email API
        .route("/api/email/config", get(api_get_email_config))
        .route("/api/email/config", post(api_update_email_config))
        // File Append API (P8.3)
        .route("/api/repos/{name}/files", get(api_list_files))
        .route("/api/repos/{name}/files/exists", get(api_check_file_exists))
        .route("/api/repos/{name}/append", post(api_append_file))
}

// ══════════════════════════════════════════════════════════════════════════════
// Page Handlers — Return full HTML pages
// ══════════════════════════════════════════════════════════════════════════════

/// GET / — Home page (redirects to /repos)
async fn index_page() -> impl IntoResponse {
    Html(INDEX_HTML)
}

/// GET /repos — Repository list page
async fn repos_page(
    State(state): State<Arc<AppState>>,
    Extension(identity): Extension<IdentityName>,
) -> impl IntoResponse {
    let repos = Repository::scan_dir(&state.config.repos_dir).unwrap_or_default();
    let repos_json: Vec<serde_json::Value> = repos
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "description": r.description.as_deref().unwrap_or(""),
                "bare": r.bare,
                "mirror": r.mirror,
            })
        })
        .collect();

    let html = REPOS_PAGE_HTML
        .replace("{{server_base}}", &state.config.bind.replace("0.0.0.0", "localhost"))
        .replace("{{user_name}}", &identity.0)
        .replace("{{repos_json}}", &serde_json::to_string(&repos_json).unwrap_or_default());

    Html(html)
}

/// GET /repos/{name} — Repository detail page
async fn repo_detail_page(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    let repo = match Repository::open(&repo_path) {
        Ok(r) => r,
        Err(_) => return (StatusCode::NOT_FOUND, Html(ERROR_404_HTML)).into_response(),
    };

    let refs = repo.refs().unwrap_or_default();
    let branches: Vec<_> = refs.iter().filter(|r| r.name.starts_with("refs/heads/")).collect();
    let tags: Vec<_> = refs.iter().filter(|r| r.name.starts_with("refs/tags/")).collect();

    let base_url = state.config.bind.replace("0.0.0.0", "localhost");
    let http_url = format!("http://{}/{}", base_url, name);
    let ssh_url = format!("git@{}:{}/{}", base_url.split(':').next().unwrap_or(&base_url), base_url.split(':').nth(1).unwrap_or("localhost"), name);

    let refs_json = serde_json::to_string(&refs).unwrap_or_default();
    let branches_json = serde_json::to_string(&branches).unwrap_or_default();
    let tags_json = serde_json::to_string(&tags).unwrap_or_default();

    let html = REPO_DETAIL_PAGE_HTML
        .replace("{{repo_name}}", &repo.name)
        .replace("{{http_url}}", &http_url)
        .replace("{{ssh_url}}", &ssh_url)
        .replace("{{base_url}}", &base_url)
        .replace("{{refs_json}}", &refs_json)
        .replace("{{branches_json}}", &branches_json)
        .replace("{{tags_json}}", &tags_json)
        .replace("{{branch_count}}", &branches.len().to_string())
        .replace("{{tag_count}}", &tags.len().to_string());

    Html(html).into_response()
}

/// GET /repos/{name}/automation — Automation configuration page
async fn automation_page(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    if !repo_path.exists() {
        return (StatusCode::NOT_FOUND, Html(ERROR_404_HTML)).into_response();
    }

    let webhooks = state.webhooks.read().await;
    let mirrors = state.mirrors.read().await;
    let webhooks_json = serde_json::to_string(&*webhooks).unwrap_or_default();
    let mirrors_json = serde_json::to_string(&*mirrors).unwrap_or_default();

    let html = AUTOMATION_PAGE_HTML
        .replace("{{repo_name}}", &name)
        .replace("{{webhooks_json}}", &webhooks_json)
        .replace("{{mirrors_json}}", &mirrors_json);

    Html(html).into_response()
}

/// GET /repos/new — Create new repository page
async fn new_repo_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let html = NEW_REPO_PAGE_HTML
        .replace("{{server_base}}", &state.config.bind.replace("0.0.0.0", "localhost"));

    Html(html)
}

// ══════════════════════════════════════════════════════════════════════════════
// API Handlers — Return JSON data
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
struct ApiResponse<T> {
    data: T,
}

#[derive(Serialize)]
struct RepoListItem {
    name: String,
    description: String,
    bare: bool,
    mirror: bool,
    http_url: String,
    ssh_url: String,
}

/// GET /web-ui/api/list — List all repositories
async fn api_list_repos(State(state): State<Arc<AppState>>) -> Json<Vec<RepoListItem>> {
    let repos = Repository::scan_dir(&state.config.repos_dir).unwrap_or_default();
    let base_url = state.config.bind.replace("0.0.0.0", "localhost");

    let items: Vec<RepoListItem> = repos
        .into_iter()
        .map(|r| RepoListItem {
            name: r.name.clone(),
            description: r.description.unwrap_or_default(),
            bare: r.bare,
            mirror: r.mirror,
            http_url: format!("http://{}/{}", base_url, r.name),
            ssh_url: format!("git@{}:{}", base_url, r.name),
        })
        .collect();

    Json(items)
}

/// GET /web-ui/api/repos/{name} — Get repository details
async fn api_get_repo(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<RepoListItem>, StatusCode> {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    let repo = Repository::open(&repo_path).map_err(|_| StatusCode::NOT_FOUND)?;

    let base_url = state.config.bind.replace("0.0.0.0", "localhost");
    let http_url = format!("http://{}/{}", base_url, name);
    let ssh_url = format!("git@{}:{}", base_url, name);

    Ok(Json(RepoListItem {
        name: repo.name,
        description: repo.description.unwrap_or_default(),
        bare: repo.bare,
        mirror: repo.mirror,
        http_url,
        ssh_url,
    }))
}

/// GET /web-ui/api/repos/{name}/refs — Get repository refs
async fn api_get_refs(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<RefInfo>>, StatusCode> {
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    let repo = Repository::open(&repo_path).map_err(|_| StatusCode::NOT_FOUND)?;
    let refs = repo.refs().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(refs))
}

/// GET /web-ui/api/repos/{name}/archive — Download archive
async fn api_archive(
    Path(name): Path<String>,
    Query(params): Query<ArchiveQuery>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, StatusCode> {
    let format = params.format.as_deref().unwrap_or("zip");
    let repo_path = state.config.repos_dir.join(format!("{}.git", name));
    if !repo_path.exists() {
        return Err(StatusCode::NOT_FOUND);
    }

    let archive_path = state.config.repos_dir.join(format!("{}.{}", name, format));

    // Create archive using git archive or zip
    let output = if format == "tar.gz" {
        tokio::process::Command::new("git")
            .args(["archive", "--format=tar.gz", "-o", archive_path.to_str().unwrap(), "HEAD"])
            .current_dir(&repo_path)
            .output()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    } else {
        tokio::process::Command::new("git")
            .args(["archive", "--format=zip", "-o", archive_path.to_str().unwrap(), "HEAD"])
            .current_dir(&repo_path)
            .output()
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    };

    if !output.status.success() {
        // Fallback: just serve the repo directory
        return Err(StatusCode::NOT_FOUND);
    }

    let bytes = tokio::fs::read(&archive_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let filename = format!("{}.{}", name, format);
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Disposition",
        format!("attachment; filename=\"{}\"", filename).parse().unwrap(),
    );
    headers.insert("Content-Type", "application/octet-stream".parse().unwrap());

    // Clean up temp archive
    let _ = tokio::fs::remove_file(&archive_path).await;

    Ok((headers, bytes).into_response())
}

#[derive(Deserialize)]
struct ArchiveQuery {
    format: Option<String>,
}

/// GET /web-ui/api/repos/{name}/hooks — Get hooks for a repo
async fn api_get_hooks(
    Path(_name): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Json<Vec<WebhookConfig>> {
    let webhooks = state.webhooks.read().await;
    Json(webhooks.clone())
}

/// GET /web-ui/api/repos/{name}/mirrors — Get mirrors for a repo
async fn api_get_mirrors(
    Path(_name): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Json<MirrorsFile> {
    let mirrors = state.mirrors.read().await;
    Json(mirrors.clone())
}

/// GET /web-ui/api/mirrors — List all mirrors
async fn api_list_mirrors(State(state): State<Arc<AppState>>) -> Json<MirrorsFile> {
    let mirrors = state.mirrors.read().await;
    Json(mirrors.clone())
}

// ══════════════════════════════════════════════════════════════════════════════
// Email Settings API (P8.2)
// ══════════════════════════════════════════════════════════════════════════════

/// GET /settings/email — Email settings page
async fn email_settings_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let notifier = state.email_notifier.read().await;
    let enabled = notifier.is_enabled();
    let html = EMAIL_SETTINGS_PAGE_HTML.replace("{{enabled}}", if enabled { "true" } else { "false" });
    Html(html).into_response()
}

/// GET /api/email/config — Get email config
async fn api_get_email_config(State(state): State<Arc<AppState>>) -> Json<EmailConfig> {
    let notifier = state.email_notifier.read().await;
    Json(notifier.config().clone())
}

/// POST /api/email/config — Update email config
async fn api_update_email_config(
    State(state): State<Arc<AppState>>,
    Json(config): Json<EmailConfig>,
) -> impl IntoResponse {
    if let Err(e) = config.save(&state.config.email_file) {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": e.to_string()}))).into_response();
    }
    let notifier = opengit_core::email_notifier::EmailNotifier::new(config);
    let mut current = state.email_notifier.write().await;
    *current = notifier;
    (StatusCode::OK, Json(serde_json::json!({"success": true}))).into_response()
}

// ══════════════════════════════════════════════════════════════════════════════
// File Append API (P8.3)
// ══════════════════════════════════════════════════════════════════════════════

use serde::Deserialize;

/// Query params for file operations
#[derive(Debug, Deserialize)]
pub struct FileQuery {
    pub path: Option<String>,
    pub branch: Option<String>,
}

/// GET /api/repos/{name}/files - List files in repository
async fn api_list_files(
    Path(name): Path<String>,
    Query(params): Query<FileQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(&name);
    if !repo_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Repository not found"})),
        )
        .into_response();
    }

    let branch = params.branch.unwrap_or_else(|| "main".to_string());
    let dir = params.path.as_deref();

    match list_files(&repo_path, &branch, dir) {
        Ok(files) => Json(serde_json::json!({"files": files, "branch": branch}))
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
        .into_response(),
    }
}

/// GET /api/repos/{name}/files/exists - Check if file exists
async fn api_check_file_exists(
    Path(name): Path<String>,
    Query(params): Query<FileQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(&name);
    if !repo_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Repository not found"})),
        )
        .into_response();
    }

    let path = match &params.path {
        Some(p) => p.clone(),
        None => return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "path parameter required"})),
        )
        .into_response(),
    };

    let branch = params.branch.unwrap_or_else(|| "main".to_string());

    match file_exists(&repo_path, &branch, &path) {
        Ok(exists) => Json(serde_json::json!({"exists": exists, "path": path, "branch": branch}))
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
        .into_response(),
    }
}

/// POST /api/repos/{name}/append - Append a new file (P8.3)
async fn api_append_file(
    Path(name): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(request): Json<AppendFileRequest>,
) -> impl IntoResponse {
    let repo_path = state.config.repos_dir.join(&name);
    if !repo_path.exists() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Repository not found"})),
        )
        .into_response();
    }

    // Default branch
    let branch = "main";

    match append_file(&repo_path, branch, &request) {
        Ok(result) => {
            tracing::info!("File appended: {} in repo {}", request.path, name);
            Json(serde_json::json!({
                "success": true,
                "sha": result.sha,
                "commit_id": result.commit_id,
                "path": result.path,
                "message": result.message
            }))
            .into_response()
        }
        Err(e) => {
            tracing::warn!("Failed to append file: {}", e);
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════════════
// Embedded HTML — All pages are embedded using include_str!
// ══════════════════════════════════════════════════════════════════════════════

static INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OpenGit</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
    }
    body { background: var(--bg-primary); color: var(--text-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { text-align: center; max-width: 600px; padding: 2rem; }
    .logo { font-size: 4rem; margin-bottom: 1rem; }
    h1 { font-size: 2.5rem; margin-bottom: 0.5rem; font-weight: 600; }
    .subtitle { color: var(--text-secondary); font-size: 1.1rem; margin-bottom: 2rem; }
    .btn { display: inline-block; padding: 0.75rem 1.5rem; border-radius: 6px; text-decoration: none; font-weight: 500; transition: all 0.2s; margin: 0.5rem; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: #4090e0; }
    .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--border); }
    .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-top: 2rem; text-align: left; }
    .feature { background: var(--bg-secondary); padding: 1rem; border-radius: 6px; border: 1px solid var(--border); }
    .feature-icon { font-size: 1.5rem; margin-bottom: 0.5rem; }
    .feature-title { font-weight: 600; margin-bottom: 0.25rem; }
    .feature-desc { font-size: 0.85rem; color: var(--text-secondary); }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">🐉</div>
    <h1>OpenGit</h1>
    <p class="subtitle">轻量级私有 Git 服务 · Agent-First 设计</p>
    <a href="/repos" class="btn btn-primary">浏览仓库</a>
    <a href="/repos/new" class="btn btn-secondary">创建仓库</a>
    <div class="features">
      <div class="feature">
        <div class="feature-icon">📦</div>
        <div class="feature-title">仓库管理</div>
        <div class="feature-desc">创建、浏览、下载 Git 仓库</div>
      </div>
      <div class="feature">
        <div class="feature-icon">🔗</div>
        <div class="feature-title">Webhooks</div>
        <div class="feature-desc">自动化 CI/CD 集成</div>
      </div>
      <div class="feature">
        <div class="feature-icon">🔄</div>
        <div class="feature-title">镜像同步</div>
        <div class="feature-desc">多平台仓库镜像</div>
      </div>
      <div class="feature">
        <div class="feature-icon">🛡️</div>
        <div class="feature-title">策略引擎</div>
        <div class="feature-desc">细粒度权限控制</div>
      </div>
    </div>
  </div>
</body>
</html>"#;

static REPOS_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>仓库列表 - OpenGit</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
    }
    body { background: var(--bg-primary); color: var(--text-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; min-height: 100vh; }
    nav { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; }
    .nav-brand { font-size: 1.25rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
    .nav-brand a { color: var(--text-primary); text-decoration: none; }
    .nav-search { flex: 1; max-width: 400px; margin: 0 2rem; }
    .nav-search input { width: 100%; padding: 0.5rem 1rem; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; }
    .nav-search input:focus { outline: none; border-color: var(--accent); }
    .nav-actions { display: flex; gap: 0.5rem; align-items: center; }
    .user-menu { color: var(--text-secondary); font-size: 0.9rem; }
    main { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem; }
    .page-title { font-size: 1.5rem; font-weight: 600; }
    .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 0.9rem; cursor: pointer; border: none; transition: all 0.2s; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: #4090e0; }
    .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--border); }
    .btn-icon { padding: 0.5rem; background: transparent; border: 1px solid var(--border); }
    .btn-icon:hover { background: var(--bg-tertiary); }
    .repo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 1rem; }
    .repo-card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; transition: border-color 0.2s; }
    .repo-card:hover { border-color: var(--accent); }
    .repo-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem; }
    .repo-name { font-size: 1rem; font-weight: 600; color: var(--accent); text-decoration: none; }
    .repo-name:hover { text-decoration: underline; }
    .repo-badge { font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 10px; background: var(--bg-tertiary); color: var(--text-secondary); }
    .repo-badge.mirror { background: rgba(63, 185, 80, 0.15); color: var(--success); }
    .repo-description { color: var(--text-secondary); font-size: 0.85rem; margin-bottom: 1rem; line-height: 1.4; }
    .repo-meta { display: flex; justify-content: space-between; align-items: center; }
    .clone-btn { font-size: 0.8rem; }
    .empty-state { text-align: center; padding: 4rem 2rem; color: var(--text-secondary); }
    .empty-state-icon { font-size: 3rem; margin-bottom: 1rem; }
    .modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center; }
    .modal-overlay.active { display: flex; }
    .modal { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; max-width: 500px; width: 90%; max-height: 80vh; overflow: auto; }
    .modal-header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); }
    .modal-title { font-weight: 600; font-size: 1.1rem; }
    .modal-close { background: none; border: none; color: var(--text-secondary); font-size: 1.5rem; cursor: pointer; padding: 0; line-height: 1; }
    .modal-close:hover { color: var(--text-primary); }
    .modal-body { padding: 1.25rem; }
    .clone-tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
    .clone-tab { padding: 0.5rem 1rem; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-size: 0.85rem; color: var(--text-secondary); }
    .clone-tab.active { background: var(--accent); color: #fff; border-color: var(--accent); }
    .clone-url-box { background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1rem; display: flex; align-items: center; gap: 0.75rem; }
    .clone-url { flex: 1; font-family: 'SF Mono', Monaco, monospace; font-size: 0.85rem; word-break: break-all; }
    .copy-btn { background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 4px; padding: 0.35rem 0.75rem; color: var(--text-primary); cursor: pointer; font-size: 0.8rem; white-space: nowrap; }
    .copy-btn:hover { background: var(--border); }
    .copy-btn.copied { background: var(--success); border-color: var(--success); }
    .toast { position: fixed; bottom: 2rem; left: 50%; transform: translateX(-50%); background: var(--bg-tertiary); border: 1px solid var(--border); padding: 0.75rem 1.5rem; border-radius: 6px; font-size: 0.9rem; z-index: 2000; opacity: 0; transition: opacity 0.3s; }
    .toast.show { opacity: 1; }
    @media (max-width: 768px) {
      nav { flex-wrap: wrap; gap: 0.75rem; }
      .nav-search { order: 3; width: 100%; margin: 0; max-width: none; }
      .repo-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <nav>
    <div class="nav-brand">
      <a href="/">🐉</a>
      <a href="/repos">OpenGit</a>
    </div>
    <div class="nav-search">
      <input type="text" id="searchInput" placeholder="搜索仓库..." oninput="filterRepos()">
    </div>
    <div class="nav-actions">
      <a href="/repos/new" class="btn btn-primary">+ 新建仓库</a>
      <span class="user-menu">{{user_name}}</span>
    </div>
  </nav>

  <main>
    <div class="page-header">
      <h1 class="page-title">仓库列表</h1>
      <a href="/repos/new" class="btn btn-primary">+ 新建仓库</a>
    </div>

    <div id="repoGrid" class="repo-grid"></div>
    <div id="emptyState" class="empty-state" style="display:none;">
      <div class="empty-state-icon">📦</div>
      <p>还没有仓库</p>
      <p style="margin-top: 0.5rem; font-size: 0.9rem;">点击上方按钮创建第一个仓库</p>
    </div>
  </main>

  <!-- Clone Modal -->
  <div id="cloneModal" class="modal-overlay">
    <div class="modal">
      <div class="modal-header">
        <span class="modal-title">克隆仓库</span>
        <button class="modal-close" onclick="closeCloneModal()">&times;</button>
      </div>
      <div class="modal-body">
        <div class="clone-tabs">
          <button class="clone-tab active" onclick="switchCloneTab('http')">HTTP</button>
          <button class="clone-tab" onclick="switchCloneTab('ssh')">SSH</button>
        </div>
        <div class="clone-url-box">
          <span id="cloneUrl" class="clone-url"></span>
          <button class="copy-btn" onclick="copyCloneUrl()">📋 复制</button>
        </div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    const repos = {{repos_json}};
    const baseUrl = '{{server_base}}';
    let currentRepo = null;
    let currentTab = 'http';

    function init() {
      renderRepos(repos);
    }

    function renderRepos(repoList) {
      const grid = document.getElementById('repoGrid');
      const empty = document.getElementById('emptyState');
      
      if (repoList.length === 0) {
        grid.style.display = 'none';
        empty.style.display = 'block';
        return;
      }
      
      grid.style.display = 'grid';
      empty.style.display = 'none';
      
      grid.innerHTML = repoList.map(repo => {
        const httpUrl = 'http://' + baseUrl + '/' + repo.name;
        const sshUrl = 'git@' + baseUrl.replace(':', ':') + ':' + repo.name;
        return `
          <div class="repo-card" data-name="${repo.name.toLowerCase()}">
            <div class="repo-header">
              <a href="/repos/${repo.name}" class="repo-name">${repo.name}</a>
              ${repo.mirror ? '<span class="repo-badge mirror">镜像</span>' : ''}
              ${!repo.bare && !repo.mirror ? '<span class="repo-badge">普通</span>' : ''}
            </div>
            <p class="repo-description">${repo.description || '暂无描述'}</p>
            <div class="repo-meta">
              <button class="btn btn-secondary clone-btn" onclick="openCloneModal('${repo.name}', '${httpUrl}', '${sshUrl}')">
                ⎘ 克隆
              </button>
              <a href="/repos/${repo.name}/archive?format=zip" class="btn btn-secondary clone-btn">📦 下载</a>
            </div>
          </div>
        `;
      }).join('');
    }

    function filterRepos() {
      const query = document.getElementById('searchInput').value.toLowerCase();
      const filtered = repos.filter(r => r.name.toLowerCase().includes(query));
      renderRepos(filtered);
    }

    function openCloneModal(name, httpUrl, sshUrl) {
      currentRepo = { name, httpUrl, sshUrl };
      document.getElementById('cloneUrl').textContent = currentTab === 'http' ? httpUrl : sshUrl;
      document.getElementById('cloneModal').classList.add('active');
    }

    function closeCloneModal() {
      document.getElementById('cloneModal').classList.remove('active');
    }

    function switchCloneTab(tab) {
      currentTab = tab;
      document.querySelectorAll('.clone-tab').forEach(t => t.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('cloneUrl').textContent = tab === 'http' ? currentRepo.httpUrl : currentRepo.sshUrl;
    }

    async function copyCloneUrl() {
      const url = document.getElementById('cloneUrl').textContent;
      try {
        await navigator.clipboard.writeText(url);
        const btn = document.querySelector('.copy-btn');
        btn.textContent = '✓ 已复制';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = '📋 复制';
          btn.classList.remove('copied');
        }, 2000);
      } catch (e) {
        showToast('复制失败，请手动复制');
      }
    }

    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    document.getElementById('cloneModal').addEventListener('click', function(e) {
      if (e.target === this) closeCloneModal();
    });

    init();
  </script>
</body>
</html>"#;

static REPO_DETAIL_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{repo_name}} - OpenGit</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
    }
    body { background: var(--bg-primary); color: var(--text-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; min-height: 100vh; }
    nav { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; align-items: center; justify-content: space-between; }
    .nav-brand { font-size: 1.25rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
    .nav-brand a { color: var(--text-primary); text-decoration: none; }
    .nav-actions { display: flex; gap: 0.5rem; }
    main { max-width: 1000px; margin: 0 auto; padding: 2rem; }
    .page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 2rem; }
    .page-title { font-size: 1.75rem; font-weight: 600; }
    .back-link { color: var(--accent); text-decoration: none; display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }
    .back-link:hover { text-decoration: underline; }
    .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 0.9rem; cursor: pointer; border: none; transition: all 0.2s; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: #4090e0; }
    .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--border); }
    .section { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 1.5rem; }
    .section-header { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); font-weight: 600; display: flex; justify-content: space-between; align-items: center; }
    .section-body { padding: 1.25rem; }
    .clone-tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
    .clone-tab { padding: 0.5rem 1rem; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; cursor: pointer; font-size: 0.85rem; color: var(--text-secondary); }
    .clone-tab.active { background: var(--accent); color: #fff; border-color: var(--accent); }
    .clone-url-box { background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1rem; display: flex; align-items: center; gap: 0.75rem; }
    .clone-url { flex: 1; font-family: 'SF Mono', Monaco, monospace; font-size: 0.85rem; word-break: break-all; }
    .copy-btn { background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 4px; padding: 0.35rem 0.75rem; color: var(--text-primary); cursor: pointer; font-size: 0.8rem; white-space: nowrap; }
    .copy-btn:hover { background: var(--border); }
    .copy-btn.copied { background: var(--success); border-color: var(--success); }
    .download-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); gap: 0.75rem; }
    .download-btn { display: flex; align-items: center; justify-content: center; gap: 0.5rem; padding: 0.75rem; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); text-decoration: none; font-weight: 500; transition: all 0.2s; }
    .download-btn:hover { background: var(--border); border-color: var(--accent); }
    .refs-list { max-height: 300px; overflow-y: auto; }
    .ref-item { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid var(--border); }
    .ref-item:last-child { border-bottom: none; }
    .ref-name { font-family: 'SF Mono', Monaco, monospace; font-size: 0.9rem; color: var(--accent); }
    .ref-sha { font-family: 'SF Mono', Monaco, monospace; font-size: 0.8rem; color: var(--text-secondary); }
    .automation-rules { display: flex; flex-direction: column; gap: 0.75rem; }
    .rule-item { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem; background: var(--bg-tertiary); border-radius: 6px; }
    .rule-info { display: flex; align-items: center; gap: 0.75rem; }
    .rule-icon { font-size: 1.25rem; }
    .rule-name { font-weight: 500; }
    .rule-status { font-size: 0.8rem; color: var(--text-secondary); }
    .rule-actions { display: flex; gap: 0.5rem; }
    .empty-state { text-align: center; padding: 2rem; color: var(--text-secondary); }
    .toast { position: fixed; bottom: 2rem; left: 50%; transform: translateX(-50%); background: var(--bg-tertiary); border: 1px solid var(--border); padding: 0.75rem 1.5rem; border-radius: 6px; font-size: 0.9rem; z-index: 2000; opacity: 0; transition: opacity 0.3s; }
    .toast.show { opacity: 1; }
    @media (max-width: 768px) {
      .page-header { flex-direction: column; gap: 1rem; }
      .section-body { padding: 1rem; }
    }
  </style>
</head>
<body>
  <nav>
    <div class="nav-brand">
      <a href="/">🐉</a>
      <a href="/repos">OpenGit</a>
      <span style="color: var(--text-secondary);">/</span>
      <span>{{repo_name}}</span>
    </div>
    <div class="nav-actions">
      <a href="/repos/{{repo_name}}/automation" class="btn btn-secondary">⚙️ 自动化</a>
    </div>
  </nav>

  <main>
    <a href="/repos" class="back-link">← 返回仓库列表</a>

    <div class="page-header">
      <h1 class="page-title">{{repo_name}}</h1>
    </div>

    <!-- Clone Section -->
    <div class="section">
      <div class="section-header">克隆</div>
      <div class="section-body">
        <div class="clone-tabs">
          <button class="clone-tab active" onclick="switchCloneTab('http')">HTTP</button>
          <button class="clone-tab" onclick="switchCloneTab('ssh')">SSH</button>
        </div>
        <div class="clone-url-box">
          <span id="cloneUrl" class="clone-url">{{http_url}}</span>
          <button class="copy-btn" onclick="copyCloneUrl()">📋 复制</button>
        </div>
      </div>
    </div>

    <!-- Download Section -->
    <div class="section">
      <div class="section-header">下载</div>
      <div class="section-body">
        <div class="download-grid">
          <a href="/api/repos/{{repo_name}}/archive?format=zip" class="download-btn">📦 下载 ZIP</a>
          <a href="/api/repos/{{repo_name}}/archive?format=tar.gz" class="download-btn">📦 下载 TAR.GZ</a>
        </div>
      </div>
    </div>

    <!-- Branches Section -->
    <div class="section">
      <div class="section-header">
        <span>分支 <span id="branchCount">({{branch_count}})</span></span>
      </div>
      <div class="section-body">
        <div id="branchesList" class="refs-list"></div>
      </div>
    </div>

    <!-- Tags Section -->
    <div class="section">
      <div class="section-header">
        <span>标签 <span id="tagCount">({{tag_count}})</span></span>
      </div>
      <div class="section-body">
        <div id="tagsList" class="refs-list"></div>
      </div>
    </div>

    <!-- Automation Section -->
    <div class="section">
      <div class="section-header">
        <span>自动化规则</span>
        <a href="/repos/{{repo_name}}/automation" class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.8rem;">+ 添加规则</a>
      </div>
      <div class="section-body">
        <div id="automationRules" class="automation-rules">
          <div class="empty-state">暂无自动化规则</div>
        </div>
      </div>
    </div>
  </main>

  <div id="toast" class="toast"></div>

  <script>
    const refs = {{refs_json}};
    const branches = {{branches_json}};
    const tags = {{tags_json}};
    let currentTab = 'http';
    const httpUrl = '{{http_url}}';
    const sshUrl = '{{ssh_url}}';

    function init() {
      renderBranches();
      renderTags();
      loadAutomation();
    }

    function renderBranches() {
      const container = document.getElementById('branchesList');
      if (branches.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无分支</div>';
        return;
      }
      container.innerHTML = branches.map(b => `
        <div class="ref-item">
          <span class="ref-name">${b.name.replace('refs/heads/', '')}</span>
          <span class="ref-sha">${b.sha.substring(0, 7)}</span>
        </div>
      `).join('');
    }

    function renderTags() {
      const container = document.getElementById('tagsList');
      if (tags.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无标签</div>';
        return;
      }
      container.innerHTML = tags.map(t => `
        <div class="ref-item">
          <span class="ref-name">${t.name.replace('refs/tags/', '')}</span>
          <span class="ref-sha">${t.sha.substring(0, 7)}</span>
        </div>
      `).join('');
    }

    async function loadAutomation() {
      // Load webhooks and mirrors from API
      try {
        const [hooksRes, mirrorsRes] = await Promise.all([
          fetch('/web-ui/api/repos/{{repo_name}}/hooks'),
          fetch('/web-ui/api/repos/{{repo_name}}/mirrors')
        ]);
        const hooks = await hooksRes.json();
        const mirrors = await mirrorsRes.json();
        
        const container = document.getElementById('automationRules');
        const rules = [];
        
        hooks.forEach(h => {
          rules.push(`<div class="rule-item">
            <div class="rule-info">
              <span class="rule-icon">🔗</span>
              <div>
                <div class="rule-name">Webhook</div>
                <div class="rule-status">${h.url}</div>
              </div>
            </div>
            <div class="rule-actions">
              <span class="rule-status">${h.active ? '✓ 启用' : '✗ 禁用'}</span>
            </div>
          </div>`);
        });
        
        mirrors.mirrors && mirrors.mirrors.forEach(m => {
          if (m.repos && m.repos.includes('{{repo_name}}')) {
            rules.push(`<div class="rule-item">
              <div class="rule-info">
                <span class="rule-icon">🔄</span>
                <div>
                  <div class="rule-name">${m.name}</div>
                  <div class="rule-status">${m.url}</div>
                </div>
              </div>
              <div class="rule-actions">
                <span class="rule-status">${m.enabled ? '✓ 启用' : '✗ 禁用'}</span>
              </div>
            </div>`);
          }
        });
        
        container.innerHTML = rules.length > 0 ? rules.join('') : '<div class="empty-state">暂无自动化规则</div>';
      } catch (e) {
        console.error('Failed to load automation:', e);
      }
    }

    function switchCloneTab(tab) {
      currentTab = tab;
      document.querySelectorAll('.clone-tab').forEach(t => t.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('cloneUrl').textContent = tab === 'http' ? httpUrl : sshUrl;
    }

    async function copyCloneUrl() {
      const url = document.getElementById('cloneUrl').textContent;
      try {
        await navigator.clipboard.writeText(url);
        const btn = document.querySelector('.copy-btn');
        btn.textContent = '✓ 已复制';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = '📋 复制';
          btn.classList.remove('copied');
        }, 2000);
      } catch (e) {
        showToast('复制失败，请手动复制');
      }
    }

    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    init();
  </script>
</body>
</html>"#;

static AUTOMATION_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>自动化规则 - {{repo_name}} - OpenGit</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
    }
    body { background: var(--bg-primary); color: var(--text-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; min-height: 100vh; }
    nav { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; align-items: center; }
    .nav-brand { font-size: 1.25rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
    .nav-brand a { color: var(--text-primary); text-decoration: none; }
    main { max-width: 900px; margin: 0 auto; padding: 2rem; }
    .back-link { color: var(--accent); text-decoration: none; display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }
    .back-link:hover { text-decoration: underline; }
    .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
    .page-title { font-size: 1.5rem; font-weight: 600; }
    .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.5rem 1rem; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 0.9rem; cursor: pointer; border: none; transition: all 0.2s; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: #4090e0; }
    .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--border); }
    .btn-danger { background: var(--danger); color: #fff; }
    .btn-danger:hover { background: #d73a32; }
    .btn-sm { padding: 0.35rem 0.75rem; font-size: 0.8rem; }
    .section { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; margin-bottom: 1.5rem; }
    .section-header { padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); font-weight: 600; display: flex; justify-content: space-between; align-items: center; }
    .section-body { padding: 1.25rem; }
    .item-list { display: flex; flex-direction: column; gap: 0.75rem; }
    .item { display: flex; justify-content: space-between; align-items: flex-start; padding: 1rem; background: var(--bg-tertiary); border-radius: 6px; gap: 1rem; }
    .item-icon { font-size: 1.5rem; }
    .item-info { flex: 1; }
    .item-name { font-weight: 600; margin-bottom: 0.25rem; }
    .item-detail { font-size: 0.85rem; color: var(--text-secondary); word-break: break-all; }
    .item-actions { display: flex; gap: 0.5rem; flex-shrink: 0; }
    .form-group { margin-bottom: 1rem; }
    .form-label { display: block; font-size: 0.9rem; font-weight: 500; margin-bottom: 0.5rem; color: var(--text-secondary); }
    .form-input { width: 100%; padding: 0.75rem; background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; }
    .form-input:focus { outline: none; border-color: var(--accent); }
    .form-select { width: 100%; padding: 0.75rem; background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; }
    .form-checkbox { display: flex; align-items: center; gap: 0.5rem; }
    .form-checkbox input { width: 1rem; height: 1rem; }
    .empty-state { text-align: center; padding: 2rem; color: var(--text-secondary); }
    .status-badge { font-size: 0.75rem; padding: 0.2rem 0.5rem; border-radius: 10px; }
    .status-active { background: rgba(63, 185, 80, 0.15); color: var(--success); }
    .status-inactive { background: rgba(139, 148, 158, 0.15); color: var(--text-secondary); }
    .modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; align-items: center; justify-content: center; }
    .modal-overlay.active { display: flex; }
    .modal { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; max-width: 500px; width: 90%; max-height: 80vh; overflow: auto; }
    .modal-header { display: flex; justify-content: space-between; align-items: center; padding: 1rem 1.25rem; border-bottom: 1px solid var(--border); }
    .modal-title { font-weight: 600; font-size: 1.1rem; }
    .modal-close { background: none; border: none; color: var(--text-secondary); font-size: 1.5rem; cursor: pointer; padding: 0; line-height: 1; }
    .modal-close:hover { color: var(--text-primary); }
    .modal-body { padding: 1.25rem; }
    .modal-footer { display: flex; justify-content: flex-end; gap: 0.5rem; padding: 1rem 1.25rem; border-top: 1px solid var(--border); }
    .toast { position: fixed; bottom: 2rem; left: 50%; transform: translateX(-50%); background: var(--bg-tertiary); border: 1px solid var(--border); padding: 0.75rem 1.5rem; border-radius: 6px; font-size: 0.9rem; z-index: 2000; opacity: 0; transition: opacity 0.3s; }
    .toast.show { opacity: 1; }
  </style>
</head>
<body>
  <nav>
    <div class="nav-brand">
      <a href="/">🐉</a>
      <a href="/repos">OpenGit</a>
      <span style="color: var(--text-secondary);">/</span>
      <a href="/repos/{{repo_name}}">{{repo_name}}</a>
      <span style="color: var(--text-secondary);">/</span>
      <span>自动化规则</span>
    </div>
  </nav>

  <main>
    <a href="/repos/{{repo_name}}" class="back-link">← 返回仓库</a>

    <div class="page-header">
      <h1 class="page-title">自动化规则: {{repo_name}}</h1>
    </div>

    <!-- Webhooks Section -->
    <div class="section">
      <div class="section-header">
        <span>🔗 Webhooks</span>
        <button class="btn btn-primary btn-sm" onclick="openWebhookModal()">+ 添加 Webhook</button>
      </div>
      <div class="section-body">
        <div id="webhooksList" class="item-list"></div>
      </div>
    </div>

    <!-- Mirrors Section -->
    <div class="section">
      <div class="section-header">
        <span>🔄 镜像同步</span>
        <button class="btn btn-primary btn-sm" onclick="openMirrorModal()">+ 添加镜像</button>
      </div>
      <div class="section-body">
        <div id="mirrorsList" class="item-list"></div>
      </div>
    </div>

    <!-- Policies Section -->
    <div class="section">
      <div class="section-header">
        <span>🛡️ 访问策略</span>
      </div>
      <div class="section-body">
        <div class="form-group">
          <label class="form-checkbox">
            <input type="checkbox" id="policyForcePush" checked>
            <span>允许强制推送</span>
          </label>
        </div>
        <div class="form-group">
          <label class="form-checkbox">
            <input type="checkbox" id="policyDeleteBranch" checked>
            <span>允许删除分支</span>
          </label>
        </div>
        <div class="form-group">
          <label class="form-checkbox">
            <input type="checkbox" id="policyRequireSign">
            <span>需要签名提交</span>
          </label>
        </div>
        <button class="btn btn-primary" onclick="savePolicies()">保存策略</button>
      </div>
    </div>
  </main>

  <!-- Webhook Modal -->
  <div id="webhookModal" class="modal-overlay">
    <div class="modal">
      <div class="modal-header">
        <span class="modal-title">添加 Webhook</span>
        <button class="modal-close" onclick="closeWebhookModal()">&times;</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">URL</label>
          <input type="url" id="webhookUrl" class="form-input" placeholder="https://example.com/webhook">
        </div>
        <div class="form-group">
          <label class="form-label">秘钥 (可选)</label>
          <input type="password" id="webhookSecret" class="form-input" placeholder="用于签名验证">
        </div>
        <div class="form-group">
          <label class="form-label">触发事件</label>
          <div class="form-checkbox">
            <input type="checkbox" id="eventPush" checked>
            <span>Push</span>
          </div>
          <div class="form-checkbox" style="margin-top: 0.5rem;">
            <input type="checkbox" id="eventTag">
            <span>Tag</span>
          </div>
          <div class="form-checkbox" style="margin-top: 0.5rem;">
            <input type="checkbox" id="eventDeleteBranch">
            <span>删除分支</span>
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeWebhookModal()">取消</button>
        <button class="btn btn-primary" onclick="saveWebhook()">保存</button>
      </div>
    </div>
  </div>

  <!-- Mirror Modal -->
  <div id="mirrorModal" class="modal-overlay">
    <div class="modal">
      <div class="modal-header">
        <span class="modal-title">添加镜像</span>
        <button class="modal-close" onclick="closeMirrorModal()">&times;</button>
      </div>
      <div class="modal-body">
        <div class="form-group">
          <label class="form-label">名称</label>
          <input type="text" id="mirrorName" class="form-input" placeholder="Gitee镜像">
        </div>
        <div class="form-group">
          <label class="form-label">目标 URL</label>
          <input type="url" id="mirrorUrl" class="form-input" placeholder="https://gitee.com/user/repo">
        </div>
      </div>
      <div class="modal-footer">
        <button class="btn btn-secondary" onclick="closeMirrorModal()">取消</button>
        <button class="btn btn-primary" onclick="saveMirror()">保存</button>
      </div>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    let webhooks = {{webhooks_json}};
    let mirrors = {{mirrors_json}};

    function init() {
      renderWebhooks();
      renderMirrors();
    }

    function renderWebhooks() {
      const container = document.getElementById('webhooksList');
      if (webhooks.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无 Webhooks</div>';
        return;
      }
      container.innerHTML = webhooks.map((h, idx) => `
        <div class="item">
          <span class="item-icon">🔗</span>
          <div class="item-info">
            <div class="item-name">${h.url}</div>
            <div class="item-detail">事件: ${h.events.join(', ') || 'push'}</div>
          </div>
          <div class="item-actions">
            <span class="status-badge ${h.active ? 'status-active' : 'status-inactive'}">${h.active ? '启用' : '禁用'}</span>
            <button class="btn btn-secondary btn-sm" onclick="deleteWebhook(${idx})">删除</button>
          </div>
        </div>
      `).join('');
    }

    function renderMirrors() {
      const container = document.getElementById('mirrorsList');
      const repoMirrors = mirrors.mirrors ? mirrors.mirrors.filter(m => m.repos && m.repos.includes('{{repo_name}}')) : [];
      if (repoMirrors.length === 0) {
        container.innerHTML = '<div class="empty-state">暂无镜像</div>';
        return;
      }
      container.innerHTML = repoMirrors.map((m, idx) => `
        <div class="item">
          <span class="item-icon">🔄</span>
          <div class="item-info">
            <div class="item-name">${m.name}</div>
            <div class="item-detail">${m.url}</div>
          </div>
          <div class="item-actions">
            <span class="status-badge ${m.enabled ? 'status-active' : 'status-inactive'}">${m.enabled ? '启用' : '禁用'}</span>
            <button class="btn btn-secondary btn-sm" onclick="deleteMirror(${idx})">删除</button>
          </div>
        </div>
      `).join('');
    }

    function openWebhookModal() {
      document.getElementById('webhookModal').classList.add('active');
    }

    function closeWebhookModal() {
      document.getElementById('webhookModal').classList.remove('active');
      document.getElementById('webhookUrl').value = '';
      document.getElementById('webhookSecret').value = '';
    }

    async function saveWebhook() {
      const url = document.getElementById('webhookUrl').value;
      const secret = document.getElementById('webhookSecret').value;
      const events = [];
      if (document.getElementById('eventPush').checked) events.push('push');
      if (document.getElementById('eventTag').checked) events.push('tag');
      if (document.getElementById('eventDeleteBranch').checked) events.push('delete-branch');

      if (!url) {
        showToast('请输入 Webhook URL');
        return;
      }

      try {
        const res = await fetch('/api/webhooks', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, secret, events })
        });
        if (res.ok) {
          showToast('Webhook 添加成功');
          closeWebhookModal();
          webhooks.push({ url, secret, events, active: true });
          renderWebhooks();
        } else {
          showToast('添加失败');
        }
      } catch (e) {
        showToast('添加失败: ' + e.message);
      }
    }

    async function deleteWebhook(idx) {
      if (!confirm('确定删除此 Webhook?')) return;
      try {
        const res = await fetch(`/api/webhooks/${idx}`, { method: 'DELETE' });
        if (res.ok) {
          showToast('Webhook 已删除');
          webhooks.splice(idx, 1);
          renderWebhooks();
        } else {
          showToast('删除失败');
        }
      } catch (e) {
        showToast('删除失败');
      }
    }

    function openMirrorModal() {
      document.getElementById('mirrorModal').classList.add('active');
    }

    function closeMirrorModal() {
      document.getElementById('mirrorModal').classList.remove('active');
      document.getElementById('mirrorName').value = '';
      document.getElementById('mirrorUrl').value = '';
    }

    async function saveMirror() {
      const name = document.getElementById('mirrorName').value;
      const url = document.getElementById('mirrorUrl').value;

      if (!name || !url) {
        showToast('请填写完整信息');
        return;
      }

      try {
        const res = await fetch('/api/mirrors', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            name, 
            url, 
            repos: ['{{repo_name}}'],
            refs: ['refs/heads/*', 'refs/tags/*']
          })
        });
        if (res.ok) {
          showToast('镜像添加成功');
          closeMirrorModal();
          location.reload();
        } else {
          showToast('添加失败');
        }
      } catch (e) {
        showToast('添加失败: ' + e.message);
      }
    }

    async function deleteMirror(idx) {
      if (!confirm('确定删除此镜像?')) return;
      try {
        const res = await fetch(`/api/mirrors/${idx}`, { method: 'DELETE' });
        if (res.ok) {
          showToast('镜像已删除');
          location.reload();
        } else {
          showToast('删除失败');
        }
      } catch (e) {
        showToast('删除失败');
      }
    }

    function savePolicies() {
      showToast('策略已保存');
    }

    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    document.querySelectorAll('.modal-overlay').forEach(modal => {
      modal.addEventListener('click', function(e) {
        if (e.target === this) {
          this.classList.remove('active');
        }
      });
    });

    init();
  </script>
</body>
</html>"#;

static NEW_REPO_PAGE_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>创建仓库 - OpenGit</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --warning: #d29922;
      --danger: #f85149;
    }
    body { background: var(--bg-primary); color: var(--text-primary); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; min-height: 100vh; }
    nav { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; align-items: center; }
    .nav-brand { font-size: 1.25rem; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; }
    .nav-brand a { color: var(--text-primary); text-decoration: none; }
    main { max-width: 600px; margin: 0 auto; padding: 2rem; }
    .back-link { color: var(--accent); text-decoration: none; display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }
    .back-link:hover { text-decoration: underline; }
    .page-title { font-size: 1.5rem; font-weight: 600; margin-bottom: 2rem; }
    .form { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 6px; padding: 1.5rem; }
    .form-group { margin-bottom: 1.25rem; }
    .form-label { display: block; font-size: 0.9rem; font-weight: 500; margin-bottom: 0.5rem; }
    .form-label .required { color: var(--danger); }
    .form-input { width: 100%; padding: 0.75rem; background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); font-size: 0.9rem; }
    .form-input:focus { outline: none; border-color: var(--accent); }
    .form-hint { font-size: 0.8rem; color: var(--text-secondary); margin-top: 0.25rem; }
    .form-checkbox { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 1rem; }
    .form-checkbox input { width: 1rem; height: 1rem; }
    .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.75rem 1.5rem; border-radius: 6px; text-decoration: none; font-weight: 500; font-size: 0.9rem; cursor: pointer; border: none; transition: all 0.2s; }
    .btn-primary { background: var(--accent); color: #fff; }
    .btn-primary:hover { background: #4090e0; }
    .btn-secondary { background: var(--bg-tertiary); color: var(--text-primary); border: 1px solid var(--border); }
    .btn-secondary:hover { background: var(--border); }
    .btn-group { display: flex; gap: 0.75rem; margin-top: 1.5rem; }
    .toast { position: fixed; bottom: 2rem; left: 50%; transform: translateX(-50%); background: var(--bg-tertiary); border: 1px solid var(--border); padding: 0.75rem 1.5rem; border-radius: 6px; font-size: 0.9rem; z-index: 2000; opacity: 0; transition: opacity 0.3s; }
    .toast.show { opacity: 1; }
    .toast.error { border-color: var(--danger); }
    .toast.success { border-color: var(--success); }
  </style>
</head>
<body>
  <nav>
    <div class="nav-brand">
      <a href="/">🐉</a>
      <a href="/repos">OpenGit</a>
      <span style="color: var(--text-secondary);">/</span>
      <span>创建仓库</span>
    </div>
  </nav>

  <main>
    <a href="/repos" class="back-link">← 返回仓库列表</a>

    <h1 class="page-title">创建新仓库</h1>

    <form id="createRepoForm" class="form">
      <div class="form-group">
        <label class="form-label">
          仓库名称 <span class="required">*</span>
        </label>
        <input type="text" id="repoName" class="form-input" placeholder="my-awesome-project" required>
        <p class="form-hint">只能包含字母、数字、中划线和下划线</p>
      </div>

      <div class="form-group">
        <label class="form-label">描述</label>
        <input type="text" id="repoDesc" class="form-input" placeholder="项目描述（可选）">
      </div>

      <label class="form-checkbox">
        <input type="checkbox" id="isMirror">
        <span>创建为镜像仓库</span>
      </label>

      <div class="btn-group">
        <button type="submit" class="btn btn-primary">创建仓库</button>
        <a href="/repos" class="btn btn-secondary">取消</a>
      </div>
    </form>
  </main>

  <div id="toast" class="toast"></div>

  <script>
    document.getElementById('createRepoForm').addEventListener('submit', async function(e) {
      e.preventDefault();
      
      const name = document.getElementById('repoName').value.trim();
      const desc = document.getElementById('repoDesc').value.trim();
      
      if (!name) {
        showToast('请输入仓库名称', 'error');
        return;
      }
      
      if (!/^[a-zA-Z0-9_-]+$/.test(name)) {
        showToast('仓库名称只能包含字母、数字、中划线和下划线', 'error');
        return;
      }

      try {
        const res = await fetch('/api/repos', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            // Token would be set from localStorage in real implementation
          },
          body: JSON.stringify({ name, description: desc })
        });
        
        if (res.ok) {
          showToast('仓库创建成功!', 'success');
          setTimeout(() => {
            window.location.href = '/repos/' + name;
          }, 1000);
        } else {
          const err = await res.json().catch(() => ({}));
          showToast('创建失败: ' + (err.message || res.statusText), 'error');
        }
      } catch (e) {
        showToast('创建失败: ' + e.message, 'error');
      }
    });

    function showToast(msg, type = '') {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.className = 'toast show ' + type;
      setTimeout(() => toast.classList.remove('show'), 3000);
    }
  </script>
</body>
</html>"#;

static ERROR_404_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>404 - 页面未找到</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { background: #0d1117; color: #e6edf3; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
    .container { text-align: center; padding: 2rem; }
    .error-code { font-size: 6rem; font-weight: 700; color: #f85149; line-height: 1; margin-bottom: 1rem; }
    .error-title { font-size: 1.5rem; margin-bottom: 0.5rem; }
    .error-desc { color: #8b949e; margin-bottom: 2rem; }
    a { color: #58a6ff; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <div class="error-code">404</div>
    <h1 class="error-title">页面未找到</h1>
    <p class="error-desc">您访问的页面不存在或已被删除</p>
    <a href="/repos">← 返回仓库列表</a>
  </div>
</body>
</html>"#;

// ══════════════════════════════════════════════════════════════════════════════
// Email Settings Page HTML (P8.2)
// ══════════════════════════════════════════════════════════════════════════════

static EMAIL_SETTINGS_PAGE_HTML: &str = r#"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>邮件设置 - OpenGit</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --border: #30363d;
      --text-primary: #e6edf3;
      --text-secondary: #8b949e;
      --accent: #58a6ff;
      --success: #3fb950;
      --danger: #f85149;
    }
    body { background: var(--bg-primary); color: var(--text-primary); font-family: -apple-system, sans-serif; min-height: 100vh; }
    .container { max-width: 700px; margin: 0 auto; padding: 2rem; }
    header { display: flex; align-items: center; justify-content: space-between; padding: 1rem 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
    .logo { font-size: 1.5rem; font-weight: 600; color: var(--accent); text-decoration: none; }
    h1 { font-size: 1.75rem; margin-bottom: 0.5rem; }
    .subtitle { color: var(--text-secondary); margin-bottom: 2rem; }
    .card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }
    .card-title { font-size: 1.1rem; font-weight: 600; margin-bottom: 1rem; }
    .form-group { margin-bottom: 1rem; }
    label { display: block; color: var(--text-secondary); font-size: 0.9rem; margin-bottom: 0.5rem; }
    input[type="text"], input[type="number"], input[type="password"] { width: 100%; padding: 0.75rem; background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px; color: var(--text-primary); }
    input:focus { outline: none; border-color: var(--accent); }
    .btn { padding: 0.75rem 1.5rem; border-radius: 6px; border: none; font-weight: 500; cursor: pointer; }
    .btn-primary { background: var(--accent); color: white; }
    .btn-primary:hover { background: #4090e0; }
    .btn-group { display: flex; gap: 1rem; margin-top: 1.5rem; }
    .toast { position: fixed; bottom: 2rem; left: 50%; transform: translateX(-50%); padding: 1rem 2rem; border-radius: 8px; opacity: 0; transition: opacity 0.3s; }
    .toast.show { opacity: 1; }
    .toast.success { background: var(--success); color: white; }
    .toast.error { background: var(--danger); color: white; }
    .status { display: inline-block; padding: 0.5rem 1rem; border-radius: 20px; font-size: 0.85rem; }
    .status.enabled { background: rgba(63, 185, 80, 0.2); color: var(--success); }
    .status.disabled { background: rgba(139, 148, 158, 0.2); color: var(--text-secondary); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <a href="/" class="logo">OpenGit</a>
    </header>
    <h1>邮件通知设置</h1>
    <p class="subtitle">配置推送和镜像同步的邮件通知</p>

    <div class="card">
      <div class="card-title">通知状态: <span id="status" class="status disabled">已禁用</span></div>
    </div>

    <div class="card">
      <div class="card-title">SMTP 配置</div>
      <div class="form-group">
        <label>服务器</label>
        <input type="text" id="smtpHost" placeholder="smtp.example.com">
      </div>
      <div class="form-group">
        <label>端口</label>
        <input type="number" id="smtpPort" value="587">
      </div>
      <div class="form-group">
        <label>用户名</label>
        <input type="text" id="smtpUsername" placeholder="email@example.com">
      </div>
      <div class="form-group">
        <label>密码</label>
        <input type="password" id="smtpPassword" placeholder="留空保留原密码">
      </div>
    </div>

    <div class="card">
      <div class="card-title">收件人</div>
      <div class="form-group">
        <label>发件地址</label>
        <input type="text" id="from" placeholder="OpenGit <notifications@example.com>">
      </div>
      <div class="form-group">
        <label>收件地址 (逗号分隔)</label>
        <input type="text" id="to" placeholder="owner@example.com">
      </div>
    </div>

    <div class="btn-group">
      <button class="btn btn-primary" onclick="saveConfig()">保存</button>
    </div>
  </div>

  <div id="toast" class="toast"></div>

  <script>
    let enabled = {{enabled}};

    async function loadConfig() {
      const res = await fetch('/api/email/config');
      const config = await res.json();
      document.getElementById('smtpHost').value = config.smtp_host || '';
      document.getElementById('smtpPort').value = config.smtp_port || 587;
      document.getElementById('smtpUsername').value = config.smtp_username || '';
      document.getElementById('from').value = config.from || '';
      document.getElementById('to').value = (config.to || []).join(', ');
      updateStatus(config.enabled);
    }

    function updateStatus(isEnabled) {
      const el = document.getElementById('status');
      el.textContent = isEnabled ? '已启用' : '已禁用';
      el.className = 'status ' + (isEnabled ? 'enabled' : 'disabled');
    }

    async function saveConfig() {
      const data = {
        enabled: true,
        smtp_host: document.getElementById('smtpHost').value,
        smtp_port: parseInt(document.getElementById('smtpPort').value) || 587,
        smtp_username: document.getElementById('smtpUsername').value,
        smtp_password: document.getElementById('smtpPassword').value,
        from: document.getElementById('from').value,
        to: document.getElementById('to').value.split(',').map(s => s.trim()).filter(s => s),
        use_tls: true
      };
      const res = await fetch('/api/email/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      const result = await res.json();
      showToast(res.ok ? '保存成功' : '保存失败: ' + (result.error || ''), res.ok ? 'success' : 'error');
      if (res.ok) {
        updateStatus(true);
        document.getElementById('smtpPassword').value = '';
      }
    }

    function showToast(msg, type) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.className = 'toast show ' + type;
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    loadConfig();
  </script>
</body>
</html>"#;
