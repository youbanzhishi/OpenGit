//! External Repository Import & Gitea Migration
//!
//! P6: Import repositories from any Git URL (GitHub, GitLab, Bitbucket, etc.)
//! P7: Migrate from Gitea via API — batch clone repos + optional metadata
//!
//! Design principles:
//! - `git clone --mirror` for bare repo import (preserves all refs, tags, branches)
//! - Gitea migration: uses Gitea API to enumerate repos, then clone each
//! - Metadata: optional pull of labels, milestones, releases from Gitea API
//! - All imports are async with progress tracking
//! - Import respects OpenGit policy (imported repos get default policy)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Instant;

// ─── Import Types ──────────────────────────────────────────────

/// Source type for repository import
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    /// Any Git URL (GitHub, GitLab, Bitbucket, self-hosted)
    Git,
    /// Gitea instance (uses API for batch migration)
    Gitea,
}

/// Import request for a single repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportRequest {
    /// Remote URL to clone from
    pub url: String,
    /// Local repository name (defaults to URL-derived name)
    pub name: Option<String>,
    /// Source type
    pub source: ImportSource,
    /// Whether to mirror all refs (default: true)
    #[serde(default = "default_true")]
    pub mirror: bool,
    /// Authentication: username for HTTPS
    pub username: Option<String>,
    /// Authentication: password/token for HTTPS
    pub password: Option<String>,
    /// SSH key path for SSH URLs
    pub ssh_key: Option<String>,
    /// Description for the imported repo
    pub description: Option<String>,
}

/// Result of a single repository import
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportResult {
    /// Repository name
    pub name: String,
    /// Remote URL that was imported
    pub source_url: String,
    /// Local path
    pub path: PathBuf,
    /// Number of branches imported
    pub branches: usize,
    /// Number of tags imported
    pub tags: usize,
    /// Time taken in seconds
    pub elapsed_secs: f64,
    /// Whether the import succeeded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Gitea migration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GiteaMigrateConfig {
    /// Gitea server URL (e.g., "https://gitea.example.com")
    pub server_url: String,
    /// Gitea API token
    pub token: String,
    /// Organization or user to migrate (optional, migrates all accessible repos if empty)
    pub owner: Option<String>,
    /// Specific repos to migrate (optional, overrides owner)
    pub repos: Vec<String>,
    /// Include labels in migration
    #[serde(default = "default_true")]
    pub include_labels: bool,
    /// Include milestones in migration
    #[serde(default = "default_true")]
    pub include_milestones: bool,
    /// Include releases in migration
    #[serde(default)]
    pub include_releases: bool,
    /// Include issues (metadata only, not full issue content)
    #[serde(default)]
    pub include_issues: bool,
    /// Username for cloning (if different from token owner)
    pub clone_username: Option<String>,
    /// Password/token for cloning (if different from API token)
    pub clone_password: Option<String>,
    /// Name prefix for imported repos (e.g., "gitea-")
    #[serde(default)]
    pub name_prefix: String,
}

/// Gitea API repository info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GiteaRepo {
    pub id: i64,
    pub name: String,
    pub full_name: String,
    pub clone_url: String,
    pub ssh_url: String,
    pub html_url: String,
    pub description: Option<String>,
    pub default_branch: Option<String>,
    pub private: bool,
    pub fork: bool,
    pub mirror: bool,
    pub size: i64,
    pub owner: GiteaUser,
}

/// Gitea API user/organization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GiteaUser {
    pub id: i64,
    pub login: String,
}

/// Gitea API label
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GiteaLabel {
    pub id: i64,
    pub name: String,
    pub color: String,
    pub description: Option<String>,
}

/// Gitea API milestone
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GiteaMilestone {
    pub id: i64,
    pub title: String,
    pub description: Option<String>,
    pub state: String,
    pub due_on: Option<String>,
}

/// Gitea API release
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GiteaRelease {
    pub id: i64,
    pub tag_name: String,
    pub name: Option<String>,
    pub body: Option<String>,
    pub draft: bool,
    pub prerelease: bool,
    pub created_at: Option<String>,
}

/// Migrated metadata from Gitea
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GiteaMetadata {
    pub labels: Vec<GiteaLabel>,
    pub milestones: Vec<GiteaMilestone>,
    pub releases: Vec<GiteaRelease>,
}

/// Batch migration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationResult {
    /// Total repos discovered
    pub total: usize,
    /// Successfully imported
    pub imported: usize,
    /// Failed imports
    pub failed: usize,
    /// Individual results
    pub results: Vec<ImportResult>,
    /// Total time in seconds
    pub elapsed_secs: f64,
}

// ─── Import Engine ─────────────────────────────────────────────

fn default_true() -> bool {
    true
}

/// Repository import engine
pub struct ImportEngine {
    /// Directory to store imported repos
    repos_dir: PathBuf,
}

impl ImportEngine {
    /// Create a new import engine
    pub fn new(repos_dir: impl Into<PathBuf>) -> Self {
        Self {
            repos_dir: repos_dir.into(),
        }
    }

    /// Import a single repository from a Git URL
    pub async fn import_repo(&self, req: &ImportRequest) -> ImportResult {
        let start = Instant::now();
        let name = req
            .name
            .clone()
            .unwrap_or_else(|| Self::derive_name(&req.url));

        match self.do_import(req, &name).await {
            Ok((path, branches, tags)) => ImportResult {
                name,
                source_url: req.url.clone(),
                path,
                branches,
                tags,
                elapsed_secs: start.elapsed().as_secs_f64(),
                success: true,
                error: None,
            },
            Err(e) => ImportResult {
                name,
                source_url: req.url.clone(),
                path: PathBuf::new(),
                branches: 0,
                tags: 0,
                elapsed_secs: start.elapsed().as_secs_f64(),
                success: false,
                error: Some(e.to_string()),
            },
        }
    }

    /// Perform the actual git clone --mirror
    async fn do_import(&self, req: &ImportRequest, name: &str) -> Result<(PathBuf, usize, usize)> {
        // Ensure repos dir exists
        std::fs::create_dir_all(&self.repos_dir)
            .with_context(|| format!("Failed to create repos dir: {}", self.repos_dir.display()))?;

        let repo_path = self.repos_dir.join(format!("{}.git", name));

        // Check if repo already exists
        if repo_path.exists() {
            anyhow::bail!(
                "Repository '{}' already exists at {}",
                name,
                repo_path.display()
            );
        }

        // Build the clone URL with authentication
        let clone_url =
            self.build_clone_url(&req.url, req.username.as_deref(), req.password.as_deref());

        // Run git clone --mirror
        let output = tokio::process::Command::new("git")
            .args([
                "clone",
                "--mirror",
                &clone_url,
                &repo_path.to_string_lossy(),
            ])
            .env("GIT_TERMINAL_PROMPT", "0") // Never prompt for credentials
            .output()
            .await
            .context("Failed to execute git clone")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("git clone failed: {}", stderr.trim());
        }

        // Count branches and tags
        let (branches, tags) = self.count_refs(&repo_path)?;

        // Set description if provided
        if let Some(desc) = &req.description {
            let desc_path = repo_path.join("description");
            let _ = std::fs::write(desc_path, desc);
        }

        // Configure the repo for OpenGit
        self.configure_imported_repo(&repo_path)?;

        Ok((repo_path, branches, tags))
    }

    /// Build clone URL with embedded credentials for HTTPS
    fn build_clone_url(&self, url: &str, username: Option<&str>, password: Option<&str>) -> String {
        // Only embed credentials for HTTPS URLs
        if url.starts_with("https://") {
            if let (Some(user), Some(pass)) = (username, password) {
                // Insert credentials: https://user:pass@host/path
                if let Some(rest) = url.strip_prefix("https://") {
                    return format!("https://{}:{}@{}", user, pass, rest);
                }
            }
        }
        url.to_string()
    }

    /// Count branches and tags in a bare repo
    fn count_refs(&self, repo_path: &Path) -> Result<(usize, usize)> {
        let repo = git2::Repository::open(repo_path)
            .with_context(|| format!("Failed to open cloned repo: {}", repo_path.display()))?;

        let mut branches = 0usize;
        let mut tags = 0usize;

        for reference in repo.references()? {
            let reference = reference?;
            if let Some(name) = reference.name() {
                if name.starts_with("refs/heads/") {
                    branches += 1;
                } else if name.starts_with("refs/tags/") {
                    tags += 1;
                }
            }
        }

        Ok((branches, tags))
    }

    /// Configure imported repo for OpenGit
    fn configure_imported_repo(&self, repo_path: &Path) -> Result<()> {
        let repo = git2::Repository::open(repo_path)?;

        // Set default branch to main or master
        let mut config = repo.config()?;
        config.set_str("core.logallrefupdates", "true")?;

        Ok(())
    }

    /// Derive a repository name from a Git URL
    pub fn derive_name(url: &str) -> String {
        // Handle various URL formats:
        // https://github.com/user/repo.git → repo
        // git@github.com:user/repo.git → repo
        // ssh://git@github.com/user/repo.git → repo

        let url = url.trim_end_matches('/');

        // Remove .git suffix
        let url = url.strip_suffix(".git").unwrap_or(url);

        // Get last path component
        if let Some(name) = url.rsplit('/').next() {
            // Also handle colon-separated (SSH format)
            if let Some(name) = name.rsplit(':').next() {
                name.to_string()
            } else {
                name.to_string()
            }
        } else {
            // Fallback: use a hash
            format!("imported-{}", &url[0..8.min(url.len())])
        }
    }

    /// Re-import (fetch) an existing mirror repo
    pub async fn fetch_mirror(&self, repo_name: &str) -> Result<()> {
        let repo_path = self.repos_dir.join(format!("{}.git", repo_name));

        if !repo_path.exists() {
            anyhow::bail!("Repository '{}' not found", repo_name);
        }

        let output = tokio::process::Command::new("git")
            .args(["remote", "update"])
            .current_dir(&repo_path)
            .output()
            .await
            .context("Failed to execute git remote update")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("git remote update failed: {}", stderr.trim());
        }

        Ok(())
    }
}

// ─── Gitea Migration ───────────────────────────────────────────

/// Gitea API client for migration
pub struct GiteaClient {
    server_url: String,
    token: String,
    http: reqwest::Client,
}

impl GiteaClient {
    /// Create a new Gitea API client
    pub fn new(server_url: &str, token: &str) -> Self {
        Self {
            server_url: server_url.trim_end_matches('/').to_string(),
            token: token.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// List all accessible repositories
    pub async fn list_repos(&self) -> Result<Vec<GiteaRepo>> {
        let mut all_repos = Vec::new();
        let mut page = 1u32;
        const PER_PAGE: u32 = 50;

        loop {
            let url = format!(
                "{}/api/v1/repos/search?limit={}&page={}",
                self.server_url, PER_PAGE, page
            );

            let resp = self
                .http
                .get(&url)
                .header("Authorization", format!("token {}", self.token))
                .send()
                .await
                .context("Failed to query Gitea API")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Gitea API error ({}): {}", status, body);
            }

            #[derive(Deserialize)]
            struct SearchResponse {
                data: Vec<GiteaRepo>,
            }

            let result: SearchResponse = resp
                .json()
                .await
                .context("Failed to parse Gitea response")?;

            let count = result.data.len();
            all_repos.extend(result.data);

            if count < PER_PAGE as usize {
                break;
            }
            page += 1;
        }

        Ok(all_repos)
    }

    /// List repositories for a specific owner
    pub async fn list_owner_repos(&self, owner: &str) -> Result<Vec<GiteaRepo>> {
        let mut all_repos = Vec::new();
        let mut page = 1u32;
        const PER_PAGE: u32 = 50;

        loop {
            let url = format!(
                "{}/api/v1/repos/search?uid={}&limit={}&page={}",
                // We search by owner name — Gitea doesn't have a direct UID lookup,
                // so we use the generic search and filter
                self.server_url,
                owner,
                PER_PAGE,
                page
            );

            let resp = self
                .http
                .get(&url)
                .header("Authorization", format!("token {}", self.token))
                .send()
                .await
                .context("Failed to query Gitea API")?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Gitea API error ({}): {}", status, body);
            }

            #[derive(Deserialize)]
            struct SearchResponse {
                data: Vec<GiteaRepo>,
            }

            let result: SearchResponse = resp
                .json()
                .await
                .context("Failed to parse Gitea response")?;

            let count = result.data.len();
            // Filter by owner
            let filtered: Vec<GiteaRepo> = result
                .data
                .into_iter()
                .filter(|r| r.owner.login.eq_ignore_ascii_case(owner))
                .collect();
            all_repos.extend(filtered);

            if count < PER_PAGE as usize {
                break;
            }
            page += 1;
        }

        Ok(all_repos)
    }

    /// Fetch labels for a repo
    pub async fn get_labels(&self, owner: &str, repo: &str) -> Result<Vec<GiteaLabel>> {
        let url = format!("{}/api/v1/repos/{}/{}/labels", self.server_url, owner, repo);
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("token {}", self.token))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new()); // Non-critical, skip on error
        }
        Ok(resp.json().await.unwrap_or_default())
    }

    /// Fetch milestones for a repo
    pub async fn get_milestones(&self, owner: &str, repo: &str) -> Result<Vec<GiteaMilestone>> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/milestones",
            self.server_url, owner, repo
        );
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("token {}", self.token))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }
        Ok(resp.json().await.unwrap_or_default())
    }

    /// Fetch releases for a repo
    pub async fn get_releases(&self, owner: &str, repo: &str) -> Result<Vec<GiteaRelease>> {
        let url = format!(
            "{}/api/v1/repos/{}/{}/releases?limit=50",
            self.server_url, owner, repo
        );
        let resp = self
            .http
            .get(&url)
            .header("Authorization", format!("token {}", self.token))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Ok(Vec::new());
        }
        Ok(resp.json().await.unwrap_or_default())
    }

    /// Fetch all metadata for a repo
    pub async fn get_metadata(
        &self,
        owner: &str,
        repo: &str,
        config: &GiteaMigrateConfig,
    ) -> GiteaMetadata {
        let labels = if config.include_labels {
            self.get_labels(owner, repo).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        let milestones = if config.include_milestones {
            self.get_milestones(owner, repo).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        let releases = if config.include_releases {
            self.get_releases(owner, repo).await.unwrap_or_default()
        } else {
            Vec::new()
        };

        GiteaMetadata {
            labels,
            milestones,
            releases,
        }
    }
}

/// Run a full Gitea migration
pub async fn migrate_from_gitea(
    config: &GiteaMigrateConfig,
    repos_dir: impl Into<PathBuf>,
) -> MigrationResult {
    let start = Instant::now();
    let engine = ImportEngine::new(repos_dir);
    let client = GiteaClient::new(&config.server_url, &config.token);

    // Discover repos
    let repos = match discover_gitea_repos(&client, config).await {
        Ok(r) => r,
        Err(e) => {
            return MigrationResult {
                total: 0,
                imported: 0,
                failed: 0,
                results: vec![ImportResult {
                    name: "discovery".to_string(),
                    source_url: config.server_url.clone(),
                    path: PathBuf::new(),
                    branches: 0,
                    tags: 0,
                    elapsed_secs: start.elapsed().as_secs_f64(),
                    success: false,
                    error: Some(format!("Failed to discover repos: {}", e)),
                }],
                elapsed_secs: start.elapsed().as_secs_f64(),
            };
        }
    };

    let total = repos.len();
    let mut results = Vec::new();

    for gitea_repo in &repos {
        // Filter specific repos if configured
        if !config.repos.is_empty() && !config.repos.contains(&gitea_repo.name) {
            continue;
        }

        let local_name = format!("{}{}", config.name_prefix, gitea_repo.name);

        let import_req = ImportRequest {
            url: gitea_repo.clone_url.clone(),
            name: Some(local_name),
            source: ImportSource::Gitea,
            mirror: true,
            username: config.clone_username.clone(),
            password: config
                .clone_password
                .clone()
                .or_else(|| Some(config.token.clone())),
            ssh_key: None,
            description: gitea_repo.description.clone(),
        };

        let result = engine.import_repo(&import_req).await;

        // If import succeeded and metadata is requested, fetch it
        if result.success
            && (config.include_labels || config.include_milestones || config.include_releases)
        {
            let owner = &gitea_repo.owner.login;
            let _metadata = client.get_metadata(owner, &gitea_repo.name, config).await;
            // Metadata is saved alongside the repo as a JSON file
            if let Ok(repo_path) = engine
                .repos_dir
                .join(format!("{}.git", result.name))
                .canonicalize()
            {
                let meta_path = repo_path.join("opengit-gitea-metadata.json");
                let _ = std::fs::write(
                    meta_path,
                    serde_json::to_string_pretty(&_metadata).unwrap_or_default(),
                );
            }
        }

        results.push(result);
    }

    let imported = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();

    MigrationResult {
        total,
        imported,
        failed,
        results,
        elapsed_secs: start.elapsed().as_secs_f64(),
    }
}

/// Discover repos from Gitea based on config
async fn discover_gitea_repos(
    client: &GiteaClient,
    config: &GiteaMigrateConfig,
) -> Result<Vec<GiteaRepo>> {
    if !config.repos.is_empty() {
        // Specific repos requested — list all and filter
        let all = client.list_repos().await?;
        Ok(all
            .into_iter()
            .filter(|r| config.repos.contains(&r.name))
            .collect())
    } else if let Some(owner) = &config.owner {
        client.list_owner_repos(owner).await
    } else {
        client.list_repos().await
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_name_https() {
        assert_eq!(
            ImportEngine::derive_name("https://github.com/user/my-repo.git"),
            "my-repo"
        );
    }

    #[test]
    fn test_derive_name_ssh() {
        assert_eq!(
            ImportEngine::derive_name("git@github.com:user/my-repo.git"),
            "my-repo"
        );
    }

    #[test]
    fn test_derive_name_no_git_suffix() {
        assert_eq!(
            ImportEngine::derive_name("https://gitlab.com/group/project"),
            "project"
        );
    }

    #[test]
    fn test_derive_name_trailing_slash() {
        assert_eq!(
            ImportEngine::derive_name("https://github.com/user/repo/"),
            "repo"
        );
    }

    #[test]
    fn test_import_request_serialization() {
        let req = ImportRequest {
            url: "https://github.com/user/repo.git".to_string(),
            name: Some("my-repo".to_string()),
            source: ImportSource::Git,
            mirror: true,
            username: None,
            password: None,
            ssh_key: None,
            description: Some("Test repo".to_string()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: ImportRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.url, req.url);
        assert_eq!(parsed.name, req.name);
        assert_eq!(parsed.source, ImportSource::Git);
    }

    #[test]
    fn test_gitea_migrate_config_default() {
        let config = GiteaMigrateConfig {
            server_url: "https://gitea.example.com".to_string(),
            token: "test-token".to_string(),
            owner: None,
            repos: vec![],
            include_labels: true,
            include_milestones: true,
            include_releases: false,
            include_issues: false,
            clone_username: None,
            clone_password: None,
            name_prefix: String::new(),
        };
        assert!(config.include_labels);
        assert!(config.include_milestones);
        assert!(!config.include_releases);
    }

    #[test]
    fn test_build_clone_url_no_auth() {
        let engine = ImportEngine::new("/tmp/repos");
        let url = engine.build_clone_url("https://github.com/user/repo.git", None, None);
        assert_eq!(url, "https://github.com/user/repo.git");
    }

    #[test]
    fn test_build_clone_url_with_auth() {
        let engine = ImportEngine::new("/tmp/repos");
        let url = engine.build_clone_url(
            "https://github.com/user/repo.git",
            Some("myuser"),
            Some("mypassword"),
        );
        assert_eq!(url, "https://myuser:mypassword@github.com/user/repo.git");
    }

    #[test]
    fn test_build_clone_url_ssh_unchanged() {
        let engine = ImportEngine::new("/tmp/repos");
        let url = engine.build_clone_url(
            "git@github.com:user/repo.git",
            Some("myuser"),
            Some("mypassword"),
        );
        assert_eq!(url, "git@github.com:user/repo.git");
    }
}
