//! Smart Branch Protection — AI-powered branch protection based on CI status
//!
//! P7.2: Automatically lock/unlock branches based on CI pipeline status.
//! Supports GitHub Actions and GitLab CI providers.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Branch protection status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BranchProtectionStatus {
    /// Branch is unlocked and accepting pushes
    Unlocked,
    /// Branch is locked with a reason
    Locked { reason: String },
    /// CI pipeline is running
    PendingCI,
    /// CI checks failed
    CiFailed { failed_checks: Vec<String> },
    /// CI passed, branch is protected
    Protected { passed_checks: Vec<String> },
}

/// CI check result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiResult {
    pub provider: String,
    pub status: CiStatus,
    pub checks: Vec<CiCheck>,
    pub timestamp: String,
}

/// CI status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiStatus {
    Success,
    Failure,
    Pending,
    Cancelled,
    Skipped,
}

/// Individual CI check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiCheck {
    pub name: String,
    pub status: CiStatus,
    pub url: Option<String>,
}

/// Required CI check for a branch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequiredCheck {
    pub name: String,
    pub required: bool,
}

/// Branch protection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchProtectionConfig {
    /// Enable branch protection
    #[serde(default)]
    pub enabled: bool,
    /// Required CI checks that must pass
    #[serde(default)]
    pub required_checks: Vec<String>,
    /// CI providers configuration
    pub ci_providers: CiProvidersConfig,
    /// Lock reason when CI fails
    #[serde(default = "default_lock_reason")]
    pub lock_reason: String,
    /// Timeout for CI checks (seconds)
    #[serde(default = "default_ci_timeout")]
    pub ci_timeout_seconds: u64,
}

fn default_lock_reason() -> String {
    "CI checks required".to_string()
}

fn default_ci_timeout() -> u64 {
    3600 // 1 hour
}

impl Default for BranchProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            required_checks: vec![
                "ci/build".to_string(),
                "ci/test".to_string(),
                "ci/lint".to_string(),
            ],
            ci_providers: CiProvidersConfig::default(),
            lock_reason: default_lock_reason(),
            ci_timeout_seconds: default_ci_timeout(),
        }
    }
}

impl BranchProtectionConfig {
    /// Load from TOML file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save to TOML file
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// CI providers configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiProvidersConfig {
    #[serde(default)]
    pub github: GithubCiConfig,
    #[serde(default)]
    pub gitlab: GitlabCiConfig,
}

impl Default for CiProvidersConfig {
    fn default() -> Self {
        Self {
            github: GithubCiConfig::default(),
            gitlab: GitlabCiConfig::default(),
        }
    }
}

/// GitHub Actions configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubCiConfig {
    #[serde(default)]
    pub enabled: bool,
    pub token: Option<String>,
    #[serde(default)]
    pub required_statuses: Vec<String>,
}

impl Default for GithubCiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token: None,
            required_statuses: vec!["github-actions".to_string()],
        }
    }
}

/// GitLab CI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitlabCiConfig {
    #[serde(default)]
    pub enabled: bool,
    pub token: Option<String>,
    #[serde(default)]
    pub required_statuses: Vec<String>,
}

impl Default for GitlabCiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token: None,
            required_statuses: vec!["gitlab-ci".to_string()],
        }
    }
}

/// CI provider trait for extensible CI integrations
pub trait CiProvider: Send + Sync {
    /// Provider name
    fn name(&self) -> &str;
    /// Check CI status for a repository and branch
    fn check_status(
        self: Arc<Self>,
        repo: String,
        branch: String,
    ) -> Pin<Box<dyn Future<Output = Result<CiResult>> + Send>>;
}

/// Wrapper to call check_status on Arc<dyn CiProvider>
fn call_check_status(provider: Arc<dyn CiProvider>, repo: String, branch: String) -> Pin<Box<dyn Future<Output = Result<CiResult>> + Send>> {
    // Use provider directly with Arc<dyn CiProvider> receiver
    provider.check_status(repo, branch)
}

/// GitHub Actions CI provider
pub struct GithubActionsProvider {
    client: reqwest::Client,
    token: String,
    api_base: String,
}

impl GithubActionsProvider {
    pub fn new(token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
            api_base: "https://api.github.com".to_string(),
        }
    }

    async fn get_workflow_runs(&self, repo: &str, branch: &str) -> Result<serde_json::Value> {
        let url = format!(
            "{}/repos/{}/actions/runs?branch={}&per_page=10",
            self.api_base, repo, branch
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.token))
            .header("Accept", "application/vnd.github.v3+json")
            .header("User-Agent", "OpenGit-BranchProtection")
            .send()
            .await
            .context("Failed to fetch GitHub Actions runs")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "GitHub API error: {}",
                response.status()
            );
        }

        let body = response.json().await.context("Failed to parse response")?;
        Ok(body)
    }

    fn parse_workflow_runs(&self, data: &serde_json::Value) -> CiResult {
        let runs_array = data.get("workflow_runs").and_then(|v| v.as_array());
        let empty: Vec<serde_json::Value> = vec![];
        let runs = runs_array.unwrap_or(&empty);

        let checks: Vec<CiCheck> = runs
            .iter()
            .filter_map(|run| {
                let name = run.get("name")?.as_str()?.to_string();
                let status = run.get("conclusion")?.as_str().unwrap_or("pending");
                let url = run.get("html_url")?.as_str().map(String::from);

                let ci_status = match status {
                    "success" => CiStatus::Success,
                    "failure" | "timed_out" => CiStatus::Failure,
                    "cancelled" => CiStatus::Cancelled,
                    "skipped" => CiStatus::Skipped,
                    _ => CiStatus::Pending,
                };

                Some(CiCheck {
                    name,
                    status: ci_status,
                    url,
                })
            })
            .collect();

        let overall_status = if checks.is_empty() {
            CiStatus::Pending
        } else if checks.iter().all(|c| c.status == CiStatus::Success) {
            CiStatus::Success
        } else if checks.iter().any(|c| c.status == CiStatus::Failure) {
            CiStatus::Failure
        } else {
            CiStatus::Pending
        };

        CiResult {
            provider: "github-actions".to_string(),
            status: overall_status,
            checks,
            timestamp: chrono_lite_now(),
        }
    }
}

impl CiProvider for GithubActionsProvider {
    fn name(&self) -> &str {
        "github-actions"
    }

    fn check_status(
        self: Arc<Self>,
        repo: String,
        branch: String,
    ) -> Pin<Box<dyn Future<Output = Result<CiResult>> + Send>> {
        Box::pin(async move {
            let data = self.get_workflow_runs(&repo, &branch).await?;
            Ok(self.parse_workflow_runs(&data))
        })
    }
}

/// GitLab CI provider
pub struct GitlabCiProvider {
    client: reqwest::Client,
    token: String,
    api_base: String,
}

impl GitlabCiProvider {
    pub fn new(token: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
            api_base: "https://gitlab.com/api/v4".to_string(),
        }
    }

    async fn get_pipeline(&self, repo: &str, branch: &str) -> Result<serde_json::Value> {
        // GitLab project path uses URL encoding for slashes
        let encoded_repo = repo.replace('/', "%2F");
        let url = format!(
            "{}/projects/{}/pipelines?ref={}&per_page=10",
            self.api_base, encoded_repo, branch
        );

        let response = self
            .client
            .get(&url)
            .header("PRIVATE-TOKEN", &self.token)
            .header("User-Agent", "OpenGit-BranchProtection")
            .send()
            .await
            .context("Failed to fetch GitLab pipeline")?;

        if !response.status().is_success() {
            anyhow::bail!(
                "GitLab API error: {}",
                response.status()
            );
        }

        let body = response.json().await.context("Failed to parse response")?;
        Ok(body)
    }

    fn parse_pipeline(&self, data: &serde_json::Value) -> CiResult {
        let pipelines_array = data.as_array();
        let empty: Vec<serde_json::Value> = vec![];
        let pipelines = pipelines_array.unwrap_or(&empty);

        let checks: Vec<CiCheck> = pipelines
            .iter()
            .filter_map(|pipeline| {
                let id = pipeline.get("id")?.as_i64()?;
                let status = pipeline.get("status")?.as_str()?;
                let web_url = pipeline.get("web_url")?.as_str().map(String::from);

                let ci_status = match status {
                    "success" => CiStatus::Success,
                    "failed" => CiStatus::Failure,
                    "canceled" => CiStatus::Cancelled,
                    "skipped" => CiStatus::Skipped,
                    "pending" | "created" | "running" => CiStatus::Pending,
                    _ => return None,
                };

                Some(CiCheck {
                    name: format!("pipeline-{}", id),
                    status: ci_status,
                    url: web_url,
                })
            })
            .collect();

        let overall_status = if checks.is_empty() {
            CiStatus::Pending
        } else {
            checks.first().map(|c| c.status).unwrap_or(CiStatus::Pending)
        };

        CiResult {
            provider: "gitlab-ci".to_string(),
            status: overall_status,
            checks,
            timestamp: chrono_lite_now(),
        }
    }
}

impl CiProvider for GitlabCiProvider {
    fn name(&self) -> &str {
        "gitlab-ci"
    }

    fn check_status(
        self: Arc<Self>,
        repo: String,
        branch: String,
    ) -> Pin<Box<dyn Future<Output = Result<CiResult>> + Send>> {
        Box::pin(async move {
            let data = self.get_pipeline(&repo, &branch).await?;
            Ok(self.parse_pipeline(&data))
        })
    }
}

/// CI status checker that aggregates multiple providers
pub struct CiStatusChecker {
    client: reqwest::Client,
    providers: Vec<Arc<dyn CiProvider>>,
}

impl CiStatusChecker {
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
            providers: Vec::new(),
        }
    }

    /// Add a GitHub Actions provider
    pub fn with_github(self, token: String) -> Self {
        self.with_provider(Arc::new(GithubActionsProvider::new(token)))
    }

    /// Add a GitLab CI provider
    pub fn with_gitlab(self, token: String) -> Self {
        self.with_provider(Arc::new(GitlabCiProvider::new(token)))
    }

    /// Add a custom provider
    pub fn with_provider(mut self, provider: Arc<dyn CiProvider>) -> Self {
        self.providers.push(provider);
        self
    }

    /// Check CI status from all providers
    pub async fn check_all(&self, repo: &str, branch: &str) -> Vec<CiResult> {
        let mut results = Vec::new();

        for provider in &self.providers {
            let result = call_check_status(Arc::clone(provider), repo.to_string(), branch.to_string()).await;
            match result {
                Ok(result) => {
                    info!(
                        "CI check from {}: {:?}",
                        provider.name(),
                        result.status
                    );
                    results.push(result);
                }
                Err(e) => {
                    warn!(
                        "CI check failed for {} on {}/{}: {}",
                        provider.name(),
                        repo,
                        branch,
                        e
                    );
                }
            }
        }

        results
    }

    /// Check CI status with timeout
    pub async fn check_with_timeout(
        &self,
        repo: &str,
        branch: &str,
        timeout: Duration,
    ) -> Result<Vec<CiResult>> {
        tokio::time::timeout(timeout, self.check_all(repo, branch))
            .await
            .map_err(|_| anyhow::anyhow!("CI check timed out"))
    }
}

impl Default for CiStatusChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Branch protector — evaluates push protection based on CI status
pub struct BranchProtector {
    config: BranchProtectionConfig,
    ci_checker: CiStatusChecker,
}

impl BranchProtector {
    /// Create a new branch protector from config
    pub fn new(config: BranchProtectionConfig) -> Self {
        let mut ci_checker = CiStatusChecker::new();

        if config.ci_providers.github.enabled {
            if let Some(token) = &config.ci_providers.github.token {
                ci_checker = ci_checker.with_github(token.clone());
            }
        }

        if config.ci_providers.gitlab.enabled {
            if let Some(token) = &config.ci_providers.gitlab.token {
                ci_checker = ci_checker.with_gitlab(token.clone());
            }
        }

        Self {
            config,
            ci_checker,
        }
    }

    /// Check branch protection status
    pub async fn check_protection(
        &self,
        repo: &str,
        branch: &str,
    ) -> Result<BranchProtectionStatus> {
        if !self.config.enabled {
            return Ok(BranchProtectionStatus::Unlocked);
        }

        // Check CI status
        let timeout = Duration::from_secs(self.config.ci_timeout_seconds);
        let ci_results = self
            .ci_checker
            .check_with_timeout(repo, branch, timeout)
            .await
            .unwrap_or_else(|e| {
                warn!("CI check timeout or error: {}", e);
                Vec::new()
            });

        // Aggregate results
        if ci_results.is_empty() {
            return Ok(BranchProtectionStatus::PendingCI);
        }

        // Check if all required checks pass
        let all_checks: Vec<&CiCheck> = ci_results
            .iter()
            .flat_map(|r| r.checks.iter())
            .collect();

        let mut passed_checks = Vec::new();
        let mut failed_checks = Vec::new();

        for required in &self.config.required_checks {
            let matching = all_checks.iter().filter(|c| {
                c.name.contains(required) || required.contains(&c.name)
            });

            let all_passed = matching.clone().all(|c| c.status == CiStatus::Success);
            let any_failed = matching.clone().any(|c| c.status == CiStatus::Failure);

            if all_passed {
                passed_checks.push(required.clone());
            } else if any_failed {
                failed_checks.push(required.clone());
            } else {
                // Check is pending or doesn't exist
                return Ok(BranchProtectionStatus::PendingCI);
            }
        }

        if failed_checks.is_empty() && !passed_checks.is_empty() {
            Ok(BranchProtectionStatus::Protected { passed_checks })
        } else if !failed_checks.is_empty() {
            Ok(BranchProtectionStatus::CiFailed { failed_checks })
        } else {
            Ok(BranchProtectionStatus::PendingCI)
        }
    }

    /// Evaluate whether a push should be allowed
    pub async fn evaluate_push(
        &self,
        repo: &str,
        branch: &str,
        identity: &str,
    ) -> Result<ProtectionResult> {
        let status = self.check_protection(repo, branch).await?;

        let allowed = match &status {
            BranchProtectionStatus::Unlocked => true,
            BranchProtectionStatus::Locked { .. } => false,
            BranchProtectionStatus::PendingCI => {
                // Allow push if CI is pending, but log warning
                warn!(
                    "Push allowed with pending CI to {}/{} by {}",
                    repo, branch, identity
                );
                true
            }
            BranchProtectionStatus::CiFailed { .. } => {
                // Block push if CI failed
                error!(
                    "Push blocked due to failed CI checks to {}/{} by {}",
                    repo, branch, identity
                );
                false
            }
            BranchProtectionStatus::Protected { .. } => true,
        };

        Ok(ProtectionResult {
            allowed,
            status,
            identity: identity.to_string(),
            repo: repo.to_string(),
            branch: branch.to_string(),
        })
    }
}

/// Result of push protection evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionResult {
    pub allowed: bool,
    pub status: BranchProtectionStatus,
    pub identity: String,
    pub repo: String,
    pub branch: String,
}

impl ProtectionResult {
    /// Get reason for denial
    pub fn denial_reason(&self) -> Option<String> {
        if self.allowed {
            return None;
        }

        Some(match &self.status {
            BranchProtectionStatus::Locked { reason } => reason.clone(),
            BranchProtectionStatus::CiFailed { failed_checks } => {
                format!(
                    "CI checks failed: {}",
                    failed_checks.join(", ")
                )
            }
            BranchProtectionStatus::PendingCI => {
                "CI pipeline is still running".to_string()
            }
            _ => "Branch protection active".to_string(),
        })
    }
}

/// Simple timestamp generator
fn chrono_lite_now() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();

    let secs = duration.as_secs();
    let days = secs / 86400;
    let year = 1970 + days / 365;
    let yday = days % 365;
    let month = yday / 30 + 1;
    let mday = yday % 30 + 1;
    let hour = (secs % 86400) / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, mday, hour, min, sec
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protection_status_serialization() {
        let status = BranchProtectionStatus::Protected {
            passed_checks: vec!["ci/test".to_string()],
        };
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("protected"));
    }

    #[test]
    fn test_protection_result_denial_reason() {
        let result = ProtectionResult {
            allowed: false,
            status: BranchProtectionStatus::CiFailed {
                failed_checks: vec!["ci/test".to_string()],
            },
            identity: "agent-deploy".to_string(),
            repo: "my-repo".to_string(),
            branch: "main".to_string(),
        };

        let reason = result.denial_reason().unwrap();
        assert!(reason.contains("ci/test"));
    }

    #[test]
    fn test_default_config() {
        let config = BranchProtectionConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.required_checks.len(), 3);
    }

    #[test]
    fn test_branch_protector_disabled() {
        let config = BranchProtectionConfig::default();
        let protector = BranchProtector::new(config);

        // When disabled, should always return unlocked
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(protector.evaluate_push("repo", "main", "agent"));
        assert!(result.unwrap().allowed);
    }
}
