//! Repository Mirror System
//!
//! P5.2: Git Gateway - Automatic push-based mirroring to remote Git hosts.
//! Includes security validation to protect backup repositories.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{error, info, warn};

/// Null SHA - represents deletion/empty
const NULL_SHA: &str = "0000000000000000000000000000000000000000";

/// Protected branches that should never be force-pushed or deleted
const DEFAULT_PROTECTED_BRANCHES: &[&str] = &["master", "main", "develop", "release/*"];

/// Error codes for mirror operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorError {
    pub code: String,
    pub message: String,
    pub repo: String,
    pub branch: Option<String>,
    pub severity: MirrorSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MirrorSeverity {
    #[default]
    Medium,
    Critical,
    High,
    Low,
}

/// Mirror push result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorPushResult {
    pub target: String,
    pub success: bool,
    pub error: Option<MirrorError>,
    pub old_sha: String,
    pub new_sha: String,
}

/// Mirror status for a repository
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MirrorStatus {
    pub repo: String,
    pub last_sync: Option<String>,
    pub issues: Vec<MirrorIssue>,
    pub targets: Vec<TargetStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorIssue {
    pub id: String,
    pub error_code: String,
    pub message: String,
    pub timestamp: String,
    pub resolved: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetStatus {
    pub name: String,
    pub healthy: bool,
    pub last_sync: Option<String>,
    pub error: Option<String>,
}

/// Mirror push context
#[derive(Debug, Clone)]
pub struct MirrorPushContext<'a> {
    pub repo_name: &'a str,
    pub ref_name: &'a str,
    pub old_sha: &'a str,
    pub new_sha: &'a str,
    pub actor: &'a str,
    pub repos_dir: &'a Path,
}

/// Security validation context
#[derive(Debug, Clone)]
pub struct SecurityValidation<'a> {
    pub allow_empty_mirror: bool,
    pub allow_force_push: bool,
    pub allow_branch_delete: bool,
    pub require_history_continuity: bool,
    pub protected_branches: Vec<&'a str>,
}

impl Default for SecurityValidation<'static> {
    fn default() -> Self {
        Self {
            allow_empty_mirror: false,
            allow_force_push: false,
            allow_branch_delete: false,
            require_history_continuity: true,
            protected_branches: DEFAULT_PROTECTED_BRANCHES.to_vec(),
        }
    }
}

/// Mirror target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorTarget {
    /// Friendly name for this mirror
    pub name: String,
    /// Remote URL to push to (e.g., "git@github.com:user/{repo}.git")
    pub url: String,
    /// Which repos to mirror (empty or ["*"] = all repos)
    #[serde(default)]
    pub repos: Vec<String>,
    /// Which refs to mirror (default: all refs)
    #[serde(default)]
    pub refs: Vec<String>,
    /// Mirror enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// SSH key path for this mirror (optional)
    #[serde(default)]
    pub ssh_key: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Mirror configuration file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MirrorsFile {
    #[serde(default)]
    pub mirrors: Vec<MirrorTarget>,
}

impl MirrorsFile {
    /// Load mirrors from a TOML file
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let mirrors: Self = toml::from_str(&content)?;
        Ok(mirrors)
    }

    /// Save mirrors to a TOML file
    pub fn save_to_file(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// Mirror manager handles matching repos to targets
#[derive(Debug, Clone)]
pub struct MirrorManager {
    targets: Vec<MirrorTarget>,
    security: SecurityValidation<'static>,
}

impl MirrorManager {
    /// Create a new mirror manager from config
    pub fn new(mirrors: &MirrorsFile) -> Self {
        Self {
            targets: mirrors
                .mirrors
                .iter()
                .filter(|m| m.enabled)
                .cloned()
                .collect(),
            security: SecurityValidation::default(),
        }
    }

    /// Create with custom security settings
    pub fn with_security(mirrors: &MirrorsFile, security: SecurityValidation<'static>) -> Self {
        Self {
            targets: mirrors
                .mirrors
                .iter()
                .filter(|m| m.enabled)
                .cloned()
                .collect(),
            security,
        }
    }

    /// Get mirror targets for a specific repo
    pub fn targets_for_repo(&self, repo_name: &str) -> Vec<&MirrorTarget> {
        self.targets
            .iter()
            .filter(|t| Self::matches_repo(t, repo_name))
            .collect()
    }

    /// Check if a mirror target matches a repo name
    fn matches_repo(target: &MirrorTarget, repo_name: &str) -> bool {
        if target.repos.is_empty() {
            return true;
        }
        target.repos.iter().any(|pattern| {
            if pattern == "*" {
                return true;
            }
            // Support simple glob: "my-*" matches "my-repo"
            if let Some(prefix) = pattern.strip_suffix('*') {
                return repo_name.starts_with(prefix);
            }
            pattern == repo_name
        })
    }

    /// Get all enabled targets
    pub fn all_targets(&self) -> &[MirrorTarget] {
        &self.targets
    }

    /// Get mirror names
    pub fn mirror_names(&self) -> Vec<&str> {
        self.targets.iter().map(|t| t.name.as_str()).collect()
    }

    /// Validate push safety before mirroring
    pub fn validate_push(&self, ctx: &MirrorPushContext<'_>) -> Result<Vec<MirrorError>> {
        let mut errors = Vec::new();

        // 1. Check for empty/deletion
        if let Some(e) = self.check_not_empty(ctx) {
            errors.push(e);
        }

        // 2. Check for force push
        if let Some(e) = self.check_not_force_push(ctx) {
            errors.push(e);
        }

        // 3. Check branch protection
        if let Some(e) = self.check_branch_protection(ctx) {
            errors.push(e);
        }

        // 4. Check delete ratio (大量删除)
        if let Some(e) = self.check_delete_ratio(ctx) {
            errors.push(e);
        }

        Ok(errors)
    }

    /// Check: not pushing to empty repo or deletion
    fn check_not_empty(&self, ctx: &MirrorPushContext<'_>) -> Option<MirrorError> {
        // 检测删除操作
        if ctx.new_sha == NULL_SHA {
            if !self.security.allow_branch_delete {
                return Some(MirrorError {
                    code: "E001".to_string(),
                    message: format!("🚫 禁止镜像：检测到分支删除操作 ({})", ctx.ref_name),
                    repo: ctx.repo_name.to_string(),
                    branch: Some(ctx.ref_name.to_string()),
                    severity: MirrorSeverity::High,
                });
            }
        }

        // 检测空仓库（new_sha 是 null）
        if ctx.old_sha == NULL_SHA && ctx.new_sha != NULL_SHA {
            // 新建分支，检查仓库是否有内容
            if !self.has_commits(ctx) {
                if !self.security.allow_empty_mirror {
                    return Some(MirrorError {
                        code: "E002".to_string(),
                        message: format!("🚫 禁止镜像：源仓库 {} 为空提交", ctx.repo_name),
                        repo: ctx.repo_name.to_string(),
                        branch: Some(ctx.ref_name.to_string()),
                        severity: MirrorSeverity::High,
                    });
                }
            }
        }

        None
    }

    /// Check: not force pushing
    fn check_not_force_push(&self, ctx: &MirrorPushContext<'_>) -> Option<MirrorError> {
        // 跳过新建分支
        if ctx.old_sha == NULL_SHA {
            return None;
        }

        if !self.security.allow_force_push {
            return Some(MirrorError {
                code: "E003".to_string(),
                message: format!(
                    "🚫 禁止镜像：检测到 force-push\n\
                     分支: {}\n\
                     旧提交: {}\n\
                     新提交: {}\n\
                     原因: 禁止强制推送，保护备份仓库历史完整性",
                    ctx.ref_name,
                    &ctx.old_sha[..8],
                    &ctx.new_sha[..8]
                ),
                repo: ctx.repo_name.to_string(),
                branch: Some(ctx.ref_name.to_string()),
                severity: MirrorSeverity::Critical,
            });
        }

        None
    }

    /// Check: branch protection rules
    fn check_branch_protection(&self, ctx: &MirrorPushContext<'_>) -> Option<MirrorError> {
        // 检查是否受保护分支
        let is_protected = self.security.protected_branches.iter().any(|pattern| {
            if pattern.ends_with("/*") {
                // glob pattern: release/*
                let prefix = &pattern[..pattern.len() - 2];
                ctx.ref_name.starts_with(prefix)
            } else {
                *pattern == ctx.ref_name
            }
        });

        if is_protected {
            // 检查删除
            if ctx.new_sha == NULL_SHA {
                return Some(MirrorError {
                    code: "E004".to_string(),
                    message: format!("🚫 禁止镜像：保护分支 {} 禁止删除", ctx.ref_name),
                    repo: ctx.repo_name.to_string(),
                    branch: Some(ctx.ref_name.to_string()),
                    severity: MirrorSeverity::Critical,
                });
            }
        }

        None
    }

    /// Check: delete ratio (大量删除检测)
    fn check_delete_ratio(&self, ctx: &MirrorPushContext<'_>) -> Option<MirrorError> {
        if ctx.old_sha == NULL_SHA || ctx.new_sha == NULL_SHA {
            return None;
        }

        // 获取变更的文件统计
        let diff = self.get_diff_stats(ctx)?;
        let total = diff.added + diff.modified + diff.deleted;
        if total == 0 {
            return None;
        }

        let delete_ratio = diff.deleted as f64 / total as f64;
        let max_ratio = 0.5; // 50% 删除率上限

        if delete_ratio > max_ratio {
            return Some(MirrorError {
                code: "E005".to_string(),
                message: format!(
                    "🚫 禁止镜像：删除比例 {:.0}% 超过限制 {:.0}%\n\
                     新增: {}, 修改: {}, 删除: {}",
                    delete_ratio * 100.0,
                    max_ratio * 100.0,
                    diff.added,
                    diff.modified,
                    diff.deleted
                ),
                repo: ctx.repo_name.to_string(),
                branch: Some(ctx.ref_name.to_string()),
                severity: MirrorSeverity::High,
            });
        }

        None
    }

    /// Check if repo has commits
    fn has_commits(&self, ctx: &MirrorPushContext<'_>) -> bool {
        let repo_path = ctx.repos_dir.join(format!("{}.git", ctx.repo_name));
        let output = Command::new("git")
            .args(&["rev-list", "--count", ctx.new_sha])
            .current_dir(&repo_path)
            .output()
            .ok();

        match output {
            Some(o) if o.status.success() => {
                let count = String::from_utf8_lossy(&o.stdout);
                count.trim().parse::<u32>().unwrap_or(0) > 0
            }
            _ => false,
        }
    }

    /// Get diff statistics between old and new SHA
    fn get_diff_stats(&self, ctx: &MirrorPushContext<'_>) -> Option<DiffStats> {
        let repo_path = ctx.repos_dir.join(format!("{}.git", ctx.repo_name));
        let output = Command::new("git")
            .args(&[
                "diff",
                "--numstat",
                &format!("{}..{}", ctx.old_sha, ctx.new_sha),
            ])
            .current_dir(&repo_path)
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let mut stats = DiffStats::default();
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            if parts.len() >= 3 {
                let added: i32 = parts[0].parse().unwrap_or(0);
                let deleted: i32 = parts[1].parse().unwrap_or(0);

                if added == 0 && deleted == 0 {
                    // 二进制文件
                    continue;
                }

                if deleted > 0 {
                    stats.deleted += deleted;
                }
                if added > 0 {
                    stats.added += added;
                }
                stats.modified += 1;
            }
        }

        Some(stats)
    }

    /// Push to all mirror targets
    pub async fn push_to_mirrors(&self, ctx: &MirrorPushContext<'_>) -> Vec<MirrorPushResult> {
        let mut results = Vec::new();
        let targets = self.targets_for_repo(ctx.repo_name);

        for target in targets {
            let result = self.push_to_target(ctx, target).await;
            results.push(result);
        }

        results
    }

    /// Push to a single mirror target
    async fn push_to_target(
        &self,
        ctx: &MirrorPushContext,
        target: &MirrorTarget,
    ) -> MirrorPushResult {
        // 构建远程 URL (替换 {repo})
        let remote_url = target.url.replace("{repo}", ctx.repo_name);

        // 确定要推送的 ref
        let ref_to_push = if ctx.ref_name.starts_with("refs/heads/") {
            ctx.ref_name.replace("refs/heads/", "refs/heads/")
        } else {
            ctx.ref_name.to_string()
        };

        // 获取仓库路径
        let repo_path = ctx.repos_dir.join(format!("{}.git", ctx.repo_name));

        info!(
            "Pushing {} to {} ({})",
            ctx.ref_name, target.name, remote_url
        );

        // 构建 git push 命令
        let mut cmd = Command::new("git");
        cmd.arg("push")
            .arg(&remote_url)
            .arg(format!("{}:{}", ctx.new_sha, ref_to_push))
            .current_dir(&repo_path);

        // 如果指定了 SSH key，配置 SSH
        if let Some(ref ssh_key) = target.ssh_key {
            let ssh_cmd = format!("ssh -i {}", ssh_key);
            cmd.env("GIT_SSH_COMMAND", ssh_cmd);
        }

        // 执行推送
        match cmd.output() {
            Ok(output) => {
                if output.status.success() {
                    info!(
                        "✅ Mirror push success: {} → {}",
                        ctx.repo_name, target.name
                    );
                    MirrorPushResult {
                        target: target.name.clone(),
                        success: true,
                        error: None,
                        old_sha: ctx.old_sha.to_string(),
                        new_sha: ctx.new_sha.to_string(),
                    }
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    error!(
                        "❌ Mirror push failed: {} → {}: {}",
                        ctx.repo_name, target.name, stderr
                    );
                    MirrorPushResult {
                        target: target.name.clone(),
                        success: false,
                        error: Some(MirrorError {
                            code: "E101".to_string(),
                            message: format!("镜像推送失败: {}", stderr),
                            repo: ctx.repo_name.to_string(),
                            branch: Some(ctx.ref_name.to_string()),
                            severity: MirrorSeverity::High,
                        }),
                        old_sha: ctx.old_sha.to_string(),
                        new_sha: ctx.new_sha.to_string(),
                    }
                }
            }
            Err(e) => {
                error!(
                    "❌ Mirror push error: {} → {}: {}",
                    ctx.repo_name, target.name, e
                );
                MirrorPushResult {
                    target: target.name.clone(),
                    success: false,
                    error: Some(MirrorError {
                        code: "E102".to_string(),
                        message: format!("镜像推送异常: {}", e),
                        repo: ctx.repo_name.to_string(),
                        branch: Some(ctx.ref_name.to_string()),
                        severity: MirrorSeverity::High,
                    }),
                    old_sha: ctx.old_sha.to_string(),
                    new_sha: ctx.new_sha.to_string(),
                }
            }
        }
    }
}

#[derive(Debug, Default)]
struct DiffStats {
    added: i32,
    modified: i32,
    deleted: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mirror_config_load_default() {
        let mirrors = MirrorsFile::default();
        assert!(mirrors.mirrors.is_empty());
    }

    #[test]
    fn test_mirror_matching_all_repos() {
        let mirrors = MirrorsFile {
            mirrors: vec![MirrorTarget {
                name: "gitee".into(),
                url: "git@gitee.com:user/repo.git".into(),
                repos: vec![],
                refs: vec![],
                enabled: true,
                ssh_key: None,
            }],
        };
        let manager = MirrorManager::new(&mirrors);
        assert_eq!(manager.targets_for_repo("my-repo").len(), 1);
        assert_eq!(manager.targets_for_repo("other-repo").len(), 1);
    }

    #[test]
    fn test_mirror_matching_specific_repos() {
        let mirrors = MirrorsFile {
            mirrors: vec![MirrorTarget {
                name: "gitee".into(),
                url: "git@gitee.com:user/repo.git".into(),
                repos: vec!["my-repo".into()],
                refs: vec![],
                enabled: true,
                ssh_key: None,
            }],
        };
        let manager = MirrorManager::new(&mirrors);
        assert_eq!(manager.targets_for_repo("my-repo").len(), 1);
        assert_eq!(manager.targets_for_repo("other-repo").len(), 0);
    }

    #[test]
    fn test_mirror_matching_glob_pattern() {
        let mirrors = MirrorsFile {
            mirrors: vec![MirrorTarget {
                name: "gitee".into(),
                url: "git@gitee.com:user/repo.git".into(),
                repos: vec!["open-*".into()],
                refs: vec![],
                enabled: true,
                ssh_key: None,
            }],
        };
        let manager = MirrorManager::new(&mirrors);
        assert_eq!(manager.targets_for_repo("open-daemon").len(), 1);
        assert_eq!(manager.targets_for_repo("closed-project").len(), 0);
    }

    #[test]
    fn test_mirror_disabled() {
        let mirrors = MirrorsFile {
            mirrors: vec![MirrorTarget {
                name: "gitee".into(),
                url: "git@gitee.com:user/repo.git".into(),
                repos: vec![],
                refs: vec![],
                enabled: false,
                ssh_key: None,
            }],
        };
        let manager = MirrorManager::new(&mirrors);
        assert!(manager.all_targets().is_empty());
    }

    #[test]
    fn test_mirrors_file_roundtrip() {
        let mirrors = MirrorsFile {
            mirrors: vec![MirrorTarget {
                name: "github".into(),
                url: "git@github.com:user/repo.git".into(),
                repos: vec!["*".into()],
                refs: vec!["refs/heads/*".into()],
                enabled: true,
                ssh_key: Some("~/.ssh/mirror_key".into()),
            }],
        };
        let toml_str = toml::to_string_pretty(&mirrors).unwrap();
        let parsed: MirrorsFile = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.mirrors.len(), 1);
        assert_eq!(parsed.mirrors[0].name, "github");
    }

    #[test]
    fn test_security_validation_force_push() {
        let mirrors = MirrorsFile::default();
        let manager = MirrorManager::new(&mirrors);

        let ctx = MirrorPushContext {
            repo_name: "test-repo",
            ref_name: "refs/heads/master",
            old_sha: "abc1234000000000000000000000000000000000",
            new_sha: "def5678000000000000000000000000000000000",
            actor: "test-agent",
            repos_dir: Path::new("/tmp/repos"),
        };

        let errors = manager.validate_push(&ctx).unwrap();
        assert!(!errors.is_empty());
        assert_eq!(errors[0].code, "E003"); // force push error
    }

    #[test]
    fn test_security_validation_branch_delete() {
        let mirrors = MirrorsFile::default();
        let manager = MirrorManager::new(&mirrors);

        let ctx = MirrorPushContext {
            repo_name: "test-repo",
            ref_name: "refs/heads/master",
            old_sha: "abc1234000000000000000000000000000000000",
            new_sha: "0000000000000000000000000000000000000000",
            actor: "test-agent",
            repos_dir: Path::new("/tmp/repos"),
        };

        let errors = manager.validate_push(&ctx).unwrap();
        assert!(!errors.is_empty());
        // E001: deletion, or E004: protected branch delete
        assert!(errors.iter().any(|e| e.code == "E001" || e.code == "E004"));
    }

    #[test]
    fn test_protected_branch_delete() {
        let mirrors = MirrorsFile::default();
        let manager = MirrorManager::new(&mirrors);

        // Test protected branch delete
        let ctx = MirrorPushContext {
            repo_name: "test-repo",
            ref_name: "refs/heads/master", // protected branch
            old_sha: "abc1234000000000000000000000000000000000",
            new_sha: "0000000000000000000000000000000000000000",
            actor: "test-agent",
            repos_dir: Path::new("/tmp/repos"),
        };

        let errors = manager.validate_push(&ctx).unwrap();
        assert!(errors.iter().any(|e| e.code == "E004"));
    }
}
