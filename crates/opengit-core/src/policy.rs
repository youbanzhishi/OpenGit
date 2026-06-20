//! Policy Engine — Fine-grained permission control for Git operations
//!
//! Every Git action is evaluated against a policy before execution.
//! Policies are defined per-repo × per-identity, with sensible defaults
//! that match real-world agent safety requirements.
//!
//! P2: Supports runtime modification and file persistence.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Git actions that can be controlled by policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    /// Push commits to a branch
    Push,
    /// Force push (overwrite remote history)
    ForcePush,
    /// Delete a remote branch
    DeleteBranch,
    /// Delete the entire repository
    DeleteRepo,
    /// Create/delete tags
    Tag,
    /// Merge branches (via API)
    Merge,
    /// Reset staging area (batch unstage)
    ResetStaging,
    /// Stage all files (git add -A equivalent)
    AddAll,
    /// Stash changes
    Stash,
    /// Admin operations (repo settings, user management)
    Admin,
    /// Read/clone the repository
    Read,
}

/// Permission outcome for an action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    /// Action is allowed
    Allow,
    /// Action is denied
    Deny,
    /// Action requires additional confirmation (2FA, interactive approval)
    Confirm,
    /// Action is allowed but audit-logged with warning
    AuditLog,
}

impl Permission {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Permission::Allow | Permission::AuditLog)
    }
}

/// A single policy rule: identity pattern → action → permission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Identity pattern (glob: "agent-*", exact: "agent-deploy", or "*" for all)
    pub identity: String,
    /// The action this rule controls
    pub action: Action,
    /// The permission outcome
    pub permission: Permission,
    /// Optional reason (shown in denial messages)
    pub reason: Option<String>,
}

/// Default agent safety rules — the "never again" rules born from real incidents
fn default_agent_rules() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::Push,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::ForcePush,
            permission: Permission::Deny,
            reason: Some("强推绝对禁止 — 18个仓库分支被误删的教训".into()),
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::DeleteBranch,
            permission: Permission::Deny,
            reason: Some("删除远程分支绝对禁止 — 无任何绕过方式".into()),
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::DeleteRepo,
            permission: Permission::Deny,
            reason: Some("删除仓库绝对禁止".into()),
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::ResetStaging,
            permission: Permission::Deny,
            reason: Some("多Agent共享暂存区，清空=丢别人的工作".into()),
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::AddAll,
            permission: Permission::Deny,
            reason: Some("只能add自己改的文件，严禁git add -A".into()),
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::Stash,
            permission: Permission::Deny,
            reason: Some("stash在多Agent环境会丢工作".into()),
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::Tag,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::Merge,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::Read,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "agent-*".into(),
            action: Action::Admin,
            permission: Permission::Deny,
            reason: Some("Agent不能管理仓库设置".into()),
        },
    ]
}

fn default_human_rules() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            identity: "human-*".into(),
            action: Action::Push,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "human-*".into(),
            action: Action::ForcePush,
            permission: Permission::AuditLog,
            reason: Some("人类强推需审计记录".into()),
        },
        PolicyRule {
            identity: "human-*".into(),
            action: Action::DeleteBranch,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "human-*".into(),
            action: Action::DeleteRepo,
            permission: Permission::Confirm,
            reason: Some("删除仓库需要二次确认".into()),
        },
        PolicyRule {
            identity: "human-*".into(),
            action: Action::Read,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "human-*".into(),
            action: Action::Tag,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "human-*".into(),
            action: Action::Merge,
            permission: Permission::Allow,
            reason: None,
        },
        PolicyRule {
            identity: "human-*".into(),
            action: Action::Admin,
            permission: Permission::Allow,
            reason: None,
        },
    ]
}

/// Complete policy for a repository
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Repository name (glob pattern supported)
    pub repo: String,
    /// Policy rules (evaluated in order, first match wins)
    pub rules: Vec<PolicyRule>,
}

impl Policy {
    /// Create a policy with built-in safe defaults
    pub fn new(repo: &str) -> Self {
        let mut rules = default_agent_rules();
        rules.extend(default_human_rules());
        Self {
            repo: repo.into(),
            rules,
        }
    }

    /// Add a custom rule (inserted at the beginning = highest priority)
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.insert(0, rule);
    }
}

/// The policy engine — evaluates actions against policies
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    /// Policies indexed by repo pattern
    policies: Vec<Policy>,
    /// Default policy (applied when no repo-specific policy matches)
    default_policy: Policy,
}

#[allow(clippy::new_without_default)]
impl PolicyEngine {
    /// Create a new policy engine with safe defaults
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            default_policy: Policy::new("*"),
        }
    }

    /// Load policies from a YAML file
    pub fn from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read policy file: {}", path.display()))?;
        let config: PolicyConfig =
            serde_yaml::from_str(&content).with_context(|| "Failed to parse policy config")?;

        let mut engine = Self::new();
        for policy in config.policies {
            engine.add_policy(policy);
        }
        Ok(engine)
    }

    /// Save policies to a YAML file (P2: persistence)
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        #[derive(Serialize)]
        struct PolicyConfigFile {
            policies: Vec<Policy>,
        }
        let config = PolicyConfigFile {
            policies: self.policies.clone(),
        };
        let content =
            serde_yaml::to_string(&config).with_context(|| "Failed to serialize policy config")?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write policy file: {}", path.display()))?;
        Ok(())
    }

    /// Add a policy to the engine
    pub fn add_policy(&mut self, policy: Policy) {
        self.policies.push(policy);
    }

    /// Get all custom policies (for listing)
    pub fn custom_policies(&self) -> &[Policy] {
        &self.policies
    }

    /// Get mutable reference to custom policies (for runtime modification)
    pub fn custom_policies_mut(&mut self) -> &mut Vec<Policy> {
        &mut self.policies
    }

    /// Get the default policy (for listing)
    pub fn default_policy(&self) -> &Policy {
        &self.default_policy
    }

    /// Evaluate whether an identity can perform an action on a repo
    pub fn evaluate(&self, repo: &str, identity: &str, action: Action) -> EvalResult {
        // Find matching policy (first repo-specific, then default)
        let policy = self.find_policy(repo);

        // Evaluate rules in order, first match wins
        for rule in &policy.rules {
            if rule.action != action {
                continue;
            }
            if !matches_identity(&rule.identity, identity) {
                continue;
            }
            return EvalResult {
                action,
                permission: rule.permission,
                reason: rule.reason.clone(),
                rule_identity: rule.identity.clone(),
            };
        }

        // No matching rule — deny by default (fail-closed)
        EvalResult {
            action,
            permission: Permission::Deny,
            reason: Some("No matching policy rule — denied by default".into()),
            rule_identity: "default".into(),
        }
    }

    /// Evaluate a git push ref update with force push detection
    ///
    /// Uses repository access to check if old_sha is an ancestor of new_sha.
    /// If not, it's a force push — and the ForcePush policy is checked.
    pub fn evaluate_push_with_repo(
        &self,
        repo: &str,
        identity: &str,
        ref_name: &str,
        old_sha: &str,
        new_sha: &str,
        repo_path: &std::path::Path,
    ) -> EvalResult {
        let action = classify_push_action(ref_name, old_sha, new_sha);

        // For non-delete updates, check if it's a force push
        if action == Action::Push && old_sha != ZERO_SHA {
            // Check if old_sha is an ancestor of new_sha
            // If not, this is a force push
            if let Ok(git_repo) = crate::repository::Repository::open(repo_path) {
                match git_repo.is_ancestor(old_sha, new_sha) {
                    Ok(true) => {
                        // Normal push — old is ancestor of new
                    }
                    Ok(false) => {
                        // Force push! — old is NOT ancestor of new
                        return self.evaluate(repo, identity, Action::ForcePush);
                    }
                    Err(e) => {
                        // Can't determine ancestry — be conservative and check ForcePush
                        tracing::warn!(
                            "Cannot determine ancestry for force push check: {} — treating as potential force push",
                            e
                        );
                        let force_result = self.evaluate(repo, identity, Action::ForcePush);
                        if !force_result.is_allowed() {
                            return force_result;
                        }
                        // If force push is allowed, fall through to normal push check
                    }
                }
            }
        }

        self.evaluate(repo, identity, action)
    }

    /// Evaluate a git push ref update (without force push detection — for hook pipeline)
    pub fn evaluate_push(
        &self,
        repo: &str,
        identity: &str,
        _ref_name: &str,
        old_sha: &str,
        new_sha: &str,
    ) -> EvalResult {
        let action = classify_push_action(_ref_name, old_sha, new_sha);
        self.evaluate(repo, identity, action)
    }

    fn find_policy(&self, repo: &str) -> &Policy {
        for policy in &self.policies {
            if matches_repo(&policy.repo, repo) {
                return policy;
            }
        }
        &self.default_policy
    }
}

/// The zero SHA used in Git protocol to represent "no object"
const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

/// Classify the action type from a ref update
fn classify_push_action(ref_name: &str, old_sha: &str, new_sha: &str) -> Action {
    if new_sha == ZERO_SHA {
        // Deleting a ref
        if ref_name.starts_with("refs/tags/") {
            Action::Tag
        } else {
            Action::DeleteBranch
        }
    } else if old_sha == ZERO_SHA {
        // Creating a new ref
        Action::Push
    } else if ref_name.starts_with("refs/tags/") {
        // Updating a tag (shouldn't happen normally, but treat as tag action)
        Action::Tag
    } else {
        // Normal push update — force push detection happens at a higher level
        Action::Push
    }
}

/// Result of a policy evaluation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResult {
    pub action: Action,
    pub permission: Permission,
    pub reason: Option<String>,
    pub rule_identity: String,
}

impl EvalResult {
    pub fn is_allowed(&self) -> bool {
        self.permission.is_allowed()
    }
}

/// Top-level policy config file format
#[derive(Debug, Deserialize)]
struct PolicyConfig {
    policies: Vec<Policy>,
}

/// Match an identity pattern against an actual identity name
fn matches_identity(pattern: &str, identity: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == identity {
        return true;
    }
    // Simple glob: "agent-*" matches "agent-deploy", "agent-test", etc.
    if let Some(prefix) = pattern.strip_suffix('*') {
        return identity.starts_with(prefix);
    }
    false
}

/// Match a repo pattern against an actual repo name
fn matches_repo(pattern: &str, repo: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == repo {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return repo.starts_with(prefix);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_agent_policy() {
        let engine = PolicyEngine::new();

        // Agent can push
        let result = engine.evaluate("my-repo", "agent-deploy", Action::Push);
        assert!(result.is_allowed());

        // Agent cannot force push
        let result = engine.evaluate("my-repo", "agent-deploy", Action::ForcePush);
        assert!(!result.is_allowed());

        // Agent cannot delete branch
        let result = engine.evaluate("my-repo", "agent-deploy", Action::DeleteBranch);
        assert!(!result.is_allowed());

        // Agent cannot delete repo
        let result = engine.evaluate("my-repo", "agent-deploy", Action::DeleteRepo);
        assert!(!result.is_allowed());

        // Agent cannot add all
        let result = engine.evaluate("my-repo", "agent-deploy", Action::AddAll);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_default_human_policy() {
        let engine = PolicyEngine::new();

        // Human can push
        let result = engine.evaluate("my-repo", "human-alice", Action::Push);
        assert!(result.is_allowed());

        // Human can delete branch
        let result = engine.evaluate("my-repo", "human-alice", Action::DeleteBranch);
        assert!(result.is_allowed());

        // Human force push is audit-logged
        let result = engine.evaluate("my-repo", "human-alice", Action::ForcePush);
        assert!(result.is_allowed());
        assert_eq!(result.permission, Permission::AuditLog);

        // Human delete repo needs confirm
        let result = engine.evaluate("my-repo", "human-alice", Action::DeleteRepo);
        assert_eq!(result.permission, Permission::Confirm);
    }

    #[test]
    fn test_custom_policy() {
        let mut engine = PolicyEngine::new();
        let mut policy = Policy::new("special-repo");
        policy.add_rule(PolicyRule {
            identity: "agent-deploy".into(),
            action: Action::ForcePush,
            permission: Permission::Allow,
            reason: Some("Deploy agent needs force push for rollback".into()),
        });
        engine.add_policy(policy);

        // Deploy agent can force push on special-repo
        let result = engine.evaluate("special-repo", "agent-deploy", Action::ForcePush);
        assert!(result.is_allowed());

        // But other agents still cannot
        let result = engine.evaluate("special-repo", "agent-test", Action::ForcePush);
        assert!(!result.is_allowed());

        // Other repos still use default
        let result = engine.evaluate("other-repo", "agent-deploy", Action::ForcePush);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_push_ref_evaluation() {
        let engine = PolicyEngine::new();

        // Delete ref = DeleteBranch action
        let result = engine.evaluate_push(
            "my-repo",
            "agent-deploy",
            "refs/heads/feature",
            "abc123",
            "0000000000000000000000000000000000000000",
        );
        assert!(!result.is_allowed());
        assert_eq!(result.action, Action::DeleteBranch);

        // Normal push = Push action
        let result = engine.evaluate_push(
            "my-repo",
            "agent-deploy",
            "refs/heads/feature",
            "0000000000000000000000000000000000000000",
            "abc123",
        );
        assert!(result.is_allowed());
    }

    #[test]
    fn test_fail_closed() {
        let engine = PolicyEngine::new();
        // Unknown identity pattern with no matching rule = deny
        let result = engine.evaluate("my-repo", "service-unknown", Action::Admin);
        assert!(!result.is_allowed());
    }

    #[test]
    fn test_classify_push_action() {
        // Delete branch
        assert_eq!(
            classify_push_action(
                "refs/heads/feature",
                "abc123",
                "0000000000000000000000000000000000000000"
            ),
            Action::DeleteBranch
        );
        // Delete tag
        assert_eq!(
            classify_push_action(
                "refs/tags/v1.0",
                "abc123",
                "0000000000000000000000000000000000000000"
            ),
            Action::Tag
        );
        // New branch
        assert_eq!(
            classify_push_action(
                "refs/heads/feature",
                "0000000000000000000000000000000000000000",
                "abc123"
            ),
            Action::Push
        );
        // Normal update
        assert_eq!(
            classify_push_action("refs/heads/master", "abc123", "def456"),
            Action::Push
        );
    }

    #[test]
    fn test_policy_persistence() {
        let dir = std::env::temp_dir().join("opengit_policy_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("policies.yaml");

        // Create and save
        {
            let mut engine = PolicyEngine::new();
            let mut policy = Policy::new("my-repo");
            policy.add_rule(PolicyRule {
                identity: "agent-special".into(),
                action: Action::ForcePush,
                permission: Permission::Allow,
                reason: Some("Special exception".into()),
            });
            engine.add_policy(policy);
            engine.save_to_file(&path).unwrap();
        }

        // Load and verify
        let engine = PolicyEngine::from_file(&path).unwrap();
        let result = engine.evaluate("my-repo", "agent-special", Action::ForcePush);
        assert!(result.is_allowed());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
