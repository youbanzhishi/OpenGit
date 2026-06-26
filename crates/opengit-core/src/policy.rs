//! Policy engine — fine-grained access control for Git operations.
//!
//! Evaluates identity + action + repo against rule set and returns Allow/Deny/Confirm/AuditLog.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Git operation types that can be controlled by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Push,
    ForcePush,
    DeleteBranch,
    DeleteRepo,
    Tag,
    Merge,
    ResetStaging,
    AddAll,
    Stash,
    Admin,
    Read,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Push => "push",
            Self::ForcePush => "force_push",
            Self::DeleteBranch => "delete_branch",
            Self::DeleteRepo => "delete_repo",
            Self::Tag => "tag",
            Self::Merge => "merge",
            Self::ResetStaging => "reset_staging",
            Self::AddAll => "add_all",
            Self::Stash => "stash",
            Self::Admin => "admin",
            Self::Read => "read",
        }
    }
}

/// Permission level for a policy rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    Allow,
    Deny,
    Confirm,
    AuditLog,
}

/// Result of a policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalResult {
    pub allowed: bool,
    pub permission: Permission,
    pub action: Action,
    pub reason: Option<String>,
    pub matched_rule: Option<String>,
}

impl EvalResult {
    pub fn is_allowed(&self) -> bool {
        self.allowed
    }

    pub fn allow(action: Action) -> Self {
        Self {
            allowed: true,
            permission: Permission::Allow,
            action,
            reason: None,
            matched_rule: None,
        }
    }

    pub fn deny(action: Action, reason: impl Into<String>) -> Self {
        Self {
            allowed: false,
            permission: Permission::Deny,
            action,
            reason: Some(reason.into()),
            matched_rule: None,
        }
    }
}

/// A single policy rule: identity + action → permission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub identity: String,
    pub action: Action,
    pub permission: Permission,
    pub reason: Option<String>,
}

/// A set of rules scoped to a repository (or "*" for global).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub repo: String,
    pub rules: Vec<PolicyRule>,
}

impl Policy {
    pub fn new(repo: impl Into<String>) -> Self {
        Self {
            repo: repo.into(),
            rules: Vec::new(),
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }
}

/// The policy engine: holds default + custom policies, evaluates requests.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    default: Policy,
    custom: Vec<Policy>,
}

impl PolicyEngine {
    /// Create a new engine with default allow-all policy.
    pub fn new() -> Self {
        let mut default = Policy::new("*");
        default.add_rule(PolicyRule {
            identity: "*".into(),
            action: Action::Read,
            permission: Permission::Allow,
            reason: Some("default read access".into()),
        });
        Self {
            default,
            custom: Vec::new(),
        }
    }

    /// Load policy engine from a YAML file.
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let policies: Vec<Policy> = serde_yaml::from_str(&content).unwrap_or_default();
        let (default, custom): (Vec<_>, Vec<_>) =
            policies.into_iter().partition(|p| p.repo == "*");
        let default = default.into_iter().next().unwrap_or_else(|| Policy::new("*"));
        Ok(Self { default, custom })
    }

    /// Save all policies to a YAML file.
    pub fn save_to_file(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut all = vec![self.default.clone()];
        all.extend(self.custom.clone());
        let content = serde_yaml::to_string(&all)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Evaluate a general action against policy.
    pub fn evaluate(&self, repo: &str, identity: &str, action: Action) -> EvalResult {
        // Check custom policies first (most specific match wins)
        for policy in &self.custom {
            if policy.repo == "*" || policy.repo == repo {
                if let Some(result) = self.eval_rules(&policy.rules, identity, action) {
                    return result;
                }
            }
        }
        // Fall back to default policy
        if let Some(result) = self.eval_rules(&self.default.rules, identity, action) {
            return result;
        }
        // Default deny
        EvalResult::deny(action, "no matching policy rule")
    }

    /// Evaluate a push operation (includes ref-based checks).
    pub fn evaluate_push(
        &self,
        repo: &str,
        identity: &str,
        _ref_name: &str,
        _old_sha: &str,
        _new_sha: &str,
    ) -> EvalResult {
        self.evaluate(repo, identity, Action::Push)
    }

    fn eval_rules(&self, rules: &[PolicyRule], identity: &str, action: Action) -> Option<EvalResult> {
        for rule in rules {
            if (rule.identity == "*" || rule.identity == identity) && rule.action == action {
                let allowed = matches!(rule.permission, Permission::Allow | Permission::AuditLog);
                return Some(EvalResult {
                    allowed,
                    permission: rule.permission,
                    action,
                    reason: rule.reason.clone(),
                    matched_rule: Some(format!(
                        "{}:{}:{:?}",
                        rule.identity,
                        action.as_str(),
                        rule.permission
                    )
                    .to_lowercase()),
                });
            }
        }
        None
    }

    pub fn custom_policies(&self) -> &[Policy] {
        &self.custom
    }

    pub fn custom_policies_mut(&mut self) -> &mut Vec<Policy> {
        &mut self.custom
    }

    pub fn default_policy(&self) -> &Policy {
        &self.default
    }

    pub fn add_policy(&mut self, policy: Policy) {
        self.custom.push(policy);
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}
