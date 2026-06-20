//! Hook Pipeline — Intercept and evaluate Git operations
//!
//! The hook pipeline is the enforcement layer. Even if someone bypasses
//! the API, the Git hooks will still enforce policy.
//!
//! P7: Added AI Guard integration for code semantic analysis.

use crate::ai_guard::AiGuard;
use crate::audit::{AuditEntry, AuditLog};
use crate::policy::{Action, PolicyEngine};
use serde::{Deserialize, Serialize};

/// Context provided to hook execution
#[derive(Debug, Clone)]
pub struct HookContext {
    /// Repository name
    pub repo: String,
    /// Identity making the operation
    pub identity: String,
    /// Hook type
    pub hook_type: HookType,
    /// Environment variables from Git
    pub env: std::collections::HashMap<String, String>,
}

/// Type of Git hook
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookType {
    PreReceive,
    Update,
    PostReceive,
}

/// A ref update received by pre-receive hook
#[derive(Debug, Clone)]
pub struct RefUpdate {
    /// Ref name (e.g., "refs/heads/master")
    pub ref_name: String,
    /// Old SHA (0000... = new ref)
    pub old_sha: String,
    /// New SHA (0000... = deleted ref)
    pub new_sha: String,
}

/// Result of hook execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookResult {
    /// Whether the hook allows the operation
    pub allowed: bool,
    /// Evaluation results for each ref update
    pub ref_results: Vec<RefResult>,
    /// Overall message (shown to git client)
    pub message: String,
}

/// Result for a single ref update
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefResult {
    pub ref_name: String,
    pub action: Action,
    pub allowed: bool,
    pub reason: Option<String>,
}

/// The hook pipeline — processes git hook input and evaluates against policy
pub struct HookPipeline {
    policy_engine: PolicyEngine,
    audit_log: AuditLog,
    /// AI Guard for code semantic analysis (P7)
    ai_guard: Option<AiGuard>,
}

impl HookPipeline {
    /// Create with policy engine and audit log
    pub fn new(policy_engine: PolicyEngine, audit_log: AuditLog) -> Self {
        Self {
            policy_engine,
            audit_log,
            ai_guard: None,
        }
    }

    /// Create with AI Guard enabled
    pub fn with_ai_guard(policy_engine: PolicyEngine, audit_log: AuditLog, ai_guard: AiGuard) -> Self {
        Self {
            policy_engine,
            audit_log,
            ai_guard: Some(ai_guard),
        }
    }

    /// Enable AI Guard
    pub fn enable_ai_guard(&mut self, ai_guard: AiGuard) {
        self.ai_guard = Some(ai_guard);
    }

    /// Check if AI Guard is enabled
    pub fn has_ai_guard(&self) -> bool {
        self.ai_guard.is_some()
    }

    /// Evaluate commit messages using AI Guard
    pub fn evaluate_with_ai_guard(&self, commit_messages: &[String]) -> Option<crate::ai_guard::GuardResult> {
        if let Some(guard) = &self.ai_guard {
            for msg in commit_messages {
                let result = guard.evaluate_commit_message(msg);
                if !result.allowed {
                    return Some(result);
                }
            }
            Some(crate::ai_guard::GuardResult::allowed())
        } else {
            None
        }
    }

    /// Evaluate diff content using AI Guard
    pub fn evaluate_diff_with_ai_guard(&self, diff_content: &str) -> Option<crate::ai_guard::GuardResult> {
        if let Some(guard) = &self.ai_guard {
            Some(guard.evaluate_diff(diff_content))
        } else {
            None
        }
    }

    /// Process a pre-receive hook
    ///
    /// Input format (stdin):
    ///   <old-sha> <new-sha> <ref-name>\n
    ///   ...
    ///
    /// Returns HookResult indicating allow/deny for each ref update.
    /// If ANY ref is denied, the entire push is rejected (atomic).
    pub fn process_pre_receive(&self, ctx: &HookContext, updates: &[RefUpdate]) -> HookResult {
        let mut ref_results = Vec::new();
        let mut all_allowed = true;
        let mut messages = Vec::new();

        for update in updates {
            let result = self.policy_engine.evaluate_push(
                &ctx.repo,
                &ctx.identity,
                &update.ref_name,
                &update.old_sha,
                &update.new_sha,
            );

            let allowed = result.is_allowed();

            if !allowed {
                all_allowed = false;
                let action_str = format!("{:?}", result.action);
                messages.push(format!(
                    "DENIED: {} - {} on {} by {}",
                    action_str,
                    result.reason.as_deref().unwrap_or("policy denied"),
                    update.ref_name,
                    ctx.identity,
                ));
            }

            // Audit log entry
            self.audit_log.log(AuditEntry {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                operation: crate::audit::AuditOperation::MirrorPush,
                repo: ctx.repo.clone(),
                branch: None,
                actor: None,
                identity: Some(ctx.identity.clone()),
                action: Some(format!("{:?}", result.action)),
                ref_name: Some(update.ref_name.clone()),
                allowed: allowed,
                reason: result.reason.clone(),
                details: crate::audit::AuditDetails::MirrorPush {
                    targets: vec![],
                    blocked_by: None,
                },
            });

            ref_results.push(RefResult {
                ref_name: update.ref_name.clone(),
                action: result.action,
                allowed: allowed,
                reason: result.reason.clone(),
            });
        }

        let message = if all_allowed {
            "All ref updates allowed by policy".into()
        } else {
            messages.join("\n")
        };

        HookResult {
            allowed: all_allowed,
            ref_results,
            message,
        }
    }

    /// Process an update hook (per-ref, runs after pre-receive)
    pub fn process_update(&self, ctx: &HookContext, update: &RefUpdate) -> HookResult {
        let result = self.policy_engine.evaluate_push(
            &ctx.repo,
            &ctx.identity,
            &update.ref_name,
            &update.old_sha,
            &update.new_sha,
        );

        let allowed = result.is_allowed();

        self.audit_log.log(AuditEntry {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            operation: crate::audit::AuditOperation::MirrorPush,
            repo: ctx.repo.clone(),
            branch: None,
            actor: None,
            identity: Some(ctx.identity.clone()),
            action: Some(format!("{:?}", result.action)),
            ref_name: Some(update.ref_name.clone()),
            allowed: Some(allowed),
            reason: result.reason.clone(),
            details: crate::audit::AuditDetails::MirrorPush {
                targets: vec![],
                blocked_by: None,
            },
        });

        HookResult {
            allowed,
            ref_results: vec![RefResult {
                ref_name: update.ref_name.clone(),
                action: result.action,
                allowed: allowed,
                reason: result.reason.clone(),
            }],
            message: if allowed {
                "Allowed".into()
            } else {
                format!("DENIED: {}", result.reason.clone().unwrap_or_default())
            },
        }
    }

    /// Parse pre-receive hook stdin input
    pub fn parse_pre_receive_input(input: &str) -> Vec<RefUpdate> {
        input
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    Some(RefUpdate {
                        old_sha: parts[0].into(),
                        new_sha: parts[1].into(),
                        ref_name: parts[2].into(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pre_receive_input() {
        let input = "abc123 def456 refs/heads/master\n000000 111222 refs/heads/feature-branch\n";
        let updates = HookPipeline::parse_pre_receive_input(input);
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].ref_name, "refs/heads/master");
        assert_eq!(updates[1].old_sha, "000000");
    }

    #[test]
    fn test_agent_cannot_delete_branch() {
        let engine = PolicyEngine::new();
        let audit = AuditLog::new();
        let pipeline = HookPipeline::new(engine, audit);

        let ctx = HookContext {
            repo: "test-repo".into(),
            identity: "agent-deploy".into(),
            hook_type: HookType::PreReceive,
            env: Default::default(),
        };

        let updates = vec![RefUpdate {
            ref_name: "refs/heads/feature-branch".into(),
            old_sha: "abc123".into(),
            new_sha: "0000000000000000000000000000000000000000".into(),
        }];

        let result = pipeline.process_pre_receive(&ctx, &updates);
        assert!(!result.allowed);
    }

    #[test]
    fn test_agent_can_push() {
        let engine = PolicyEngine::new();
        let audit = AuditLog::new();
        let pipeline = HookPipeline::new(engine, audit);

        let ctx = HookContext {
            repo: "test-repo".into(),
            identity: "agent-deploy".into(),
            hook_type: HookType::PreReceive,
            env: Default::default(),
        };

        let updates = vec![RefUpdate {
            ref_name: "refs/heads/feature-branch".into(),
            old_sha: "0000000000000000000000000000000000000000".into(),
            new_sha: "abc123".into(),
        }];

        let result = pipeline.process_pre_receive(&ctx, &updates);
        assert!(result.allowed);
    }

    #[test]
    fn test_human_can_delete_branch() {
        let engine = PolicyEngine::new();
        let audit = AuditLog::new();
        let pipeline = HookPipeline::new(engine, audit);

        let ctx = HookContext {
            repo: "test-repo".into(),
            identity: "human-alice".into(),
            hook_type: HookType::PreReceive,
            env: Default::default(),
        };

        let updates = vec![RefUpdate {
            ref_name: "refs/heads/feature-branch".into(),
            old_sha: "abc123".into(),
            new_sha: "0000000000000000000000000000000000000000".into(),
        }];

        let result = pipeline.process_pre_receive(&ctx, &updates);
        assert!(result.allowed);
    }
}
