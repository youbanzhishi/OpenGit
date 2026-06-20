//! Mirror Audit Log System
//!
//! P5.2: Complete audit trail for all mirror operations
//! Tracks push attempts, successes, failures, and resolutions

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing;

use crate::mirror::{MirrorError, MirrorPushResult, MirrorSeverity};

/// Audit entry for a mirror operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique entry ID
    pub id: String,
    /// Timestamp (RFC3339)
    pub timestamp: String,
    /// Operation type
    pub operation: AuditOperation,
    /// Repository name
    pub repo: String,
    /// Branch name
    pub branch: Option<String>,
    /// Actor (user/service) who triggered
    pub actor: Option<String>,
    /// Identity (extended field)
    pub identity: Option<String>,
    /// Action description (extended field)
    pub action: Option<String>,
    /// Ref name (extended field)
    pub ref_name: Option<String>,
    /// Whether operation was allowed
    pub allowed: Option<bool>,
    /// Reason for decision
    pub reason: Option<String>,
    /// Details
    pub details: AuditDetails,
}

/// Operation types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    /// Push attempt to mirrors
    MirrorPush,
    /// Push blocked by security validation
    MirrorBlocked,
    /// Alert created
    AlertCreated,
    /// Alert resolved
    AlertResolved,
    /// Target added
    TargetAdded,
    /// Target removed
    TargetRemoved,
    /// Config changed
    ConfigChanged,
}

/// Details variant based on operation type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AuditDetails {
    MirrorPush {
        /// Targets attempted
        targets: Vec<TargetAttempt>,
        /// Security validation errors (if blocked)
        blocked_by: Option<Vec<String>>,
    },
    AlertEvent {
        alert_id: String,
        error_code: String,
        severity: String,
        message: String,
    },
    Resolution {
        alert_id: String,
        note: String,
    },
    ConfigChange {
        field: String,
        old_value: Option<String>,
        new_value: Option<String>,
    },
    TargetChange {
        target_name: String,
        target_url: String,
    },
}

/// Individual target attempt result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAttempt {
    pub name: String,
    pub success: bool,
    pub old_sha: String,
    pub new_sha: String,
    pub error_message: Option<String>,
}

/// Audit log - complete history of mirror operations
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Log a generic audit entry
    pub fn log(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    /// Log a mirror push operation
    pub fn log_mirror_push(
        &mut self,
        repo: &str,
        branch: &str,
        actor: Option<&str>,
        results: &[MirrorPushResult],
        errors: &[MirrorError],
    ) {
        let targets: Vec<TargetAttempt> = results
            .iter()
            .map(|r| TargetAttempt {
                name: r.target.clone(),
                success: r.success,
                old_sha: r.old_sha.clone(),
                new_sha: r.new_sha.clone(),
                error_message: r.error.as_ref().map(|e| e.message.clone()),
            })
            .collect();

        let blocked_by = if errors.is_empty() {
            None
        } else {
            Some(errors.iter().map(|e| e.code.clone()).collect())
        };

        let entry = AuditEntry {
            id: uuid_v4(),
            timestamp: now_rfc3339(),
            operation: AuditOperation::MirrorPush,
            repo: repo.to_string(),
            branch: Some(branch.to_string()),
            actor: actor.map(String::from),
            identity: None,
            action: None,
            ref_name: None,
            allowed: None,
            reason: None,
            details: AuditDetails::MirrorPush {
                targets,
                blocked_by,
            },
        };

        self.entries.push(entry);
    }

    /// Log a blocked mirror push (security validation failure)
    pub fn log_blocked(
        &mut self,
        repo: &str,
        branch: &str,
        actor: Option<&str>,
        errors: &[MirrorError],
    ) {
        let entry = AuditEntry {
            id: uuid_v4(),
            timestamp: now_rfc3339(),
            operation: AuditOperation::MirrorBlocked,
            repo: repo.to_string(),
            branch: Some(branch.to_string()),
            actor: actor.map(String::from),
            identity: None,
            action: None,
            ref_name: None,
            allowed: None,
            reason: None,
            details: AuditDetails::MirrorPush {
                targets: vec![],
                blocked_by: Some(errors.iter().map(|e| e.code.clone()).collect()),
            },
        };

        self.entries.push(entry);
    }

    /// Log alert created
    pub fn log_alert_created(&mut self, repo: &str, alert_id: &str, error: &MirrorError) {
        let entry = AuditEntry {
            id: uuid_v4(),
            timestamp: now_rfc3339(),
            operation: AuditOperation::AlertCreated,
            repo: repo.to_string(),
            branch: error.branch.clone(),
            actor: None,
            identity: None,
            action: None,
            ref_name: None,
            allowed: None,
            reason: None,
            details: AuditDetails::AlertEvent {
                alert_id: alert_id.to_string(),
                error_code: error.code.clone(),
                severity: format!("{:?}", error.severity),
                message: error.message.clone(),
            },
        };

        self.entries.push(entry);
    }

    /// Log alert resolution
    pub fn log_alert_resolved(&mut self, repo: &str, alert_id: &str, note: &str) {
        let entry = AuditEntry {
            id: uuid_v4(),
            timestamp: now_rfc3339(),
            operation: AuditOperation::AlertResolved,
            repo: repo.to_string(),
            branch: None,
            actor: None,
            identity: None,
            action: None,
            ref_name: None,
            allowed: None,
            reason: None,
            details: AuditDetails::Resolution {
                alert_id: alert_id.to_string(),
                note: note.to_string(),
            },
        };

        self.entries.push(entry);
    }

    /// Log target added
    pub fn log_target_added(&mut self, target_name: &str, target_url: &str) {
        let entry = AuditEntry {
            id: uuid_v4(),
            timestamp: now_rfc3339(),
            operation: AuditOperation::TargetAdded,
            repo: "*".to_string(),
            branch: None,
            actor: None,
            identity: None,
            action: None,
            ref_name: None,
            allowed: None,
            reason: None,
            details: AuditDetails::TargetChange {
                target_name: target_name.to_string(),
                target_url: target_url.to_string(),
            },
        };

        self.entries.push(entry);
    }

    /// Log config change
    pub fn log_config_change(
        &mut self,
        field: &str,
        old_value: Option<&str>,
        new_value: Option<&str>,
    ) {
        let entry = AuditEntry {
            id: uuid_v4(),
            timestamp: now_rfc3339(),
            operation: AuditOperation::ConfigChanged,
            repo: "*".to_string(),
            branch: None,
            actor: None,
            identity: None,
            action: None,
            ref_name: None,
            allowed: None,
            reason: None,
            details: AuditDetails::ConfigChange {
                field: field.to_string(),
                old_value: old_value.map(String::from),
                new_value: new_value.map(String::from),
            },
        };

        self.entries.push(entry);
    }

    /// Get all entries
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// Get entries for a specific repo
    pub fn for_repo(&self, repo: &str) -> Vec<&AuditEntry> {
        self.entries.iter().filter(|e| e.repo == repo).collect()
    }

    /// Get recent entries (last N)
    pub fn recent(&self, count: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(count).collect()
    }

    /// Get blocked operations count
    pub fn blocked_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.operation == AuditOperation::MirrorBlocked)
            .count()
    }

    /// Get failed pushes count
    pub fn failed_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.operation == AuditOperation::MirrorPush)
            .filter_map(|e| match &e.details {
                AuditDetails::MirrorPush { targets, .. } => {
                    Some(targets.iter().any(|t| !t.success))
                }
                _ => Some(false),
            })
            .filter(|x| *x)
            .count()
    }

    /// Load from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = std::fs::read_to_string(path)?;
        let entries: Vec<AuditEntry> = serde_json::from_str(&content)?;
        Ok(Self { entries })
    }

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&self.entries)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// Format entry for CLI display
impl AuditEntry {
    pub fn format_cli(&self) -> String {
        let emoji = match self.operation {
            AuditOperation::MirrorPush => "📤",
            AuditOperation::MirrorBlocked => "🚫",
            AuditOperation::AlertCreated => "⚠️",
            AuditOperation::AlertResolved => "✅",
            AuditOperation::TargetAdded => "➕",
            AuditOperation::TargetRemoved => "➖",
            AuditOperation::ConfigChanged => "⚙️",
        };

        let op_name = match self.operation {
            AuditOperation::MirrorPush => "Mirror Push",
            AuditOperation::MirrorBlocked => "Blocked",
            AuditOperation::AlertCreated => "Alert",
            AuditOperation::AlertResolved => "Resolved",
            AuditOperation::TargetAdded => "Target Added",
            AuditOperation::TargetRemoved => "Target Removed",
            AuditOperation::ConfigChanged => "Config Changed",
        };

        let details = match &self.details {
            AuditDetails::MirrorPush {
                targets,
                blocked_by,
            } => {
                if blocked_by.is_some() {
                    format!("BLOCKED by: {}", blocked_by.as_ref().unwrap().join(", "))
                } else {
                    let success_count = targets.iter().filter(|t| t.success).count();
                    format!(
                        "{} → {} targets ({} success)",
                        self.repo,
                        targets.len(),
                        success_count
                    )
                }
            }
            AuditDetails::AlertEvent {
                alert_id: _alert_id,
                error_code,
                severity,
                message,
            } => {
                format!(
                    "[{}] {} - {}",
                    error_code,
                    severity,
                    message.chars().take(50).collect::<String>()
                )
            }
            AuditDetails::Resolution { alert_id, note } => {
                format!("Alert {} - {}", alert_id, note)
            }
            AuditDetails::ConfigChange {
                field,
                old_value,
                new_value,
            } => {
                format!(
                    "{}: {} → {}",
                    field,
                    old_value.as_deref().unwrap_or("(none)"),
                    new_value.as_deref().unwrap_or("(none)")
                )
            }
            AuditDetails::TargetChange {
                target_name,
                target_url,
            } => {
                format!("{} ({})", target_name, target_url)
            }
        };

        format!(
            "{} {} | {} | {} | {}",
            emoji, self.timestamp, op_name, self.repo, details
        )
    }
}

/// Generate simple UUID
fn uuid_v4() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let random: u64 = {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let state = RandomState::new();
        let mut hasher = state.build_hasher();
        hasher.write_u128(timestamp);
        hasher.finish()
    };

    format!(
        "{:016x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        timestamp as u64,
        (random >> 48) as u16,
        (random >> 44) as u16 & 0x0fff,
        ((random >> 32) as u16 & 0x3fff) | 0x8000,
        random & 0xffffffffffff
    )
}

/// Get current time as RFC3339
fn now_rfc3339() -> String {
    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

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

/// Mirror status summary
#[derive(Debug, Clone, Default)]
pub struct MirrorStatusSummary {
    pub total_repos: usize,
    pub total_pushes: usize,
    pub successful_pushes: usize,
    pub failed_pushes: usize,
    pub blocked_operations: usize,
    pub active_alerts: usize,
}

impl AuditLog {
    /// Generate status summary
    pub fn status_summary(&self) -> MirrorStatusSummary {
        let mut summary = MirrorStatusSummary::default();

        summary.total_repos = self
            .entries
            .iter()
            .filter(|e| e.repo != "*")
            .map(|e| e.repo.clone())
            .collect::<std::collections::HashSet<_>>()
            .len();

        summary.total_pushes = self
            .entries
            .iter()
            .filter(|e| e.operation == AuditOperation::MirrorPush)
            .count();

        summary.successful_pushes = self
            .entries
            .iter()
            .filter(|e| e.operation == AuditOperation::MirrorPush)
            .filter_map(|e| match &e.details {
                AuditDetails::MirrorPush {
                    targets,
                    blocked_by: None,
                } => Some(targets.iter().all(|t| t.success)),
                _ => None,
            })
            .filter(|x| *x)
            .count();

        summary.failed_pushes = self
            .entries
            .iter()
            .filter(|e| e.operation == AuditOperation::MirrorPush)
            .filter_map(|e| match &e.details {
                AuditDetails::MirrorPush { targets, .. } => {
                    Some(targets.iter().any(|t| !t.success))
                }
                _ => None,
            })
            .filter(|x| *x)
            .count();

        summary.blocked_operations = self.blocked_count();

        // Active alerts = AlertCreated - AlertResolved
        let created = self
            .entries
            .iter()
            .filter(|e| e.operation == AuditOperation::AlertCreated)
            .count();
        let resolved = self
            .entries
            .iter()
            .filter(|e| e.operation == AuditOperation::AlertResolved)
            .count();
        summary.active_alerts = created - resolved;

        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log_record() {
        let mut log = AuditLog::new();

        let results = vec![
            MirrorPushResult {
                target: "github".to_string(),
                success: true,
                error: None,
                old_sha: "abc".to_string(),
                new_sha: "def".to_string(),
            },
            MirrorPushResult {
                target: "gitee".to_string(),
                success: false,
                error: Some(MirrorError {
                    code: "E101".to_string(),
                    message: "Connection failed".to_string(),
                    repo: "test-repo".to_string(),
                    branch: Some("main".to_string()),
                    severity: MirrorSeverity::High,
                }),
                old_sha: "abc".to_string(),
                new_sha: "def".to_string(),
            },
        ];

        log.log_mirror_push(
            "test-repo",
            "refs/heads/main",
            Some("developer"),
            &results,
            &[],
        );

        assert_eq!(log.entries().len(), 1);
        assert_eq!(log.failed_count(), 1);
    }

    #[test]
    fn test_status_summary() {
        let mut log = AuditLog::new();
        log.log_blocked("repo1", "main", Some("test"), &[]);
        log.log_blocked("repo2", "main", Some("test"), &[]);

        let summary = log.status_summary();
        assert_eq!(summary.blocked_operations, 2);
    }

    #[test]
    fn test_entry_format_cli() {
        let entry = AuditEntry {
            id: "test-1".to_string(),
            timestamp: "2026-06-17T10:00:00Z".to_string(),
            operation: AuditOperation::MirrorBlocked,
            repo: "my-repo".to_string(),
            branch: Some("main".to_string()),
            actor: Some("developer".to_string()),
            identity: None,
            action: None,
            ref_name: None,
            allowed: None,
            reason: None,
            details: AuditDetails::MirrorPush {
                targets: vec![],
                blocked_by: Some(vec!["E003".to_string()]),
            },
        };

        let formatted = entry.format_cli();
        assert!(formatted.contains("my-repo"));
        assert!(formatted.contains("Blocked"));
    }
}
