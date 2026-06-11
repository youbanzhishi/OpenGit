//! Audit Log — Every Git operation is logged for traceability

use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// A single audit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// When the event occurred
    pub timestamp: String,
    /// Repository name
    pub repo: String,
    /// Identity that performed the action
    pub identity: String,
    /// Action that was attempted
    pub action: String,
    /// Ref name (if applicable)
    pub ref_name: Option<String>,
    /// Whether the action was allowed
    pub allowed: bool,
    /// Reason for denial (if denied)
    pub reason: Option<String>,
}

/// Audit log — thread-safe append-only log
#[derive(Debug)]
pub struct AuditLog {
    entries: Mutex<Vec<AuditEntry>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    /// Log an entry
    pub fn log(&self, entry: AuditEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(entry);
        }
    }

    /// Get all entries
    pub fn entries(&self) -> Vec<AuditEntry> {
        self.entries.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Get entries for a specific repo
    pub fn entries_for_repo(&self, repo: &str) -> Vec<AuditEntry> {
        self.entries()
            .into_iter()
            .filter(|e| e.repo == repo)
            .collect()
    }

    /// Get denied entries
    pub fn denied_entries(&self) -> Vec<AuditEntry> {
        self.entries().into_iter().filter(|e| !e.allowed).collect()
    }

    /// Export entries as JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&self.entries()).unwrap_or_default()
    }
}

impl Clone for AuditLog {
    fn clone(&self) -> Self {
        Self {
            entries: Mutex::new(self.entries()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_log() {
        let log = AuditLog::new();
        log.log(AuditEntry {
            timestamp: "2026-06-11T00:00:00Z".into(),
            repo: "test-repo".into(),
            identity: "agent-deploy".into(),
            action: "DeleteBranch".into(),
            ref_name: Some("refs/heads/feature".into()),
            allowed: false,
            reason: Some("删除远程分支绝对禁止".into()),
        });

        assert_eq!(log.entries().len(), 1);
        assert_eq!(log.denied_entries().len(), 1);
        assert_eq!(log.entries_for_repo("test-repo").len(), 1);
        assert_eq!(log.entries_for_repo("other-repo").len(), 0);
    }
}
