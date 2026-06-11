//! Audit Log — Every Git operation is logged for traceability
//!
//! P2: Supports file persistence — entries are appended to a JSON file.

use serde::{Deserialize, Serialize};
use std::path::Path;
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

/// Audit log — thread-safe append-only log with optional file persistence
#[derive(Debug)]
pub struct AuditLog {
    entries: Mutex<Vec<AuditEntry>>,
    file_path: Option<String>,
}

#[allow(clippy::new_without_default)]
impl AuditLog {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            file_path: None,
        }
    }

    /// Create an audit log with file persistence
    pub fn with_file(path: &Path) -> Self {
        let mut log = Self::new();
        log.file_path = Some(path.to_string_lossy().to_string());

        // Load existing entries from file
        if path.exists() {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(entries) = serde_json::from_str::<Vec<AuditEntry>>(&content) {
                    if let Ok(mut e) = log.entries.lock() {
                        *e = entries;
                    }
                }
            }
        }

        log
    }

    /// Log an entry and persist to file
    pub fn log(&self, entry: AuditEntry) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.push(entry);
            // Persist to file if configured
            if let Some(ref path) = self.file_path {
                if let Some(parent) = std::path::Path::new(path).parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                if let Ok(json) = serde_json::to_string(&*entries) {
                    let _ = std::fs::write(path, json);
                }
            }
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

    /// Get recent entries (last N)
    pub fn recent(&self, n: usize) -> Vec<AuditEntry> {
        let entries = self.entries();
        let start = entries.len().saturating_sub(n);
        entries[start..].to_vec()
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
            file_path: self.file_path.clone(),
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

    #[test]
    fn test_audit_log_recent() {
        let log = AuditLog::new();
        for i in 0..10 {
            log.log(AuditEntry {
                timestamp: format!("2026-06-11T00:0{}:00Z", i),
                repo: "test".into(),
                identity: "agent".into(),
                action: "Push".into(),
                ref_name: None,
                allowed: true,
                reason: None,
            });
        }
        assert_eq!(log.recent(3).len(), 3);
        assert_eq!(log.entries().len(), 10);
    }

    #[test]
    fn test_audit_log_file_persistence() {
        let dir = std::env::temp_dir().join("opengit_audit_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let path = dir.join("audit.json");

        {
            let log = AuditLog::with_file(&path);
            log.log(AuditEntry {
                timestamp: "2026-06-11T00:00:00Z".into(),
                repo: "test-repo".into(),
                identity: "agent-deploy".into(),
                action: "Push".into(),
                ref_name: None,
                allowed: true,
                reason: None,
            });
        }

        // Reload and verify
        let log2 = AuditLog::with_file(&path);
        assert_eq!(log2.entries().len(), 1);
        assert_eq!(log2.entries()[0].repo, "test-repo");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
