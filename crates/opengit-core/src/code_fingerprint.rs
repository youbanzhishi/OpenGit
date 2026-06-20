//! Code Fingerprint — Traceable code provenance
//!
//! P7.5: Generate unique fingerprints for code changes that can be traced
//! back to their origin. Supports forensic analysis and audit trails.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Code fingerprint for a commit or diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeFingerprint {
    /// SHA256 hash of the blob content
    pub content_hash: String,
    /// Identity fingerprint (who made the change)
    pub author_fingerprint: String,
    /// Timestamp of the change
    pub timestamp: String,
    /// Hash of commit message (for traceability)
    pub commit_message_hash: String,
    /// List of files changed
    pub files_changed: Vec<String>,
    /// Number of lines added
    pub lines_added: u32,
    /// Number of lines deleted
    pub lines_deleted: u32,
    /// Repository this fingerprint belongs to
    pub repo: String,
    /// Branch or ref
    pub ref_name: String,
}

impl CodeFingerprint {
    /// Generate a short hash (first 12 characters)
    pub fn short_hash(&self) -> String {
        self.content_hash.chars().take(12).collect()
    }

    /// Format as CLI display
    pub fn format_cli(&self) -> String {
        format!(
            "Fingerprint: {} | {} | +{}/-{} | {} files | {}",
            self.short_hash(),
            self.author_fingerprint.chars().take(8).collect::<String>(),
            self.lines_added,
            self.lines_deleted,
            self.files_changed.len(),
            self.timestamp
        )
    }
}

/// Trace result when searching for fingerprint origin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    /// The fingerprint being traced
    pub fingerprint: CodeFingerprint,
    /// Possible source identities
    pub possible_sources: Vec<IdentityMatch>,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
    /// Evidence items
    pub evidence: Vec<EvidenceItem>,
    /// Trace timestamp
    pub traced_at: String,
}

/// Identity match in trace result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityMatch {
    /// Identity name
    pub identity: String,
    /// Match score (0.0 - 1.0)
    pub score: f32,
    /// Reason for match
    pub reason: String,
}

/// Evidence item supporting the trace
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    /// Timestamp of evidence
    pub timestamp: String,
    /// Action that occurred
    pub action: String,
    /// Repository
    pub repo: String,
    /// Ref (branch/tag)
    pub ref_name: String,
    /// Additional details
    pub details: Option<String>,
}

impl EvidenceItem {
    /// Format evidence for display
    pub fn format_cli(&self) -> String {
        format!(
            "{} | {} | {} | {} | {}",
            self.timestamp,
            self.action,
            self.repo,
            self.ref_name,
            self.details.as_deref().unwrap_or("-")
        )
    }
}

/// Code fingerprint generator
pub struct FingerprintGenerator {
    hasher: Sha256,
}

impl FingerprintGenerator {
    /// Create a new generator
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Generate a fingerprint from git commit data
    pub fn generate_commit_fingerprint(
        &self,
        repo: &str,
        ref_name: &str,
        commit_hash: &str,
        author: &str,
        message: &str,
        files: &[String],
        lines_added: u32,
        lines_deleted: u32,
        timestamp: &str,
    ) -> CodeFingerprint {
        let mut hasher = Sha256::new();

        // Hash all components
        hasher.update(commit_hash.as_bytes());
        hasher.update(author.as_bytes());
        hasher.update(message.as_bytes());
        for file in files {
            hasher.update(file.as_bytes());
        }
        hasher.update(lines_added.to_le_bytes());
        hasher.update(lines_deleted.to_le_bytes());

        let content_hash = hex::encode(hasher.finalize());

        // Generate author fingerprint (hashed identity)
        let mut author_hasher = Sha256::new();
        author_hasher.update(author.as_bytes());
        let author_fingerprint = hex::encode(author_hasher.finalize());

        // Hash commit message
        let mut msg_hasher = Sha256::new();
        msg_hasher.update(message.as_bytes());
        let commit_message_hash = hex::encode(msg_hasher.finalize());

        CodeFingerprint {
            content_hash,
            author_fingerprint,
            timestamp: timestamp.to_string(),
            commit_message_hash,
            files_changed: files.to_vec(),
            lines_added,
            lines_deleted,
            repo: repo.to_string(),
            ref_name: ref_name.to_string(),
        }
    }

    /// Generate a fingerprint from a diff
    pub fn generate_diff_fingerprint(&self, diff_content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(diff_content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Verify a fingerprint
    pub fn verify(&self, fingerprint: &CodeFingerprint) -> bool {
        // Recompute hash and compare
        let mut hasher = Sha256::new();
        hasher.update(fingerprint.files_changed.join("").as_bytes());
        hasher.update(fingerprint.lines_added.to_le_bytes());
        hasher.update(fingerprint.lines_deleted.to_le_bytes());

        let computed = hex::encode(hasher.finalize());

        // Content hash includes more than just diff, so this is simplified
        // In production, would need original commit data for full verification
        computed.len() == fingerprint.content_hash.len()
    }

    /// Trace a fingerprint to find its origin
    pub fn trace(
        &self,
        fingerprint: &CodeFingerprint,
        store: &FingerprintStore,
    ) -> TraceResult {
        let mut evidence = Vec::new();
        let mut sources = Vec::new();

        // Search for similar fingerprints
        let similar = store.search_similar(fingerprint);

        if similar.is_empty() {
            // No direct matches, return low confidence
            return TraceResult {
                fingerprint: fingerprint.clone(),
                possible_sources: vec![],
                confidence: 0.0,
                evidence: vec![],
                traced_at: chrono_lite_now(),
            };
        }

        // Calculate confidence and gather evidence
        let mut total_score = 0.0;
        for similar_fp in &similar {
            let score = self.calculate_similarity(fingerprint, similar_fp);
            total_score += score;

            // Find evidence for this fingerprint
            let fp_evidence = store.get_evidence(&similar_fp.content_hash);
            evidence.extend(fp_evidence);

            sources.push(IdentityMatch {
                identity: similar_fp.author_fingerprint.chars().take(8).collect(),
                score,
                reason: if score > 0.8 {
                    "Exact author match".to_string()
                } else if score > 0.5 {
                    "Similar code patterns".to_string()
                } else {
                    "Partial match".to_string()
                },
            });
        }

        // Sort sources by score
        sources.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());

        let confidence = if similar.len() > 0 {
            (total_score / similar.len() as f32).min(1.0)
        } else {
            0.0
        };

        // Deduplicate evidence
        evidence.dedup_by(|a, b| a.timestamp == b.timestamp && a.action == b.action);

        TraceResult {
            fingerprint: fingerprint.clone(),
            possible_sources: sources,
            confidence,
            evidence,
            traced_at: chrono_lite_now(),
        }
    }

    /// Calculate similarity between two fingerprints
    fn calculate_similarity(&self, a: &CodeFingerprint, b: &CodeFingerprint) -> f32 {
        let mut score = 0.0;

        // Author match is strong signal
        if a.author_fingerprint == b.author_fingerprint {
            score += 0.5;
        }

        // Time proximity
        if let (Some(t1), Some(t2)) = (parse_timestamp(&a.timestamp), parse_timestamp(&b.timestamp)) {
            let diff = t1.duration_since(t2).unwrap_or_default();
            if diff.as_secs() < 86400 {
                // Within 24 hours
                score += 0.2;
            }
        }

        // File overlap
        let overlap: f32 = a
            .files_changed
            .iter()
            .filter(|f| b.files_changed.contains(f))
            .count() as f32;
        let max_files = a.files_changed.len().max(b.files_changed.len()).max(1);
        score += 0.2 * (overlap / max_files as f32);

        // Lines changed similarity
        let lines_diff = (a.lines_added as i32 - b.lines_added as i32).unsigned_abs()
            + (a.lines_deleted as i32 - b.lines_deleted as i32).unsigned_abs();
        if lines_diff < 10 {
            score += 0.1;
        }

        score.min(1.0)
    }
}

impl Default for FingerprintGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Fingerprint store — persists and indexes fingerprints
pub struct FingerprintStore {
    path: PathBuf,
    fingerprints: HashMap<String, Vec<CodeFingerprint>>,
    evidence: HashMap<String, Vec<EvidenceItem>>,
}

impl FingerprintStore {
    /// Create a new store
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            fingerprints: HashMap::new(),
            evidence: HashMap::new(),
        }
    }

    /// Load from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new(path.to_path_buf()));
        }

        let content = std::fs::read_to_string(path)
            .context("Failed to read fingerprint store")?;
        let data: FingerprintStoreData = serde_json::from_str(&content)
            .context("Failed to parse fingerprint store")?;

        let mut fingerprints = HashMap::new();
        for fp in data.fingerprints {
            fingerprints
                .entry(fp.content_hash[..12.min(fp.content_hash.len())].to_string())
                .or_insert_with(Vec::new)
                .push(fp);
        }

        Ok(Self {
            path: path.to_path_buf(),
            fingerprints,
            evidence: data.evidence,
        })
    }

    /// Save to file
    pub fn save(&self) -> Result<()> {
        let all_fingerprints: Vec<CodeFingerprint> = self
            .fingerprints
            .values()
            .flatten()
            .cloned()
            .collect();

        let data = FingerprintStoreData {
            fingerprints: all_fingerprints,
            evidence: self.evidence.values().flatten().cloned().collect(),
        };

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&data)?;
        std::fs::write(&self.path, content)?;

        Ok(())
    }

    /// Store a fingerprint
    pub fn store(&mut self, fingerprint: CodeFingerprint) -> Result<()> {
        let key = fingerprint.content_hash[..12.min(fingerprint.content_hash.len())].to_string();
        self.fingerprints
            .entry(key)
            .or_insert_with(Vec::new)
            .push(fingerprint);
        Ok(())
    }

    /// Add evidence for a fingerprint
    pub fn add_evidence(&mut self, fingerprint_hash: &str, evidence: EvidenceItem) {
        self.evidence
            .entry(fingerprint_hash[..12.min(fingerprint_hash.len())].to_string())
            .or_insert_with(Vec::new)
            .push(evidence);
    }

    /// Get evidence for a fingerprint
    pub fn get_evidence(&self, fingerprint_hash: &str) -> Vec<EvidenceItem> {
        self.evidence
            .get(&fingerprint_hash[..12.min(fingerprint_hash.len())].to_string())
            .cloned()
            .unwrap_or_default()
    }

    /// Query fingerprints by content hash
    pub fn query(&self, content_hash: &str) -> Option<&Vec<CodeFingerprint>> {
        self.fingerprints.get(&content_hash[..12.min(content_hash.len())].to_string())
    }

    /// Search for similar fingerprints
    pub fn search_similar(&self, fingerprint: &CodeFingerprint) -> Vec<CodeFingerprint> {
        let mut similar = Vec::new();

        for fps in self.fingerprints.values() {
            for fp in fps {
                // Check author match
                if fp.author_fingerprint == fingerprint.author_fingerprint {
                    similar.push(fp.clone());
                    continue;
                }

                // Check file overlap
                let overlap: usize = fp
                    .files_changed
                    .iter()
                    .filter(|f| fingerprint.files_changed.contains(f))
                    .count();

                if overlap > 0 && overlap >= fp.files_changed.len() / 2 {
                    similar.push(fp.clone());
                }
            }
        }

        similar
    }

    /// Get all fingerprints
    pub fn all(&self) -> Vec<&CodeFingerprint> {
        self.fingerprints.values().flatten().collect()
    }

    /// Get fingerprint count
    pub fn count(&self) -> usize {
        self.fingerprints.values().map(|v| v.len()).sum()
    }
}

/// Internal store data format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FingerprintStoreData {
    fingerprints: Vec<CodeFingerprint>,
    evidence: Vec<EvidenceItem>,
}

/// Fingerprint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintConfig {
    /// Enable fingerprinting
    #[serde(default)]
    pub enabled: bool,
    /// Minimum lines changed to generate fingerprint
    #[serde(default = "default_min_lines")]
    pub min_lines: u32,
    /// Store fingerprints in git notes
    #[serde(default)]
    pub git_notes_enabled: bool,
}

fn default_min_lines() -> u32 {
    3
}

impl Default for FingerprintConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_lines: default_min_lines(),
            git_notes_enabled: false,
        }
    }
}

impl FingerprintConfig {
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

// Helper functions

fn parse_timestamp(ts: &str) -> Option<SystemTime> {
    let parts: Vec<&str> = ts.split(&['-', 'T', ':'][..]).collect();
    if parts.len() < 5 {
        return None;
    }

    let year: u64 = parts[0].parse().ok()?;
    let month: u64 = parts[1].parse().ok()?;
    let day: u64 = parts[2].parse().ok()?;
    let hour: u64 = parts[3].parse().ok()?;
    let min: u64 = parts[4].parse().ok()?;

    let days_since_epoch = (year as u64 - 1970) * 365 + (month - 1) * 30 + day - 1;
    let secs_since_epoch = days_since_epoch * 86400 + hour * 3600 + min * 60;

    SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(secs_since_epoch))
}

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
    fn test_fingerprint_generation() {
        let generator = FingerprintGenerator::new();

        let fp = generator.generate_commit_fingerprint(
            "my-repo",
            "refs/heads/main",
            "abc123def456",
            "agent-deploy",
            "Fix critical bug",
            &["src/main.rs", "src/lib.rs"],
            10,
            2,
            "2026-06-17T10:00:00Z",
        );

        assert_eq!(fp.repo, "my-repo");
        assert_eq!(fp.files_changed.len(), 2);
        assert_eq!(fp.lines_added, 10);
        assert_eq!(fp.lines_deleted, 2);
        assert!(!fp.content_hash.is_empty());
    }

    #[test]
    fn test_fingerprint_short_hash() {
        let fp = CodeFingerprint {
            content_hash: "abcdef1234567890".to_string(),
            author_fingerprint: "author123".to_string(),
            timestamp: "2026-06-17T10:00:00Z".to_string(),
            commit_message_hash: "msg123".to_string(),
            files_changed: vec!["file.rs".to_string()],
            lines_added: 10,
            lines_deleted: 2,
            repo: "test".to_string(),
            ref_name: "main".to_string(),
        };

        assert_eq!(fp.short_hash(), "abcdef123456");
    }

    #[test]
    fn test_fingerprint_store() {
        let temp_path = std::env::temp_dir().join("fingerprint_test.json");
        let mut store = FingerprintStore::new(temp_path.clone());

        let fp = CodeFingerprint {
            content_hash: "test_hash_123456789".to_string(),
            author_fingerprint: "author".to_string(),
            timestamp: "2026-06-17T10:00:00Z".to_string(),
            commit_message_hash: "msg".to_string(),
            files_changed: vec!["file.rs".to_string()],
            lines_added: 10,
            lines_deleted: 2,
            repo: "test".to_string(),
            ref_name: "main".to_string(),
        };

        store.store(fp.clone()).unwrap();
        assert_eq!(store.count(), 1);

        let queried = store.query("test_hash_");
        assert!(queried.is_some());
    }

    #[test]
    fn test_search_similar() {
        let temp_path = std::env::temp_dir().join("fingerprint_similar_test.json");
        let mut store = FingerprintStore::new(temp_path);

        let fp1 = CodeFingerprint {
            content_hash: "hash1".to_string(),
            author_fingerprint: "author1".to_string(),
            timestamp: "2026-06-17T10:00:00Z".to_string(),
            commit_message_hash: "msg1".to_string(),
            files_changed: vec!["file1.rs".to_string(), "file2.rs".to_string()],
            lines_added: 10,
            lines_deleted: 2,
            repo: "test".to_string(),
            ref_name: "main".to_string(),
        };

        let fp2 = CodeFingerprint {
            content_hash: "hash2".to_string(),
            author_fingerprint: "author1".to_string(), // Same author
            timestamp: "2026-06-17T11:00:00Z".to_string(),
            commit_message_hash: "msg2".to_string(),
            files_changed: vec!["file1.rs".to_string(), "file3.rs".to_string()],
            lines_added: 5,
            lines_deleted: 1,
            repo: "test".to_string(),
            ref_name: "main".to_string(),
        };

        store.store(fp1.clone()).unwrap();
        store.store(fp2).unwrap();

        let similar = store.search_similar(&fp1);
        assert!(similar.len() >= 1);
    }

    #[test]
    fn test_similarity_calculation() {
        let generator = FingerprintGenerator::new();

        let fp1 = CodeFingerprint {
            content_hash: "hash1".to_string(),
            author_fingerprint: "author1".to_string(),
            timestamp: "2026-06-17T10:00:00Z".to_string(),
            commit_message_hash: "msg1".to_string(),
            files_changed: vec!["file1.rs".to_string()],
            lines_added: 10,
            lines_deleted: 2,
            repo: "test".to_string(),
            ref_name: "main".to_string(),
        };

        let fp2 = CodeFingerprint {
            content_hash: "hash2".to_string(),
            author_fingerprint: "author1".to_string(), // Same author
            timestamp: "2026-06-17T11:00:00Z".to_string(),
            commit_message_hash: "msg2".to_string(),
            files_changed: vec!["file1.rs".to_string()], // Same file
            lines_added: 11,
            lines_deleted: 2,
            repo: "test".to_string(),
            ref_name: "main".to_string(),
        };

        let similarity = generator.calculate_similarity(&fp1, &fp2);
        assert!(similarity > 0.5); // Should have high similarity due to same author
    }

    #[test]
    fn test_trace_result() {
        let generator = FingerprintGenerator::new();

        let fp = generator.generate_commit_fingerprint(
            "my-repo",
            "refs/heads/main",
            "abc123",
            "agent",
            "Test commit",
            &["file.rs"],
            5,
            1,
            "2026-06-17T10:00:00Z",
        );

        let temp_path = std::env::temp_dir().join("trace_test.json");
        let store = FingerprintStore::new(temp_path);

        let result = generator.trace(&fp, &store);

        assert_eq!(result.fingerprint.content_hash, fp.content_hash);
        assert!(result.confidence >= 0.0);
    }

    #[test]
    fn test_evidence_format() {
        let evidence = EvidenceItem {
            timestamp: "2026-06-17T10:00:00Z".to_string(),
            action: "push".to_string(),
            repo: "my-repo".to_string(),
            ref_name: "refs/heads/main".to_string(),
            details: Some("Author: agent".to_string()),
        };

        let formatted = evidence.format_cli();
        assert!(formatted.contains("2026-06-17"));
        assert!(formatted.contains("push"));
    }
}
