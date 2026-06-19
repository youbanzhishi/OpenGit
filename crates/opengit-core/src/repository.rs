//! Repository — Bare repo management with zero-migration compatibility
//!
//! OpenGit reads existing Git bare repos directly. No import, no conversion.
//! Just point OpenGit at your repos directory and it works.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A Git repository managed by OpenGit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Repository {
    /// Repository name (e.g., "OpenDAW")
    pub name: String,
    /// File system path to the bare repo
    pub path: PathBuf,
    /// Whether this is a bare repo
    pub bare: bool,
    /// Description
    pub description: Option<String>,
    /// Whether the repo is mirrored from another remote
    pub mirror: bool,
    /// Group ID for classification (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// Tags for additional metadata
    #[serde(default)]
    pub tags: Vec<String>,
}

impl Repository {
    /// Open an existing bare repository
    pub fn open(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()
            .trim_end_matches(".git")
            .to_string();

        // Verify it's a valid git repo
        let head = path.join("HEAD");
        if !head.exists() {
            anyhow::bail!("Not a Git repository: {}", path.display());
        }

        let bare = path.join("config").exists(); // bare repos have config at top level

        Ok(Self {
            name,
            path: path.to_path_buf(),
            bare,
            description: None,
            mirror: false,
            group_id: None,
            tags: Vec::new(),
        })
    }

    /// Create a new bare repository
    pub fn create(path: &Path, name: &str) -> Result<Self> {
        let repo_path = path.join(format!("{}.git", name));
        std::fs::create_dir_all(&repo_path)
            .with_context(|| format!("Failed to create repo directory: {}", repo_path.display()))?;

        // Initialize bare repo with git2
        git2::Repository::init_bare(&repo_path)
            .with_context(|| format!("Failed to init bare repo: {}", repo_path.display()))?;

        let mut repo = Self::open(&repo_path)?;
        repo.description = Some(format!("Created at {}", chrono::Utc::now().to_rfc3339()));
        Ok(repo)
    }

    /// Scan a directory for bare repositories
    pub fn scan_dir(dir: &Path) -> Result<Vec<Self>> {
        let mut repos = Vec::new();
        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.join("HEAD").exists() {
                if let Ok(repo) = Self::open(&path) {
                    repos.push(repo);
                }
            }
        }

        Ok(repos)
    }

    /// Get the refs in this repository
    pub fn refs(&self) -> Result<Vec<RefInfo>> {
        let repo = git2::Repository::open(&self.path)
            .with_context(|| format!("Failed to open repo: {}", self.path.display()))?;

        let mut refs = Vec::new();
        for reference in repo.references()? {
            let reference = reference?;
            let name = reference.name().unwrap_or("").to_string();
            let kind = if name.starts_with("refs/heads/") {
                RefKind::Branch
            } else if name.starts_with("refs/tags/") {
                RefKind::Tag
            } else {
                RefKind::Other
            };

            let sha = reference
                .peel_to_commit()
                .map(|c| c.id().to_string())
                .unwrap_or_else(|_| "unknown".into());

            refs.push(RefInfo { name, sha, kind });
        }

        Ok(refs)
    }

    /// Check if a commit is an ancestor of another (for force push detection)
    pub fn is_ancestor(&self, ancestor: &str, descendant: &str) -> Result<bool> {
        let repo = git2::Repository::open(&self.path)?;
        let ancestor_oid = git2::Oid::from_str(ancestor)?;
        let descendant_oid = git2::Oid::from_str(descendant)?;

        let mut revwalk = repo.revwalk()?;
        revwalk.push(descendant_oid)?;

        Ok(revwalk.any(|oid| match oid {
            Ok(o) => o == ancestor_oid,
            Err(_) => false,
        }))
    }

    /// Get reflog entries for a ref
    pub fn reflog(&self, ref_name: &str) -> Result<Vec<ReflogEntry>> {
        let repo = git2::Repository::open(&self.path)?;
        let refname = if ref_name.starts_with("refs/") {
            ref_name.to_string()
        } else {
            format!("refs/heads/{}", ref_name)
        };

        let mut entries = Vec::new();
        if let Ok(reflog) = repo.reflog(&refname) {
            for entry in reflog.iter() {
                entries.push(ReflogEntry {
                    old_sha: entry.id_old().to_string(),
                    new_sha: entry.id_new().to_string(),
                    message: entry.message().map(|m| m.to_string()),
                });
            }
        }

        Ok(entries)
    }

    /// Get repository disk size
    pub fn size_bytes(&self) -> Result<u64> {
        let mut total = 0u64;
        fn walk_dir(path: &Path, total: &mut u64) {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_dir() {
                        walk_dir(&p, total);
                    } else if let Ok(meta) = p.metadata() {
                        *total += meta.len();
                    }
                }
            }
        }
        walk_dir(&self.path, &mut total);
        Ok(total)
    }
}

/// Information about a ref (branch/tag)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefInfo {
    pub name: String,
    pub sha: String,
    pub kind: RefKind,
}

/// Kind of ref
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RefKind {
    Branch,
    Tag,
    Other,
}

/// A reflog entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReflogEntry {
    pub old_sha: String,
    pub new_sha: String,
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_create_and_open_repo() {
        let dir = std::env::temp_dir().join("opengit_test_create");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let repo = Repository::create(&dir, "test-repo").unwrap();
        assert_eq!(repo.name, "test-repo");
        assert!(repo.bare);

        // Open it again
        let repo2 = Repository::open(&repo.path).unwrap();
        assert_eq!(repo2.name, "test-repo");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_scan_dir() {
        let dir = std::env::temp_dir().join("opengit_test_scan");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        Repository::create(&dir, "repo1").unwrap();
        Repository::create(&dir, "repo2").unwrap();

        let repos = Repository::scan_dir(&dir).unwrap();
        assert_eq!(repos.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }
}
