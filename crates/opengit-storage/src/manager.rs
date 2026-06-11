//! Storage Manager — CRUD for bare repositories

use anyhow::{Context, Result};
use opengit_core::repository::Repository;
use std::path::{Path, PathBuf};

/// Manages repository storage on the filesystem
pub struct StorageManager {
    /// Root directory for all repositories
    root: PathBuf,
}

impl StorageManager {
    pub fn new(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)
            .with_context(|| format!("Failed to create repos dir: {}", root.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
        })
    }

    /// Get the path for a named repository
    pub fn repo_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("{}.git", name))
    }

    /// Create a new bare repository
    pub fn create_repo(&self, name: &str) -> Result<Repository> {
        Repository::create(&self.root, name)
    }

    /// Open an existing repository
    pub fn open_repo(&self, name: &str) -> Result<Repository> {
        let path = self.repo_path(name);
        Repository::open(&path)
    }

    /// List all repositories
    pub fn list_repos(&self) -> Result<Vec<Repository>> {
        Repository::scan_dir(&self.root)
    }

    /// Check if a repository exists
    pub fn repo_exists(&self, name: &str) -> bool {
        self.repo_path(name).join("HEAD").exists()
    }

    /// Delete a repository (with safety check!)
    pub fn delete_repo(&self, name: &str) -> Result<()> {
        let path = self.repo_path(name);
        if !path.exists() {
            anyhow::bail!("Repository not found: {}", name);
        }
        // Safety: move to trash instead of rm
        let trash = self.root.join(".trash");
        std::fs::create_dir_all(&trash)?;
        let timestamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let trash_path = trash.join(format!("{}-{}", name, timestamp));
        std::fs::rename(&path, &trash_path)
            .with_context(|| format!("Failed to move repo to trash: {}", name))?;
        Ok(())
    }
}
