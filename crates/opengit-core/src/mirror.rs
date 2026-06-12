//! Repository Mirror System
//!
//! P5: Automatic push-based mirroring to remote Git hosts.
//! On post-receive, mirrors push refs to configured remote URLs.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Mirror target configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorTarget {
    /// Friendly name for this mirror
    pub name: String,
    /// Remote URL to push to (e.g., "git@github.com:user/repo.git")
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
            }],
        };
        let toml_str = toml::to_string_pretty(&mirrors).unwrap();
        let parsed: MirrorsFile = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.mirrors.len(), 1);
        assert_eq!(parsed.mirrors[0].name, "github");
    }
}
