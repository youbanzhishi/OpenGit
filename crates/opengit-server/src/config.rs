//! Server configuration

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Directory containing bare repositories
    pub repos_dir: PathBuf,
    /// Bind address (e.g., "0.0.0.0:9418")
    pub bind: String,
    /// Policy file path
    pub policy_file: PathBuf,
    /// Identity file path
    pub identity_file: PathBuf,
    /// Audit log file path
    pub audit_file: PathBuf,
}

impl ServerConfig {
    pub fn load(cli: &crate::Cli) -> Result<Self> {
        let mut config = if cli.config.exists() {
            let content = std::fs::read_to_string(&cli.config)
                .with_context(|| format!("Failed to read config: {}", cli.config.display()))?;
            toml::from_str(&content).with_context(|| "Failed to parse config")?
        } else {
            Self::default_config()
        };

        // CLI overrides
        if let Some(repos_dir) = &cli.repos_dir {
            config.repos_dir = repos_dir.clone();
        }
        if let Some(bind) = &cli.bind {
            config.bind = bind.clone();
        }
        if let Some(policy) = &cli.policy {
            config.policy_file = policy.clone();
        }

        // Ensure repos directory exists
        std::fs::create_dir_all(&config.repos_dir)?;

        Ok(config)
    }

    fn default_config() -> Self {
        Self {
            repos_dir: PathBuf::from("./repos"),
            bind: "0.0.0.0:9418".into(),
            policy_file: PathBuf::from("config/policies.yaml"),
            identity_file: PathBuf::from("config/identities.yaml"),
            audit_file: PathBuf::from("data/audit.json"),
        }
    }
}
