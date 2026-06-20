//! Server configuration
//!
//! P4: Added SSH and plugin configuration.
//! P5: Added mirror configuration.
//! P8.2: Added email notification configuration.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Directory containing bare repositories
    pub repos_dir: PathBuf,
    /// HTTP bind address (e.g., "0.0.0.0:9418")
    pub bind: String,
    /// SSH bind address (empty = SSH disabled)
    #[serde(default)]
    pub ssh_bind: String,
    /// Host key for SSH
    #[serde(default = "default_ssh_host_key")]
    pub ssh_host_key: PathBuf,
    /// Policy file path
    pub policy_file: PathBuf,
    /// Identity file path
    pub identity_file: PathBuf,
    /// Audit log file path
    pub audit_file: PathBuf,
    /// Webhook config file path
    #[serde(default = "default_webhook_file")]
    pub webhook_file: PathBuf,
    /// Plugin config file path
    #[serde(default = "default_plugin_file")]
    pub plugin_file: PathBuf,
    /// Mirror config file path
    #[serde(default = "default_mirror_file")]
    pub mirror_file: PathBuf,

    /// Rate limit config file path
    #[serde(default = "default_rate_limit_file")]
    pub rate_limit_file: PathBuf,
    /// Email notification config file path (P8.2)
    #[serde(default = "default_email_file")]
    pub email_file: PathBuf,
}

fn default_rate_limit_file() -> PathBuf {
    PathBuf::from("config/rate-limit.toml")
}

fn default_ssh_host_key() -> PathBuf {
    PathBuf::from("config/ssh_host_key")
}

fn default_webhook_file() -> PathBuf {
    PathBuf::from("config/webhooks.yaml")
}

fn default_plugin_file() -> PathBuf {
    PathBuf::from("config/plugins.toml")
}

fn default_mirror_file() -> PathBuf {
    PathBuf::from("config/mirrors.toml")
}

fn default_email_file() -> PathBuf {
    PathBuf::from("config/email.toml")
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
            ssh_bind: String::new(),
            ssh_host_key: PathBuf::from("config/ssh_host_key"),
            policy_file: PathBuf::from("config/policies.yaml"),
            identity_file: PathBuf::from("config/identities.yaml"),
            audit_file: PathBuf::from("data/audit.json"),
            webhook_file: PathBuf::from("config/webhooks.yaml"),
            plugin_file: PathBuf::from("config/plugins.toml"),
            mirror_file: PathBuf::from("config/mirrors.toml"),
            rate_limit_file: PathBuf::from("config/rate-limit.toml"),
            email_file: PathBuf::from("config/email.toml"),
        }
    }
}
