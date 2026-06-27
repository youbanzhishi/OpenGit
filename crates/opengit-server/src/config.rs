//! Server configuration — loaded from TOML file with CLI overrides.

use anyhow::Result;
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Server configuration.
///
/// All file paths are resolved relative to the config file's directory
/// when loaded from a file; CLI overrides use absolute paths as-is.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// HTTP bind address, e.g. "0.0.0.0:8080"
    pub bind: String,
    /// SSH bind address, e.g. "0.0.0.0:2222"
    #[serde(default)]
    pub ssh_bind: String,
    /// Repository storage directory
    pub repos_dir: PathBuf,
    /// Policy file path (YAML)
    pub policy_file: PathBuf,
    /// Identity store file path (YAML)
    pub identity_file: PathBuf,
    /// Webhook configuration file path (YAML)
    pub webhook_file: PathBuf,
    /// Audit log file path
    pub audit_file: PathBuf,
    /// Mirror configuration file path (TOML)
    pub mirror_file: PathBuf,
    /// Plugin configuration file path (TOML)
    pub plugin_file: PathBuf,
    /// Rate limit configuration file path (TOML)
    pub rate_limit_file: PathBuf,
    /// Email notification configuration file path (TOML)
    pub email_file: PathBuf,
    /// Groups configuration file path (YAML)
    pub group_file: PathBuf,
    /// Group membership file path (YAML)
    pub group_membership_file: PathBuf,
}

impl ServerConfig {
    /// Load configuration from CLI arguments.
    pub fn load(cli: &crate::Cli) -> Result<Self> {
        let config_path = &cli.config;

        let mut config = if config_path.exists() {
            let content = std::fs::read_to_string(config_path)?;
            let mut cfg: ServerConfig = toml::from_str(&content)?;
            if let Some(parent) = config_path.parent() {
                cfg.resolve_paths(parent);
            }
            cfg
        } else {
            Self::default_paths()
        };

        if let Some(repos_dir) = &cli.repos_dir {
            config.repos_dir = repos_dir.clone();
        }
        if let Some(bind) = &cli.bind {
            config.bind = bind.clone();
        }
        if let Some(policy) = &cli.policy {
            config.policy_file = policy.clone();
        }

        Ok(config)
    }

    fn default_paths() -> Self {
        Self {
            bind: "0.0.0.0:8080".to_string(),
            ssh_bind: String::new(),
            repos_dir: PathBuf::from("repos"),
            policy_file: PathBuf::from("config/policy.yaml"),
            identity_file: PathBuf::from("config/identities.yaml"),
            webhook_file: PathBuf::from("config/webhooks.yaml"),
            audit_file: PathBuf::from("config/audit.log"),
            mirror_file: PathBuf::from("config/mirrors.toml"),
            plugin_file: PathBuf::from("config/plugins.toml"),
            rate_limit_file: PathBuf::from("config/rate-limit.toml"),
            email_file: PathBuf::from("config/email.toml"),
            group_file: PathBuf::from("config/groups.yaml"),
            group_membership_file: PathBuf::from("config/group-membership.yaml"),
        }
    }

    fn resolve_paths(&mut self, base: &Path) {
        fn resolve(base: &Path, p: &mut PathBuf) {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        resolve(base, &mut self.repos_dir);
        resolve(base, &mut self.policy_file);
        resolve(base, &mut self.identity_file);
        resolve(base, &mut self.webhook_file);
        resolve(base, &mut self.audit_file);
        resolve(base, &mut self.mirror_file);
        resolve(base, &mut self.plugin_file);
        resolve(base, &mut self.rate_limit_file);
        resolve(base, &mut self.email_file);
        resolve(base, &mut self.group_file);
        resolve(base, &mut self.group_membership_file);
    }
}
