//! Hook Plugin System — Extensible pre/post-receive hooks
//!
//! P4: Trait-based plugin framework for custom Git hook logic.
//! Built-in plugins: BranchProtection, PushLimit.
//!
//! Plugins are configured in config/plugins.toml and loaded at startup.

use crate::audit::AuditLog;
use crate::hook::{HookContext, HookType, RefUpdate};
use crate::policy::Permission;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A hook plugin that can intercept and evaluate Git operations.
///
/// Implement this trait to add custom enforcement logic
/// beyond the built-in policy engine.
pub trait HookPlugin: Send + Sync {
    /// Plugin name (for logging and config)
    fn name(&self) -> &str;

    /// Evaluate a pre-receive hook.
    /// Return None to allow, Some(reason) to deny.
    fn pre_receive(&self, ctx: &HookContext, updates: &[RefUpdate]) -> Option<String> {
        let _ = (ctx, updates);
        None
    }

    /// Evaluate a single ref update (update hook).
    /// Return None to allow, Some(reason) to deny.
    fn update(&self, ctx: &HookContext, update: &RefUpdate) -> Option<String> {
        let _ = (ctx, update);
        None
    }

    /// Post-receive notification (cannot deny).
    fn post_receive(&self, ctx: &HookContext, updates: &[RefUpdate]) {
        let _ = (ctx, updates);
    }
}

/// Plugin configuration from TOML
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Plugin name
    pub name: String,
    /// Whether the plugin is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Plugin-specific settings
    #[serde(default)]
    pub settings: HashMap<String, toml::Value>,
}

fn default_true() -> bool {
    true
}

/// Plugin configuration file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginsFile {
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
}

impl PluginsFile {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self {
                plugins: Vec::new(),
            });
        }
        let content = std::fs::read_to_string(path)?;
        let config: PluginsFile = toml::from_str(&content)?;
        Ok(config)
    }
}

// ─── Built-in Plugins ──────────────────────────────────────────

/// Branch Protection Plugin — Enforce protection rules on specific branches
///
/// Settings:
///   protected_branches = ["master", "main", "release/*"]
///   allow_force_push = false
///   allow_delete = false
pub struct BranchProtectionPlugin {
    protected_branches: Vec<String>,
    allow_force_push: bool,
    allow_delete: bool,
}

impl BranchProtectionPlugin {
    pub fn from_settings(settings: &HashMap<String, toml::Value>) -> Self {
        let protected_branches = settings
            .get("protected_branches")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["master".into(), "main".into()]);

        let allow_force_push = settings
            .get("allow_force_push")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let allow_delete = settings
            .get("allow_delete")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        Self {
            protected_branches,
            allow_force_push,
            allow_delete,
        }
    }

    fn is_protected(&self, ref_name: &str) -> bool {
        let branch_name = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);

        self.protected_branches.iter().any(|pattern| {
            if pattern.ends_with("/*") {
                let prefix = &pattern[..pattern.len() - 2];
                branch_name.starts_with(prefix)
            } else {
                branch_name == pattern
            }
        })
    }
}

impl HookPlugin for BranchProtectionPlugin {
    fn name(&self) -> &str {
        "branch-protection"
    }

    fn pre_receive(&self, _ctx: &HookContext, updates: &[RefUpdate]) -> Option<String> {
        let zero_sha = "0000000000000000000000000000000000000000";

        for update in updates {
            if self.is_protected(&update.ref_name) {
                // Check for delete
                if update.new_sha == zero_sha && !self.allow_delete {
                    return Some(format!(
                        "branch-protection: deleting protected branch '{}' is forbidden",
                        update.ref_name
                    ));
                }

                // Check for force push (non-zero old sha that differs)
                if update.old_sha != zero_sha
                    && update.old_sha != update.new_sha
                    && !self.allow_force_push
                {
                    return Some(format!(
                        "branch-protection: force-pushing to protected branch '{}' is forbidden",
                        update.ref_name
                    ));
                }
            }
        }

        None
    }
}

/// Push Limit Plugin — Enforce maximum push size
///
/// Settings:
///   max_file_size_mb = 100
///   max_total_size_mb = 500
pub struct PushLimitPlugin {
    max_file_size_mb: u64,
    max_total_size_mb: u64,
}

impl PushLimitPlugin {
    pub fn from_settings(settings: &HashMap<String, toml::Value>) -> Self {
        let max_file_size_mb = settings
            .get("max_file_size_mb")
            .and_then(|v| v.as_integer())
            .unwrap_or(100) as u64;

        let max_total_size_mb = settings
            .get("max_total_size_mb")
            .and_then(|v| v.as_integer())
            .unwrap_or(500) as u64;

        Self {
            max_file_size_mb,
            max_total_size_mb,
        }
    }
}

impl HookPlugin for PushLimitPlugin {
    fn name(&self) -> &str {
        "push-limit"
    }

    fn pre_receive(&self, ctx: &HookContext, _updates: &[RefUpdate]) -> Option<String> {
        // Check repo size against limits
        // This is a simplified check — full implementation would
        // inspect pack data for individual file sizes
        let repo_path = ctx.env.get("OPENGIT_REPO_PATH").unwrap_or(&".".to_string());
        let repo_total = get_dir_size_mb(repo_path).unwrap_or(0);

        if repo_total > self.max_total_size_mb {
            return Some(format!(
                "push-limit: repository size ({repo_total}MB) exceeds limit ({}MB)",
                self.max_total_size_mb
            ));
        }

        None
    }
}

/// Calculate directory size in MB (simplified)
fn get_dir_size_mb(path: &str) -> Option<u64> {
    let output = std::process::Command::new("du")
        .args(["-sm", path])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.split_whitespace().next()?.parse().ok()
}

/// Plugin manager — loads and runs all configured plugins
pub struct PluginManager {
    plugins: Vec<Box<dyn HookPlugin>>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Vec::new(),
        }
    }

    /// Load plugins from configuration
    pub fn load_from_config(config: &PluginsFile) -> Self {
        let mut manager = Self::new();

        for plugin_config in &config.plugins {
            if !plugin_config.enabled {
                continue;
            }

            match plugin_config.name.as_str() {
                "branch-protection" => {
                    let plugin = BranchProtectionPlugin::from_settings(&plugin_config.settings);
                    manager.plugins.push(Box::new(plugin));
                    tracing::info!("Loaded plugin: branch-protection");
                }
                "push-limit" => {
                    let plugin = PushLimitPlugin::from_settings(&plugin_config.settings);
                    manager.plugins.push(Box::new(plugin));
                    tracing::info!("Loaded plugin: push-limit");
                }
                _ => {
                    tracing::warn!("Unknown plugin: {}", plugin_config.name);
                }
            }
        }

        manager
    }

    /// Run all plugins for pre-receive hook
    /// Returns the first denial reason, or None if all allow
    pub fn run_pre_receive(&self, ctx: &HookContext, updates: &[RefUpdate]) -> Option<String> {
        for plugin in &self.plugins {
            if let Some(reason) = plugin.pre_receive(ctx, updates) {
                tracing::warn!("Plugin '{}' denied: {reason}", plugin.name());
                return Some(reason);
            }
        }
        None
    }

    /// Run all plugins for update hook
    pub fn run_update(&self, ctx: &HookContext, update: &RefUpdate) -> Option<String> {
        for plugin in &self.plugins {
            if let Some(reason) = plugin.update(ctx, update) {
                tracing::warn!("Plugin '{}' denied: {reason}", plugin.name());
                return Some(reason);
            }
        }
        None
    }

    /// Run all plugins for post-receive hook
    pub fn run_post_receive(&self, ctx: &HookContext, updates: &[RefUpdate]) {
        for plugin in &self.plugins {
            plugin.post_receive(ctx, updates);
        }
    }

    /// List loaded plugin names
    pub fn plugin_names(&self) -> Vec<&str> {
        self.plugins.iter().map(|p| p.name()).collect()
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_protection_protected() {
        let plugin = BranchProtectionPlugin {
            protected_branches: vec!["master".into(), "release/*".into()],
            allow_force_push: false,
            allow_delete: false,
        };

        let ctx = HookContext {
            repo: "test".into(),
            identity: "agent-deploy".into(),
            hook_type: HookType::PreReceive,
            env: Default::default(),
        };

        // Delete protected branch → deny
        let updates = vec![RefUpdate {
            ref_name: "refs/heads/master".into(),
            old_sha: "abc123".into(),
            new_sha: "0000000000000000000000000000000000000000".into(),
        }];
        assert!(plugin.pre_receive(&ctx, &updates).is_some());

        // Push to protected branch → allow
        let updates = vec![RefUpdate {
            ref_name: "refs/heads/master".into(),
            old_sha: "abc123".into(),
            new_sha: "def456".into(),
        }];
        assert!(plugin.pre_receive(&ctx, &updates).is_none());

        // Push to unprotected branch → allow
        let updates = vec![RefUpdate {
            ref_name: "refs/heads/feature".into(),
            old_sha: "abc123".into(),
            new_sha: "def456".into(),
        }];
        assert!(plugin.pre_receive(&ctx, &updates).is_none());

        // Wildcard pattern match
        let updates = vec![RefUpdate {
            ref_name: "refs/heads/release/v1".into(),
            old_sha: "abc123".into(),
            new_sha: "0000000000000000000000000000000000000000".into(),
        }];
        assert!(plugin.pre_receive(&ctx, &updates).is_some());
    }

    #[test]
    fn test_plugin_manager_load() {
        let config = PluginsFile {
            plugins: vec![PluginConfig {
                name: "branch-protection".into(),
                enabled: true,
                settings: HashMap::new(),
            }],
        };

        let manager = PluginManager::load_from_config(&config);
        assert_eq!(manager.plugin_names(), vec!["branch-protection"]);
    }

    #[test]
    fn test_plugin_disabled() {
        let config = PluginsFile {
            plugins: vec![PluginConfig {
                name: "branch-protection".into(),
                enabled: false,
                settings: HashMap::new(),
            }],
        };

        let manager = PluginManager::load_from_config(&config);
        assert!(manager.plugin_names().is_empty());
    }
}
