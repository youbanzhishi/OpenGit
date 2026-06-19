//! Mirror Alert & Notification System
//!
//! P5.2: Alert channels for mirror operations - Webhook, Email, Feishu
//!
//! Alert flow:
//! 1. Mirror push fails → create MirrorAlert
//! 2. AlertDispatcher routes to enabled channels
//! 3. Each channel sends notification
//! 4. Audit log records all alerts

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::process::Command;
use tracing::{error, info, warn};

use crate::mirror::{MirrorError, MirrorPushResult, MirrorSeverity};

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable webhook alerts
    #[serde(default)]
    pub webhook_enabled: bool,
    /// Webhook URL (POST JSON)
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Webhook secret for HMAC signature
    #[serde(default)]
    pub webhook_secret: Option<String>,

    /// Enable email alerts
    #[serde(default)]
    pub email_enabled: bool,
    /// SMTP server
    #[serde(default)]
    pub smtp_server: Option<String>,
    /// SMTP port
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    /// SMTP username
    #[serde(default)]
    pub smtp_username: Option<String>,
    /// SMTP password
    #[serde(default)]
    pub smtp_password: Option<String>,
    /// From address
    #[serde(default)]
    pub email_from: Option<String>,
    /// To addresses (comma-separated)
    #[serde(default)]
    pub email_to: Vec<String>,

    /// Enable Feishu alerts
    #[serde(default)]
    pub feishu_enabled: bool,
    /// Feishu Webhook URL
    #[serde(default)]
    pub feishu_webhook: Option<String>,
    /// Feishu mention list (phone numbers or open IDs)
    #[serde(default)]
    pub feishu_mentions: Vec<String>,

    /// Alert threshold by severity
    #[serde(default)]
    pub severity_threshold: MirrorSeverity,
}

fn default_smtp_port() -> u16 {
    587
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            webhook_enabled: false,
            webhook_url: None,
            webhook_secret: None,
            email_enabled: false,
            smtp_server: None,
            smtp_port: 587,
            smtp_username: None,
            smtp_password: None,
            email_from: None,
            email_to: Vec::new(),
            feishu_enabled: false,
            feishu_webhook: None,
            feishu_mentions: Vec::new(),
            severity_threshold: MirrorSeverity::Medium,
        }
    }
}

impl AlertConfig {
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

/// Alert severity ordering
impl MirrorSeverity {
    pub fn as_u8(&self) -> u8 {
        match self {
            MirrorSeverity::Critical => 4,
            MirrorSeverity::High => 3,
            MirrorSeverity::Medium => 2,
            MirrorSeverity::Low => 1,
        }
    }

    pub fn should_alert(&self, threshold: &MirrorSeverity) -> bool {
        self.as_u8() >= threshold.as_u8()
    }
}

/// Mirror alert event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorAlert {
    /// Unique alert ID
    pub id: String,
    /// Alert timestamp (RFC3339)
    pub timestamp: String,
    /// Repository name
    pub repo: String,
    /// Branch (if applicable)
    pub branch: Option<String>,
    /// Error code
    pub error_code: String,
    /// Error message
    pub message: String,
    /// Severity level
    pub severity: MirrorSeverity,
    /// Mirror targets affected
    pub targets: Vec<String>,
    /// Original SHA (if push)
    pub old_sha: Option<String>,
    /// New SHA (if push)
    pub new_sha: Option<String>,
    /// Actor who triggered
    pub actor: Option<String>,
    /// Resolution status
    pub resolved: bool,
    /// Resolution note
    pub resolution_note: Option<String>,
}

impl MirrorAlert {
    /// Create a new alert from mirror errors
    pub fn from_errors(
        repo: &str,
        errors: &[MirrorError],
        results: &[MirrorPushResult],
        actor: Option<&str>,
    ) -> Self {
        let now = chrono_lite_now();
        let first_error = errors.first();

        Self {
            id: uuid_v4(),
            timestamp: now,
            repo: repo.to_string(),
            branch: first_error.and_then(|e| e.branch.clone()),
            error_code: first_error
                .map(|e| e.code.clone())
                .unwrap_or_else(|| "E099".to_string()),
            message: first_error
                .map(|e| e.message.clone())
                .unwrap_or_else(|| "Unknown error".to_string()),
            severity: first_error
                .map(|e| e.severity)
                .unwrap_or(MirrorSeverity::High),
            targets: results.iter().map(|r| r.target.clone()).collect(),
            old_sha: results.first().map(|r| r.old_sha.clone()),
            new_sha: results.first().map(|r| r.new_sha.clone()),
            actor: actor.map(String::from),
            resolved: false,
            resolution_note: None,
        }
    }

    /// Get emoji for severity
    pub fn severity_emoji(&self) -> &'static str {
        match self.severity {
            MirrorSeverity::Critical => "🔴",
            MirrorSeverity::High => "🟠",
            MirrorSeverity::Medium => "🟡",
            MirrorSeverity::Low => "🟢",
        }
    }

    /// Format as text for email/CLI
    pub fn format_text(&self) -> String {
        let emoji = self.severity_emoji();
        format!(
            r#"{} [{}] Mirror Alert: {}

Repository: {}
Branch: {}
Error Code: {}
Message: {}
Targets Affected: {}
Timestamp: {}
Actor: {}
Status: {}
"#,
            emoji,
            self.severity_as_str(),
            self.repo,
            self.repo,
            self.branch.as_deref().unwrap_or("N/A"),
            self.error_code,
            self.message,
            self.targets.join(", "),
            self.timestamp,
            self.actor.as_deref().unwrap_or("unknown"),
            if self.resolved { "RESOLVED" } else { "ACTIVE" }
        )
    }

    /// Format as Feishu message card
    pub fn format_feishu_card(&self) -> serde_json::Value {
        let status_color = match self.severity {
            MirrorSeverity::Critical => "red",
            MirrorSeverity::High => "orange",
            MirrorSeverity::Medium => "yellow",
            MirrorSeverity::Low => "green",
        };

        let mentions = self.targets.join(", ");

        serde_json::json!({
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {
                        "tag": "plain_text",
                        "content": format!("{} Mirror Alert: {}", self.severity_emoji(), self.repo)
                    },
                    "template": status_color
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {
                            "tag": "lark_md",
                            "content": self.message
                        }
                    },
                    {
                        "tag": "hr"
                    },
                    {
                        "tag": "div",
                        "fields": [
                            {
                                "is_short": true,
                                "text": {
                                    "tag": "lark_md",
                                    "content": "**Error Code**\n{}".to_owned() + self.error_code.as_str()
                                }
                            },
                            {
                                "is_short": true,
                                "text": {
                                    "tag": "lark_md",
                                    "content": "**Branch**\n{}".to_owned() + self.branch.as_deref().unwrap_or("N/A")
                                }
                            },
                            {
                                "is_short": true,
                                "text": {
                                    "tag": "lark_md",
                                    "content": "**Targets**\n{}".to_owned() + mentions.as_str()
                                }
                            },
                            {
                                "is_short": true,
                                "text": {
                                    "tag": "lark_md",
                                    "content": "**Time**\n{}".to_owned() + self.timestamp.as_str()
                                }
                            }
                        ]
                    },
                    {
                        "tag": "hr"
                    },
                    {
                        "tag": "note",
                        "elements": [
                            {
                                "tag": "plain_text",
                                "content": "View full audit log: `og mirror status --repo `".to_owned() + self.repo.as_str() + "`"
                            }
                        ]
                    }
                ]
            }
        })
    }

    fn severity_as_str(&self) -> &'static str {
        match self.severity {
            MirrorSeverity::Critical => "CRITICAL",
            MirrorSeverity::High => "HIGH",
            MirrorSeverity::Medium => "MEDIUM",
            MirrorSeverity::Low => "LOW",
        }
    }
}

/// Alert dispatcher - routes alerts to enabled channels
#[derive(Debug, Clone)]
pub struct AlertDispatcher {
    config: AlertConfig,
}

impl AlertDispatcher {
    pub fn new(config: AlertConfig) -> Self {
        Self { config }
    }

    /// Dispatch an alert to all enabled channels
    pub async fn dispatch(&self, alert: &MirrorAlert) {
        // Check severity threshold
        if !alert.severity.should_alert(&self.config.severity_threshold) {
            info!("Alert {} below threshold, skipping notification", alert.id);
            return;
        }

        // Dispatch to each channel
        if self.config.webhook_enabled {
            self.send_webhook(alert).await;
        }

        if self.config.email_enabled {
            self.send_email(alert).await;
        }

        if self.config.feishu_enabled {
            self.send_feishu(alert).await;
        }
    }

    /// Send via webhook
    async fn send_webhook(&self, alert: &MirrorAlert) {
        let url = match &self.config.webhook_url {
            Some(u) => u,
            None => {
                warn!("Webhook enabled but no URL configured");
                return;
            }
        };

        let payload = serde_json::json!({
            "event": "mirror.alert",
            "alert": {
                "id": alert.id,
                "timestamp": alert.timestamp,
                "repo": alert.repo,
                "branch": alert.branch,
                "error_code": alert.error_code,
                "message": alert.message,
                "severity": format!("{:?}", alert.severity),
                "targets": alert.targets,
                "old_sha": alert.old_sha,
                "new_sha": alert.new_sha,
                "actor": alert.actor,
            }
        });

        match self.send_http_post(url, &payload).await {
            Ok(_) => info!("Webhook alert sent: {}", alert.id),
            Err(e) => error!("Failed to send webhook alert: {}", e),
        }
    }

    /// Send via email
    async fn send_email(&self, alert: &MirrorAlert) {
        if self.config.email_to.is_empty() {
            warn!("Email enabled but no recipients configured");
            return;
        }

        let smtp_server = match &self.config.smtp_server {
            Some(s) => s,
            None => {
                warn!("Email enabled but no SMTP server configured");
                return;
            }
        };

        let subject = format!(
            "{} [{}] Mirror Alert: {}",
            alert.severity_emoji(),
            format!("{:?}", alert.severity).to_uppercase(),
            alert.repo
        );

        let body = alert.format_text();

        // Build mail command
        let mut cmd = Command::new("sendmail");
        cmd.arg("-S")
            .arg(format!("smtp={}", smtp_server))
            .arg("-S")
            .arg(format!(
                "smtp-auth-user={}",
                self.config.smtp_username.as_deref().unwrap_or("")
            ))
            .arg("-S")
            .arg(format!(
                "smtp-auth-pass={}",
                self.config.smtp_password.as_deref().unwrap_or("")
            ))
            .arg("-S")
            .arg(format!(
                "smtp-auth={}",
                if self.config.smtp_username.is_some() {
                    "login"
                } else {
                    "none"
                }
            ))
            .arg("-t");

        if let Some(from) = &self.config.email_from {
            cmd.arg("-f").arg(from);
        }

        let mut email = format!(
            "To: {}\n\
             From: {}\n\
             Subject: {}\n\
             Content-Type: text/plain; charset=utf-8\n\n\
             {}",
            self.config.email_to.join(", "),
            self.config
                .email_from
                .as_deref()
                .unwrap_or("opengit@localhost"),
            subject,
            body
        );

        cmd.arg("-t");

        let output = cmd.arg("-oi").stdin(std::process::Stdio::piped()).output();

        match output {
            Ok(o) if o.status.success() => info!("Email alert sent: {}", alert.id),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                error!("Failed to send email alert: {}", stderr);
            }
            Err(e) => error!("Failed to execute sendmail: {}", e),
        }
    }

    /// Send via Feishu webhook
    async fn send_feishu(&self, alert: &MirrorAlert) {
        let webhook = match &self.config.feishu_webhook {
            Some(w) => w,
            None => {
                warn!("Feishu enabled but no webhook configured");
                return;
            }
        };

        let card = alert.format_feishu_card();

        match self.send_http_post(webhook, &card).await {
            Ok(_) => info!("Feishu alert sent: {}", alert.id),
            Err(e) => error!("Failed to send Feishu alert: {}", e),
        }
    }

    /// Generic HTTP POST helper
    async fn send_http_post(&self, url: &str, payload: &serde_json::Value) -> Result<()> {
        let json_str = payload.to_string();

        let mut cmd = Command::new("curl");
        cmd.arg("-s")
            .arg("-X")
            .arg("POST")
            .arg("-H")
            .arg("Content-Type: application/json")
            .arg("-d")
            .arg(&json_str)
            .arg(url);

        // Add HMAC signature if secret configured
        if let Some(ref secret) = self.config.webhook_secret {
            use std::io::Write;

            let mut mac = hmac_sha256::HMAC::new(secret.as_bytes());
            mac.update(json_str.as_bytes());
            let signature = hex::encode(mac.finalize());

            cmd.arg("-H")
                .arg(format!("X-Signature: sha256={}", signature));
        }

        let output = cmd.output()?;

        if !output.status.success() {
            anyhow::bail!(
                "HTTP request failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(())
    }
}

/// Generate UUID v4 (simplified)
fn uuid_v4() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();

    let random: u64 = rand_simple();

    format!(
        "{:016x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        timestamp as u64,
        (random >> 48) as u16,
        (random >> 44) as u16 & 0x0fff,
        ((random >> 32) as u16 & 0x3fff) | 0x8000,
        random & 0xffffffffffff
    )
}

/// Simple pseudo-random number generator (for IDs)
fn rand_simple() -> u64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(
        std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );
    hasher.write_u64(rand_simple());
    hasher.finish()
}

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

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

/// Alert store - persists alerts for audit and status queries
#[derive(Debug, Clone, Default)]
pub struct AlertStore {
    alerts: Vec<MirrorAlert>,
}

impl AlertStore {
    pub fn new() -> Self {
        Self { alerts: Vec::new() }
    }

    /// Add a new alert
    pub fn add(&mut self, alert: MirrorAlert) {
        self.alerts.push(alert);
    }

    /// Get all alerts
    pub fn all(&self) -> &[MirrorAlert] {
        &self.alerts
    }

    /// Get active (unresolved) alerts
    pub fn active(&self) -> Vec<&MirrorAlert> {
        self.alerts.iter().filter(|a| !a.resolved).collect()
    }

    /// Get alerts for a specific repo
    pub fn for_repo(&self, repo: &str) -> Vec<&MirrorAlert> {
        self.alerts.iter().filter(|a| a.repo == repo).collect()
    }

    /// Mark alert as resolved
    pub fn resolve(&mut self, alert_id: &str, note: &str) -> Option<MirrorAlert> {
        if let Some(alert) = self.alerts.iter_mut().find(|a| a.id == alert_id) {
            alert.resolved = true;
            alert.resolution_note = Some(note.to_string());
            return Some(alert.clone());
        }
        None
    }

    /// Load from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let content = std::fs::read_to_string(path)?;
        let alerts: Vec<MirrorAlert> = serde_json::from_str(&content)?;
        Ok(Self { alerts })
    }

    /// Save to file
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(&self.alerts)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_ordering() {
        assert!(MirrorSeverity::Critical.as_u8() > MirrorSeverity::High.as_u8());
        assert!(MirrorSeverity::High.as_u8() > MirrorSeverity::Medium.as_u8());
        assert!(MirrorSeverity::Medium.as_u8() > MirrorSeverity::Low.as_u8());
    }

    #[test]
    fn test_severity_threshold() {
        let critical = MirrorSeverity::Critical;
        let medium = MirrorSeverity::Medium;

        assert!(critical.should_alert(&medium));
        assert!(!medium.should_alert(&critical));
    }

    #[test]
    fn test_alert_format_text() {
        let alert = MirrorAlert {
            id: "test-123".to_string(),
            timestamp: "2026-06-17T10:00:00Z".to_string(),
            repo: "my-repo".to_string(),
            branch: Some("main".to_string()),
            error_code: "E003".to_string(),
            message: "Force push detected".to_string(),
            severity: MirrorSeverity::Critical,
            targets: vec!["github".to_string(), "gitee".to_string()],
            old_sha: Some("abc1234".to_string()),
            new_sha: Some("def5678".to_string()),
            actor: Some("developer".to_string()),
            resolved: false,
            resolution_note: None,
        };

        let text = alert.format_text();
        assert!(text.contains("my-repo"));
        assert!(text.contains("E003"));
        assert!(text.contains("Force push detected"));
    }

    #[test]
    fn test_alert_store_resolve() {
        let mut store = AlertStore::new();
        store.add(MirrorAlert {
            id: "alert-1".to_string(),
            timestamp: "2026-06-17T10:00:00Z".to_string(),
            repo: "test-repo".to_string(),
            branch: None,
            error_code: "E001".to_string(),
            message: "Test".to_string(),
            severity: MirrorSeverity::High,
            targets: vec![],
            old_sha: None,
            new_sha: None,
            actor: None,
            resolved: false,
            resolution_note: None,
        });

        assert_eq!(store.active().len(), 1);

        store.resolve("alert-1", "Fixed by rebasing");

        assert_eq!(store.active().len(), 0);
    }

    #[test]
    fn test_alert_config_default() {
        let config = AlertConfig::default();
        assert!(!config.webhook_enabled);
        assert!(!config.email_enabled);
        assert!(!config.feishu_enabled);
    }
}
