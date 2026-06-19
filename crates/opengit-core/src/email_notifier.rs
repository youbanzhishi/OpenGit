//! Email Notification System
//!
//! Sends email notifications for push and mirror sync events.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    #[serde(default)]
    pub smtp_username: String,
    #[serde(default)]
    pub smtp_password: String,
    #[serde(default)]
    pub from: String,
    pub to: Vec<String>,
    #[serde(default = "default_true")]
    pub use_tls: bool,
}

fn default_smtp_port() -> u16 { 587 }
fn default_true() -> bool { true }

impl Default for EmailConfig {
    fn default() -> Self {
        Self { enabled: false, smtp_host: String::new(), smtp_port: 587, smtp_username: String::new(), smtp_password: String::new(), from: String::new(), to: Vec::new(), use_tls: true }
    }
}

impl EmailConfig {
    pub fn load(path: &PathBuf) -> Result<Self> {
        if !path.exists() { return Ok(Self::default()); }
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
    pub fn is_configured(&self) -> bool {
        self.enabled && !self.smtp_host.is_empty() && !self.smtp_username.is_empty() && !self.from.is_empty() && !self.to.is_empty() && !self.smtp_password.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct EmailNotifier { config: EmailConfig }

impl EmailNotifier {
    pub fn new(config: EmailConfig) -> Self { Self { config } }
    pub fn is_enabled(&self) -> bool { self.config.is_configured() }
    pub fn config(&self) -> &EmailConfig { &self.config }
    
    #[allow(dead_code)]
    pub async fn send_push_notification(&self, event: &PushEmailEvent) -> Result<()> {
        if !self.is_enabled() { return Ok(()); }
        let subject = format!("[OpenGit] 推送成功: {}/{}", event.repo_name, event.branch);
        let body = self.build_push_email_body(event);
        self.send_email(&subject, &body).await
    }
    
    #[allow(dead_code)]
    pub async fn send_mirror_notification(&self, event: &MirrorEmailEvent) -> Result<()> {
        if !self.is_enabled() { return Ok(()); }
        let subject = if event.all_success {
            format!("[OpenGit] 镜像同步成功: {}", event.repo_name)
        } else if event.no_success {
            format!("[OpenGit] 镜像同步全部失败: {}", event.repo_name)
        } else {
            format!("[OpenGit] 镜像同步部分失败: {}", event.repo_name)
        };
        let body = self.build_mirror_email_body(event);
        self.send_email(&subject, &body).await
    }

    async fn send_email(&self, subject: &str, body: &str) -> Result<()> {
        use std::process::Command;
        let _ = self.try_sendmail(subject, body).await;
        Ok(())
    }

    async fn try_sendmail(&self, subject: &str, body: &str) -> Result<()> {
        use std::io::Write;
        let mut child = std::process::Command::new("sendmail")
            .args(["-t"])
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = child.stdin.take() {
            let email = format!("To: {}\r\nFrom: {}\r\nSubject: {}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{}",
                self.config.to.join(", "), self.config.from, subject, body);
            stdin.write_all(email.as_bytes())?;
        }
        let _ = child.wait()?;
        Ok(())
    }

    fn build_push_email_body(&self, event: &PushEmailEvent) -> String {
        format!("OpenGit 推送通知\n仓库: {}\n分支: {}\n操作者: {}\nSHA: {}",
            event.repo_name, event.branch, event.actor, &event.new_sha[..8.min(event.new_sha.len())])
    }

    fn build_mirror_email_body(&self, event: &MirrorEmailEvent) -> String {
        let mut body = format!("OpenGit 镜像同步报告\n仓库: {}\n分支: {}\n\n镜像同步结果:\n", event.repo_name, event.branch);
        for target in &event.targets {
            body.push_str(&format!("  - {}: {}\n", target.name, if target.success { "成功" } else { "失败" }));
        }
        body
    }
}

#[derive(Debug, Clone)]
pub struct PushEmailEvent {
    pub repo_name: String, pub branch: String, pub actor: String,
    pub old_sha: String, pub new_sha: String, pub timestamp: SystemTime,
}

#[derive(Debug, Clone)]
pub struct MirrorEmailEvent {
    pub repo_name: String, pub branch: String, pub actor: String,
    pub old_sha: String, pub new_sha: String, pub timestamp: SystemTime,
    pub targets: Vec<MirrorTargetResult>, pub all_success: bool, pub no_success: bool,
}

#[derive(Debug, Clone)]
pub struct MirrorTargetResult { pub name: String, pub success: bool, pub error: Option<String> }
