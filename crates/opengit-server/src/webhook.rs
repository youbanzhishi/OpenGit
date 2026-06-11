//! Webhook system — Post-receive notifications for CI/CD integration
//!
//! When a push succeeds, webhooks are triggered to notify external services.
//! Supports configurable URLs, event filtering, and HMAC-SHA256 signatures.

use anyhow::Result;
use opengit_core::policy::Action;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

/// A webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// URL to send the webhook to
    pub url: String,
    /// Secret for HMAC-SHA256 signature (optional)
    pub secret: Option<String>,
    /// Events to trigger on
    pub events: Vec<WebhookEvent>,
    /// Whether the webhook is active
    pub active: bool,
}

/// Events that can trigger a webhook
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebhookEvent {
    Push,
    Tag,
    DeleteBranch,
}

impl WebhookEvent {
    /// Convert from a Git action
    #[allow(dead_code)]
    pub fn from_action(action: Action) -> Option<Self> {
        match action {
            Action::Push => Some(WebhookEvent::Push),
            Action::Tag => Some(WebhookEvent::Tag),
            Action::DeleteBranch => Some(WebhookEvent::DeleteBranch),
            _ => None,
        }
    }
}

/// Webhook delivery payload (similar to GitHub webhook format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookPayload {
    /// Repository name
    pub repo: String,
    /// Identity that triggered the event
    pub identity: String,
    /// Event type
    pub event: String,
    /// Ref name
    pub ref_name: String,
    /// Old SHA
    pub old_sha: String,
    /// New SHA
    pub new_sha: String,
    /// Timestamp
    pub timestamp: String,
}

impl WebhookConfig {
    #[allow(dead_code)]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.into(),
            secret: None,
            events: vec![
                WebhookEvent::Push,
                WebhookEvent::Tag,
                WebhookEvent::DeleteBranch,
            ],
            active: true,
        }
    }

    /// Check if this webhook matches a given event
    pub fn matches_event(&self, event: WebhookEvent) -> bool {
        self.active && self.events.contains(&event)
    }
}

/// Deliver a webhook notification
pub async fn deliver_webhook(config: &WebhookConfig, payload: &WebhookPayload) -> Result<()> {
    debug!(
        "Delivering webhook to {} for event {}",
        config.url, payload.event
    );

    let client = reqwest::Client::new();
    let json_body = serde_json::to_string(payload)?;

    let mut request = client
        .post(&config.url)
        .header("Content-Type", "application/json")
        .header("X-OpenGit-Event", &payload.event)
        .header("X-OpenGit-Delivery", uuid::Uuid::new_v4().to_string())
        .body(json_body);

    // Add HMAC-SHA256 signature if secret is configured
    if let Some(secret) = &config.secret {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())?;
        mac.update(serde_json::to_vec(payload)?.as_slice());
        let signature = hex::encode(mac.finalize().into_bytes());
        request = request.header("X-OpenGit-Signature", format!("sha256={}", signature));
    }

    match request.send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                info!(
                    "Webhook delivered to {} — HTTP {}",
                    config.url,
                    resp.status()
                );
                Ok(())
            } else {
                warn!(
                    "Webhook delivery to {} returned HTTP {}",
                    config.url,
                    resp.status()
                );
                Ok(()) // Don't fail on non-2xx — just log
            }
        }
        Err(e) => {
            error!("Webhook delivery to {} failed: {}", config.url, e);
            Ok(()) // Don't propagate errors — webhooks are best-effort
        }
    }
}

/// Deliver all matching webhooks for an event
pub async fn deliver_all(
    webhooks: &[WebhookConfig],
    payload: &WebhookPayload,
    event: WebhookEvent,
) {
    let matching: Vec<_> = webhooks.iter().filter(|w| w.matches_event(event)).collect();

    if matching.is_empty() {
        return;
    }

    debug!(
        "Delivering {} webhooks for event {:?}",
        matching.len(),
        event
    );

    for config in matching {
        // Best-effort delivery — don't block on failures
        if let Err(e) = deliver_webhook(config, payload).await {
            error!("Webhook delivery error: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webhook_config() {
        let config = WebhookConfig::new("https://ci.example.com/hook");
        assert_eq!(config.url, "https://ci.example.com/hook");
        assert!(config.active);
        assert!(config.matches_event(WebhookEvent::Push));
        assert!(config.matches_event(WebhookEvent::Tag));

        let inactive = WebhookConfig {
            url: "https://example.com".into(),
            secret: None,
            events: vec![WebhookEvent::Push],
            active: false,
        };
        assert!(!inactive.matches_event(WebhookEvent::Push));
    }

    #[test]
    fn test_webhook_event_from_action() {
        assert_eq!(
            WebhookEvent::from_action(Action::Push),
            Some(WebhookEvent::Push)
        );
        assert_eq!(
            WebhookEvent::from_action(Action::Tag),
            Some(WebhookEvent::Tag)
        );
        assert_eq!(
            WebhookEvent::from_action(Action::DeleteBranch),
            Some(WebhookEvent::DeleteBranch)
        );
        assert_eq!(WebhookEvent::from_action(Action::Admin), None);
    }
}
