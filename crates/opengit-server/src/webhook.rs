//! Webhook system — Post-receive notifications for CI/CD integration
//!
//! P3: Enhanced ref parsing — post-receive hook output is parsed to extract
//!     exact ref names and SHAs for precise webhook payloads.

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

    /// Classify a ref update into the matching webhook event
    pub fn from_ref_update(ref_name: &str, old_sha: &str, new_sha: &str) -> Option<Self> {
        let zero_sha = "0000000000000000000000000000000000000000";
        if new_sha == zero_sha {
            // Deletion
            if ref_name.starts_with("refs/tags/") {
                Some(WebhookEvent::Tag)
            } else {
                Some(WebhookEvent::DeleteBranch)
            }
        } else if ref_name.starts_with("refs/tags/") {
            Some(WebhookEvent::Tag)
        } else {
            Some(WebhookEvent::Push)
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
    /// Event type (push, tag, delete-branch)
    pub event: String,
    /// Ref name (e.g., refs/heads/master)
    pub ref_name: String,
    /// Old SHA
    pub old_sha: String,
    /// New SHA
    pub new_sha: String,
    /// Timestamp
    pub timestamp: String,
}

/// A parsed ref update from post-receive hook output
#[derive(Debug, Clone)]
pub struct RefUpdate {
    pub ref_name: String,
    pub old_sha: String,
    pub new_sha: String,
}

impl RefUpdate {
    /// Parse post-receive hook stdin output
    /// Format: `<old-sha> <new-sha> <ref-name>\n`
    pub fn parse_stdin(input: &str) -> Vec<Self> {
        input
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|line| {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 3 {
                    Some(Self {
                        old_sha: parts[0].to_string(),
                        new_sha: parts[1].to_string(),
                        ref_name: parts[2].to_string(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }
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

/// Deliver webhooks for ref updates (P3: precise per-ref delivery)
pub async fn deliver_for_refs(
    webhooks: &[WebhookConfig],
    repo: &str,
    identity: &str,
    ref_updates: &[RefUpdate],
) -> u32 {
    let mut sent = 0u32;
    for update in ref_updates {
        let event =
            match WebhookEvent::from_ref_update(&update.ref_name, &update.old_sha, &update.new_sha)
            {
                Some(e) => e,
                None => continue,
            };

        let event_name = match event {
            WebhookEvent::Push => "push",
            WebhookEvent::Tag => "tag",
            WebhookEvent::DeleteBranch => "delete-branch",
        };

        let payload = WebhookPayload {
            repo: repo.to_string(),
            identity: identity.to_string(),
            event: event_name.to_string(),
            ref_name: update.ref_name.clone(),
            old_sha: update.old_sha.clone(),
            new_sha: update.new_sha.clone(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        };

        for config in webhooks.iter().filter(|w| w.matches_event(event)) {
            if let Err(e) = deliver_webhook(config, &payload).await {
                error!("Webhook delivery error: {}", e);
            } else {
                sent += 1;
            }
        }
    }
    sent
}

/// Deliver all matching webhooks for an event (legacy — for non-ref-specific triggers)
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

    #[test]
    fn test_webhook_event_from_ref_update() {
        // Normal push
        assert_eq!(
            WebhookEvent::from_ref_update("refs/heads/master", "abc123", "def456"),
            Some(WebhookEvent::Push)
        );
        // New branch
        assert_eq!(
            WebhookEvent::from_ref_update(
                "refs/heads/feature",
                "0000000000000000000000000000000000000000",
                "abc123"
            ),
            Some(WebhookEvent::Push)
        );
        // Delete branch
        assert_eq!(
            WebhookEvent::from_ref_update(
                "refs/heads/feature",
                "abc123",
                "0000000000000000000000000000000000000000"
            ),
            Some(WebhookEvent::DeleteBranch)
        );
        // Tag push
        assert_eq!(
            WebhookEvent::from_ref_update(
                "refs/tags/v1.0",
                "0000000000000000000000000000000000000000",
                "abc123"
            ),
            Some(WebhookEvent::Tag)
        );
    }

    #[test]
    fn test_ref_update_parse() {
        let input = "abc123def456789012345678901234567890abcd def456789012345678901234567890abcdef1234 refs/heads/master\n0000000000000000000000000000000000000000 1111111111111111111111111111111111111111 refs/heads/feature\n";
        let updates = RefUpdate::parse_stdin(input);
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].ref_name, "refs/heads/master");
        assert_eq!(updates[1].ref_name, "refs/heads/feature");
    }
}
