//! Token Policy — AI-powered token lifecycle management
//!
//! P7.4: Dynamic token permission adjustment based on behavior analysis.
//! Implements automatic token rotation, downgrade, and revocation.

use crate::audit::AuditEntry;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Token policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPolicy {
    /// Enable token policy
    #[serde(default)]
    pub enabled: bool,
    /// Policy rules
    #[serde(default)]
    pub policies: Vec<PolicyRule>,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            policies: default_policy_rules(),
        }
    }
}

/// Default policy rules
fn default_policy_rules() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            name: "high-risk-action".to_string(),
            conditions: vec![
                Condition::ActionCount {
                    action: "delete_branch".to_string(),
                    count: 3,
                    window: Duration::from_secs(3600),
                },
                Condition::ActionCount {
                    action: "force_push".to_string(),
                    count: 2,
                    window: Duration::from_secs(3600),
                },
            ],
            consequences: vec![
                Consequence::DowngradePermissions,
                Consequence::NotifyAdmin,
                Consequence::LogIncident,
            ],
        },
        PolicyRule {
            name: "idle-token-revoke".to_string(),
            conditions: vec![Condition::Idle { days: 90 }],
            consequences: vec![
                Consequence::RevokeToken,
                Consequence::NotifyAdmin,
            ],
        },
        PolicyRule {
            name: "failed-auth-lockout".to_string(),
            conditions: vec![Condition::FailedAuthCount {
                count: 5,
                window: Duration::from_secs(300),
            }],
            consequences: vec![
                Consequence::RequireReauth,
                Consequence::NotifyAdmin,
            ],
        },
        PolicyRule {
            name: "suspicious-activity".to_string(),
            conditions: vec![Condition::SuspiciousActivity],
            consequences: vec![
                Consequence::RevokeToken,
                Consequence::NotifyAdmin,
                Consequence::LogIncident,
            ],
        },
    ]
}

impl TokenPolicy {
    /// Load from TOML file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(path)?;
        let policy: Self = toml::from_str(&content)?;
        Ok(policy)
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

/// A policy rule with conditions and consequences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,
    /// Conditions that trigger this rule
    pub conditions: Vec<Condition>,
    /// Consequences when rule is triggered
    pub consequences: Vec<Consequence>,
}

impl PolicyRule {
    /// Check if all conditions are met
    pub fn check_conditions(&self, recent_actions: &[AuditEntry], now: SystemTime) -> bool {
        self.conditions
            .iter()
            .all(|c| c.evaluate(recent_actions, now))
    }
}

/// Condition types that can trigger a policy
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Count of specific action within a time window
    ActionCount {
        action: String,
        count: usize,
        #[serde(with = "duration_serde")]
        window: Duration,
    },
    /// Failed authentication attempts
    FailedAuthCount {
        count: usize,
        #[serde(with = "duration_serde")]
        window: Duration,
    },
    /// Suspicious activity detected by AI
    SuspiciousActivity,
    /// Token idle for specified days
    Idle { days: u32 },
    /// Time-based condition (outside work hours)
    OutsideWorkHours {
        start_hour: u32,
        end_hour: u32,
    },
    /// New location or IP detected
    NewLocation,
}

mod duration_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = duration.as_secs();
        let s = if secs >= 86400 {
            format!("{}d", secs / 86400)
        } else if secs >= 3600 {
            format!("{}h", secs / 3600)
        } else if secs >= 60 {
            format!("{}m", secs / 60)
        } else {
            format!("{}s", secs)
        };
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let secs = if s.ends_with('d') {
            s.trim_end_matches('d').parse::<u64>().unwrap_or(0) * 86400
        } else if s.ends_with('h') {
            s.trim_end_matches('h').parse::<u64>().unwrap_or(0) * 3600
        } else if s.ends_with('m') {
            s.trim_end_matches('m').parse::<u64>().unwrap_or(0) * 60
        } else if s.ends_with('s') {
            s.trim_end_matches('s').parse::<u64>().unwrap_or(0)
        } else {
            s.parse::<u64>().unwrap_or(0)
        };
        Ok(Duration::from_secs(secs))
    }
}

impl Condition {
    /// Evaluate if this condition is met
    fn evaluate(&self, recent_actions: &[AuditEntry], now: SystemTime) -> bool {
        match self {
            Condition::ActionCount {
                action,
                count,
                window,
            } => {
                let cutoff = now - *window;
                let action_count = recent_actions
                    .iter()
                    .filter(|e| {
                        let op_name = format!("{:?}", e.operation).to_lowercase();
                        op_name.contains(&action.to_lowercase())
                            && parse_timestamp(&e.timestamp)
                                .map(|t| t >= cutoff)
                                .unwrap_or(false)
                    })
                    .count();
                action_count >= *count
            }
            Condition::FailedAuthCount { count, window } => {
                let cutoff = now - *window;
                let fail_count = recent_actions
                    .iter()
                    .filter(|e| {
                        matches!(
                            e.operation,
                            crate::audit::AuditOperation::MirrorBlocked
                        ) && parse_timestamp(&e.timestamp)
                            .map(|t| t >= cutoff)
                            .unwrap_or(false)
                    })
                    .count();
                fail_count >= *count
            }
            Condition::SuspiciousActivity => {
                // Would be set by AI audit system
                recent_actions
                    .iter()
                    .any(|e| e.details.to_string().contains("suspicious"))
            }
            Condition::Idle { days } => {
                if let Some(last_action) = recent_actions.first() {
                    if let Some(ts) = parse_timestamp(&last_action.timestamp) {
                        let idle = now - ts;
                        return idle > Duration::from_secs((*days as u64) * 86400);
                    }
                }
                false
            }
            Condition::OutsideWorkHours { start_hour, end_hour } => {
                if let Some(last_action) = recent_actions.first() {
                    if let Some(hour) = parse_hour(&last_action.timestamp) {
                        return hour < *start_hour || hour > *end_hour;
                    }
                }
                false
            }
            Condition::NewLocation => {
                // Would be implemented with location tracking
                false
            }
        }
    }
}

/// Consequence types when a policy is triggered
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consequence {
    /// Downgrade token permissions
    DowngradePermissions,
    /// Notify administrators
    NotifyAdmin,
    /// Revoke the token immediately
    RevokeToken,
    /// Require re-authentication
    RequireReauth,
    /// Log as security incident
    LogIncident,
}

/// Token policy engine — evaluates policies and executes consequences
pub struct TokenPolicyEngine {
    policies: Vec<PolicyRule>,
}

impl TokenPolicyEngine {
    /// Create a new engine with policies
    pub fn new(policies: Vec<PolicyRule>) -> Self {
        Self { policies }
    }

    /// Evaluate all policies for an identity
    pub fn evaluate(&self, _identity: &str, recent_actions: &[AuditEntry]) -> Vec<Consequence> {
        let now = SystemTime::now();
        let mut consequences = Vec::new();

        for policy in &self.policies {
            if policy.check_conditions(recent_actions, now) {
                info!(
                    "Policy '{}' triggered for identity '{}'",
                    policy.name, _identity
                );
                consequences.extend_from_slice(&policy.consequences);
            }
        }

        consequences
    }

    /// Check if permissions should be downgraded
    pub fn should_downgrade(&self, identity: &str, recent_actions: &[AuditEntry]) -> bool {
        let consequences = self.evaluate(identity, recent_actions);
        consequences.contains(&Consequence::DowngradePermissions)
    }

    /// Check if token should be revoked
    pub fn should_revoke(&self, identity: &str, recent_actions: &[AuditEntry]) -> bool {
        let consequences = self.evaluate(identity, recent_actions);
        consequences.contains(&Consequence::RevokeToken)
    }

    /// Check if re-authentication is required
    pub fn should_require_reauth(&self, identity: &str, recent_actions: &[AuditEntry]) -> bool {
        let consequences = self.evaluate(identity, recent_actions);
        consequences.contains(&Consequence::RequireReauth)
    }

    /// Get unique consequences (deduplicated)
    pub fn get_consequences(&self, identity: &str, recent_actions: &[AuditEntry]) -> Vec<Consequence> {
        let all = self.evaluate(identity, recent_actions);
        let mut unique: Vec<Consequence> = Vec::new();
        for c in all {
            if !unique.contains(&c) {
                unique.push(c);
            }
        }
        unique
    }
}

/// Token lifecycle manager
pub struct TokenLifecycleManager {
    engine: TokenPolicyEngine,
    identities_file: PathBuf,
}

impl TokenLifecycleManager {
    /// Create a new lifecycle manager
    pub fn new(policy: TokenPolicy, identities_file: PathBuf) -> Self {
        let engine = TokenPolicyEngine::new(policy.policies);
        Self {
            engine,
            identities_file,
        }
    }

    /// Check for expired tokens
    pub fn check_expired_tokens(&self) -> Result<Vec<String>> {
        // Would load identity store and check token expiration
        // For now, return empty list
        Ok(Vec::new())
    }

    /// Check for idle tokens (not used for specified days)
    pub fn check_idle_tokens(&self, idle_days: u32) -> Result<Vec<String>> {
        let idle_threshold = Duration::from_secs((idle_days as u64) * 86400);
        let now = SystemTime::now();

        // Would load audit log and check last activity
        // For now, return empty list
        let _ = (idle_threshold, now);
        Ok(Vec::new())
    }

    /// Auto-rotate a token for an identity
    pub fn auto_rotate(&self, identity: &str) -> Result<TokenRotation> {
        info!("Auto-rotating token for identity: {}", identity);

        let rotation = TokenRotation {
            identity: identity.to_string(),
            old_token_label: None,
            new_token: generate_new_token(),
            reason: "Scheduled rotation".to_string(),
            timestamp: chrono_lite_now(),
        };

        Ok(rotation)
    }

    /// Execute consequences for an identity
    pub async fn execute_consequences(
        &self,
        identity: &str,
        consequences: &[Consequence],
        audit_log: &mut crate::audit::AuditLog,
    ) -> Result<()> {
        for consequence in consequences {
            match consequence {
                Consequence::DowngradePermissions => {
                    info!(
                        "Would downgrade permissions for identity: {}",
                        identity
                    );
                    // Would modify identity permissions
                }
                Consequence::NotifyAdmin => {
                    info!(
                        "Would notify admin about identity: {}",
                        identity
                    );
                    // Would send notification
                }
                Consequence::RevokeToken => {
                    info!("Would revoke token for identity: {}", identity);
                    // Would revoke token in identity store
                }
                Consequence::RequireReauth => {
                    info!(
                        "Would require re-auth for identity: {}",
                        identity
                    );
                    // Would invalidate session
                }
                Consequence::LogIncident => {
                    warn!(
                        "Security incident logged for identity: {}",
                        identity
                    );
                    // Already logged via tracing
                }
            }
        }

        // Log the consequence execution
        audit_log.log_config_change(
            "token_policy_consequence",
            None,
            Some(&format!(
                "{}: {:?}",
                identity,
                consequences
            )),
        );

        Ok(())
    }

    /// Get policy engine
    pub fn engine(&self) -> &TokenPolicyEngine {
        &self.engine
    }
}

/// Token rotation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRotation {
    /// Identity this rotation belongs to
    pub identity: String,
    /// Label of the old token (if rotating existing)
    pub old_token_label: Option<String>,
    /// The new token secret
    pub new_token: String,
    /// Reason for rotation
    pub reason: String,
    /// Timestamp of rotation
    pub timestamp: String,
}

impl TokenRotation {
    /// Format as CLI output
    pub fn format_cli(&self) -> String {
        format!(
            "Token Rotation for {}\n\
             ======================\n\
             Identity: {}\n\
             Old Token: {}\n\
             New Token: {}\n\
             Reason: {}\n\
             Time: {}",
            self.identity,
            self.identity,
            self.old_token_label.as_deref().unwrap_or("(new)"),
            &self.new_token[..20.min(self.new_token.len())] + "...",
            self.reason,
            self.timestamp
        )
    }
}

/// Generate a new token secret
fn generate_new_token() -> String {
    use sha2::{Digest, Sha256};
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(timestamp.to_le_bytes());
    hasher.update(rand_bytes());
    hex::encode(hasher.finalize())
}

/// Generate random bytes (simplified)
fn rand_bytes() -> [u8; 16] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u128(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    );
    let hash = hasher.finish();
    hash.to_le_bytes()
}

fn parse_timestamp(ts: &str) -> Option<SystemTime> {
    // Simple RFC3339-like parsing
    // Format: 2026-06-17T10:00:00Z
    let parts: Vec<&str> = ts.split(&['-', 'T', ':'][..]).collect();
    if parts.len() < 5 {
        return None;
    }

    let year: u64 = parts[0].parse().ok()?;
    let month: u64 = parts[1].parse().ok()?;
    let day: u64 = parts[2].parse().ok()?;
    let hour: u64 = parts[3].parse().ok()?;
    let min: u64 = parts[4].parse().ok()?;

    let days_since_epoch = (year as u64 - 1970) * 365 + (month - 1) * 30 + day - 1;
    let secs_since_epoch = days_since_epoch * 86400 + hour * 3600 + min * 60;

    SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(secs_since_epoch))
}

fn parse_hour(ts: &str) -> Option<u32> {
    ts.split('T')
        .nth(1)?
        .split(':')
        .next()?
        .parse()
        .ok()
}

fn chrono_lite_now() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_condition_action_count() {
        let condition = Condition::ActionCount {
            action: "mirror_push".to_string(),
            count: 2,
            window: Duration::from_secs(3600),
        };

        let now = SystemTime::now();
        let recent_actions = vec![
            create_entry("2026-06-17T09:00:00Z", crate::audit::AuditOperation::MirrorPush),
            create_entry("2026-06-17T09:30:00Z", crate::audit::AuditOperation::MirrorPush),
            create_entry("2026-06-17T10:00:00Z", crate::audit::AuditOperation::MirrorPush),
        ];

        assert!(condition.evaluate(&recent_actions, now));
    }

    #[test]
    fn test_condition_idle() {
        let condition = Condition::Idle { days: 30 };

        let now = SystemTime::now();
        let recent_actions = vec![create_entry("2026-05-01T10:00:00Z", crate::audit::AuditOperation::MirrorPush)];

        assert!(condition.evaluate(&recent_actions, now));
    }

    #[test]
    fn test_policy_evaluation() {
        let policies = vec![PolicyRule {
            name: "test".to_string(),
            conditions: vec![Condition::ActionCount {
                action: "mirror_push".to_string(),
                count: 2,
                window: Duration::from_secs(3600),
            }],
            consequences: vec![Consequence::DowngradePermissions],
        }];

        let engine = TokenPolicyEngine::new(policies);
        let now = SystemTime::now();
        let recent_actions = vec![
            create_entry("2026-06-17T09:00:00Z", crate::audit::AuditOperation::MirrorPush),
            create_entry("2026-06-17T09:30:00Z", crate::audit::AuditOperation::MirrorPush),
        ];

        let consequences = engine.evaluate("agent-test", &recent_actions);
        assert!(consequences.contains(&Consequence::DowngradePermissions));
    }

    #[test]
    fn test_token_rotation_format() {
        let rotation = TokenRotation {
            identity: "agent-deploy".to_string(),
            old_token_label: Some("ci-key".to_string()),
            new_token: "og_agent_deploy_abc123def456".to_string(),
            reason: "Security policy".to_string(),
            timestamp: "2026-06-17T10:00:00Z".to_string(),
        };

        let formatted = rotation.format_cli();
        assert!(formatted.contains("agent-deploy"));
        assert!(formatted.contains("ci-key"));
    }

    #[test]
    fn test_duration_serde() {
        let duration = Duration::from_secs(3600);
        let serialized = duration_serde::serialize(&duration, &mut serde_json::Serializer::new(vec![]).unwrap()).unwrap();
        assert_eq!(serialized, "1h");
    }

    fn create_entry(timestamp: &str, operation: crate::audit::AuditOperation) -> AuditEntry {
        AuditEntry {
            id: uuid_simple(),
            timestamp: timestamp.to_string(),
            operation,
            repo: "test-repo".to_string(),
            branch: Some("main".to_string()),
            actor: Some("agent".to_string()),
            details: crate::audit::AuditDetails::MirrorPush {
                targets: vec![],
                blocked_by: None,
            },
        }
    }

    fn uuid_simple() -> String {
        format!("{:016x}", SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64)
    }
}
