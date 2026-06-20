//! Token Policy Module - Dynamic Permission Management
//! 
//! P7.4: Added token policy for dynamic permission management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Token rotation strategy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenRotation {
    /// No rotation
    None,
    /// Rotate after fixed duration
    Duration { hours: u64 },
    /// Rotate after number of uses
    Usage { max_uses: u64 },
    /// Rotate after duration or usage, whichever comes first
    Either { hours: u64, max_uses: u64 },
    /// Rotate after duration and usage
    Both { hours: u64, max_uses: u64 },
}

impl Default for TokenRotation {
    fn default() -> Self {
        Self::None
    }
}

/// Condition for policy rules
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Condition {
    /// Always true
    Always,
    /// Never match
    Never,
    /// Time window condition
    TimeWindow { start_hour: u8, end_hour: u8 },
    /// IP allowlist
    IpAllowlist { ips: Vec<String> },
    /// IP blocklist
    IpBlocklist { ips: Vec<String> },
    /// User agent match
    UserAgent { pattern: String },
    /// Repository match
    RepoMatch { pattern: String },
    /// Custom condition
    Custom { key: String, value: String },
}

impl Default for Condition {
    fn default() -> Self {
        Self::Always
    }
}

/// Consequence of a policy rule match
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Consequence {
    /// Allow the action
    Allow,
    /// Deny the action
    Deny,
    /// Deny with a specific error message
    DenyWithMessage { message: String },
    /// Log and allow
    LogAndAllow,
    /// Log and deny
    LogAndDeny,
    /// Require MFA
    RequireMfa,
    /// Rate limit
    RateLimit { requests_per_minute: u32 },
    /// Redirect to different endpoint
    Redirect { url: String },
}

impl Default for Consequence {
    fn default() -> Self {
        Self::Allow
    }
}

/// Policy rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Rule name
    pub name: String,
    /// Rule priority (higher = more important)
    pub priority: i32,
    /// Condition to match
    pub condition: Condition,
    /// Consequence if matched
    pub consequence: Consequence,
    /// Whether this rule is enabled
    pub enabled: bool,
    /// Description of the rule
    pub description: Option<String>,
}

impl PolicyRule {
    /// Create a new policy rule
    pub fn new(name: String, condition: Condition, consequence: Consequence) -> Self {
        Self {
            name,
            priority: 0,
            condition,
            consequence,
            enabled: true,
            description: None,
        }
    }

    /// Check if the condition matches
    pub fn matches(&self, context: &PolicyContext) -> bool {
        match &self.condition {
            Condition::Always => true,
            Condition::Never => false,
            _ => false, // Other conditions need more context
        }
    }
}

impl Default for PolicyRule {
    fn default() -> Self {
        Self {
            name: String::new(),
            priority: 0,
            condition: Condition::Always,
            consequence: Consequence::Allow,
            enabled: true,
            description: None,
        }
    }
}

/// Context for policy evaluation
#[derive(Debug, Clone, Default)]
pub struct PolicyContext {
    /// Repository name
    pub repo: Option<String>,
    /// User or agent identifier
    pub user: Option<String>,
    /// IP address
    pub ip: Option<String>,
    /// User agent string
    pub user_agent: Option<String>,
    /// Action being performed
    pub action: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Token policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPolicy {
    /// Policy name
    pub name: String,
    /// Whether this policy is enabled
    pub enabled: bool,
    /// Default consequence if no rules match
    pub default_consequence: Consequence,
    /// List of policy rules
    pub rules: Vec<PolicyRule>,
    /// Token rotation settings
    pub rotation: TokenRotation,
    /// Maximum token lifetime in seconds
    pub max_lifetime_seconds: Option<u64>,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            name: String::from("default"),
            enabled: true,
            default_consequence: Consequence::Allow,
            rules: Vec::new(),
            rotation: TokenRotation::None,
            max_lifetime_seconds: None,
        }
    }
}

impl TokenPolicy {
    /// Create a new token policy with default settings
    pub fn new(name: String) -> Self {
        Self {
            name,
            ..Default::default()
        }
    }

    /// Add a rule to the policy
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Evaluate the policy for a given context
    pub fn evaluate(&self, context: &PolicyContext) -> &Consequence {
        for rule in &self.rules {
            if rule.enabled && rule.matches(context) {
                return &rule.consequence;
            }
        }
        &self.default_consequence
    }
}

/// Token lifecycle manager
#[derive(Debug, Clone)]
pub struct TokenLifecycleManager {
    /// Active tokens and their creation times
    tokens: HashMap<String, TokenInfo>,
    /// Token policy
    policy: TokenPolicy,
}

#[derive(Debug, Clone)]
struct TokenInfo {
    created_at: std::time::Instant,
    last_used: std::time::Instant,
    use_count: u64,
}

impl TokenLifecycleManager {
    /// Create a new token lifecycle manager
    pub fn new(policy: TokenPolicy) -> Self {
        Self {
            tokens: HashMap::new(),
            policy,
        }
    }

    /// Register a new token
    pub fn register_token(&mut self, token_id: String) {
        let now = std::time::Instant::now();
        self.tokens.insert(token_id, TokenInfo {
            created_at: now,
            last_used: now,
            use_count: 0,
        });
    }

    /// Record token usage
    pub fn record_usage(&mut self, token_id: &str) {
        if let Some(info) = self.tokens.get_mut(token_id) {
            info.last_used = std::time::Instant::now();
            info.use_count += 1;
        }
    }

    /// Check if a token should be rotated
    pub fn should_rotate(&self, token_id: &str) -> bool {
        if let Some(info) = self.tokens.get(token_id) {
            match &self.policy.rotation {
                TokenRotation::None => false,
                TokenRotation::Duration { hours } => {
                    let elapsed = info.created_at.elapsed().as_secs();
                    elapsed > hours * 3600
                }
                TokenRotation::Usage { max_uses } => {
                    info.use_count >= *max_uses
                }
                TokenRotation::Either { hours, max_uses } => {
                    let elapsed = info.created_at.elapsed().as_secs();
                    elapsed > hours * 3600 || info.use_count >= *max_uses
                }
                TokenRotation::Both { hours, max_uses } => {
                    let elapsed = info.created_at.elapsed().as_secs();
                    elapsed > hours * 3600 && info.use_count >= *max_uses
                }
            }
        } else {
            false
        }
    }

    /// Remove a token
    pub fn remove_token(&mut self, token_id: &str) {
        self.tokens.remove(token_id);
    }
}

impl Default for TokenLifecycleManager {
    fn default() -> Self {
        Self::new(TokenPolicy::default())
    }
}

/// Token policy engine - evaluates policies and manages token lifecycle
#[derive(Debug, Clone)]
pub struct TokenPolicyEngine {
    /// All configured policies
    policies: Vec<TokenPolicy>,
    /// Default policy name
    default_policy: String,
    /// Lifecycle managers per token
    lifecycle_managers: HashMap<String, TokenLifecycleManager>,
}

impl TokenPolicyEngine {
    /// Create a new token policy engine
    pub fn new() -> Self {
        Self {
            policies: Vec::new(),
            default_policy: String::from("default"),
            lifecycle_managers: HashMap::new(),
        }
    }

    /// Add a policy to the engine
    pub fn add_policy(&mut self, policy: TokenPolicy) {
        self.policies.push(policy);
    }

    /// Set the default policy
    pub fn set_default_policy(&mut self, name: String) {
        self.default_policy = name;
    }

    /// Get a policy by name
    pub fn get_policy(&self, name: &str) -> Option<&TokenPolicy> {
        self.policies.iter().find(|p| p.name == name)
    }

    /// Evaluate a policy for a given context
    pub fn evaluate(&self, context: &PolicyContext, policy_name: Option<&str>) -> &Consequence {
        let name = policy_name.unwrap_or(&self.default_policy);
        if let Some(policy) = self.get_policy(name) {
            policy.evaluate(context)
        } else {
            &Consequence::Allow
        }
    }

    /// Register a token with the engine
    pub fn register_token(&mut self, token_id: String, policy_name: Option<&str>) {
        let name = policy_name.unwrap_or(&self.default_policy);
        let policy = self.get_policy(name).cloned().unwrap_or_default();
        let mut manager = TokenLifecycleManager::new(policy);
        manager.register_token(token_id.clone());
        self.lifecycle_managers.insert(token_id, manager);
    }

    /// Check if a token should be rotated
    pub fn should_rotate(&self, token_id: &str) -> bool {
        self.lifecycle_managers
            .get(token_id)
            .map(|m| m.should_rotate(token_id))
            .unwrap_or(false)
    }

    /// Record token usage
    pub fn record_usage(&mut self, token_id: &str) {
        if let Some(manager) = self.lifecycle_managers.get_mut(token_id) {
            manager.record_usage(token_id);
        }
    }

    /// Remove a token
    pub fn remove_token(&mut self, token_id: &str) {
        self.lifecycle_managers.remove(token_id);
    }
}

impl Default for TokenPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}
