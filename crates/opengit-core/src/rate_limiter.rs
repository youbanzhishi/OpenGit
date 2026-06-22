//! Rate Limiter — Token bucket + sliding window rate limiting
//!
//! P8.1: Enterprise-grade rate limiting for Git operations
//!
//! Features:
//! - Per-identity rate limiting (by token)
//! - Per-IP rate limiting
//! - Configurable limits: reads vs writes
//! - Burst allowance with token bucket
//! - Sliding window for accurate counting
//!
//! Configuration: `config/rate-limit.toml`

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Sliding window counter for a single key
#[derive(Clone)]
struct WindowCounter {
    /// Timestamps of recent requests
    timestamps: Vec<Instant>,
    /// Window duration (e.g., 1 minute)
    window: Duration,
    /// Maximum requests per window
    limit: usize,
}

impl WindowCounter {
    fn new(window: Duration, limit: usize) -> Self {
        Self {
            timestamps: Vec::new(),
            window,
            limit,
        }
    }

    /// Try to acquire a token, returns true if allowed
    fn try_acquire(&mut self) -> bool {
        let now = Instant::now();
        let window_start = now - self.window;

        // Remove old timestamps outside the window
        self.timestamps.retain(|&t| t > window_start);

        // Check if we're under the limit
        if self.timestamps.len() >= self.limit {
            return false;
        }

        // Record this request
        self.timestamps.push(now);
        true
    }

    /// Get remaining requests in current window (without cleanup)
    fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.timestamps.len())
    }

    /// Reset the counter
    fn reset(&mut self) {
        self.timestamps.clear();
    }
}

/// Token bucket for burst handling
#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Try to consume tokens, returns true if allowed
    fn try_consume(&mut self, tokens: f64) -> bool {
        self.refill();

        if self.tokens >= tokens {
            self.tokens -= tokens;
            true
        } else {
            false
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.last_refill = Instant::now();

        let new_tokens = elapsed * self.refill_rate;
        self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
    }

    /// Get remaining tokens
    #[allow(dead_code)]
    fn remaining(&self) -> f64 {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;
        (self.tokens + new_tokens).min(self.max_tokens)
    }
}

/// Combined rate limiter using sliding window + token bucket
#[derive(Clone)]
struct HybridLimiter {
    /// Sliding window for hard limit
    window_counter: WindowCounter,
    /// Token bucket for burst
    token_bucket: TokenBucket,
}

impl HybridLimiter {
    fn new(window: Duration, limit: usize, burst: usize) -> Self {
        // Token bucket refill rate: limit per second
        let refill_rate = limit as f64 / window.as_secs_f64();

        Self {
            window_counter: WindowCounter::new(window, limit),
            token_bucket: TokenBucket::new(burst as f64, refill_rate),
        }
    }

    /// Try to acquire permission, returns true if allowed
    fn try_acquire(&mut self) -> RateLimitResult {
        // First check sliding window (hard limit)
        if !self.window_counter.try_acquire() {
            return RateLimitResult::Denied {
                reason: "window_limit".into(),
                retry_after: Some(1), // seconds
            };
        }

        // Then check token bucket (burst limit)
        if !self.token_bucket.try_consume(1.0) {
            // Revert the window counter
            self.window_counter.timestamps.pop();
            return RateLimitResult::Denied {
                reason: "burst_limit".into(),
                retry_after: Some(1),
            };
        }

        RateLimitResult::Allowed {
            remaining: self.window_counter.remaining() as u32,
            reset_in: self.window_counter.window.as_secs() as u32,
        }
    }
}

/// Result of rate limit check
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed {
        remaining: u32,
        reset_in: u32,
    },
    Denied {
        reason: String,
        retry_after: Option<u32>,
    },
}

impl RateLimitResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, RateLimitResult::Allowed { .. })
    }

    pub fn retry_after(&self) -> Option<u32> {
        match self {
            RateLimitResult::Denied { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

/// Rate limit categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitKind {
    /// Read operations (git fetch/clone)
    Read,
    /// Write operations (git push)
    Write,
    /// API operations
    Api,
    /// Admin operations
    Admin,
}

impl RateLimitKind {
    pub fn from_path(path: &str) -> Self {
        if path.contains("git-receive-pack") || path.contains("git-upload-pack") {
            if path.contains("git-receive-pack") {
                Self::Write
            } else {
                Self::Read
            }
        } else if path.starts_with("/api/") {
            if path.starts_with("/api/identities") || path.starts_with("/api/policy") {
                Self::Admin
            } else {
                Self::Api
            }
        } else {
            Self::Read
        }
    }
}

/// Rate limit configuration
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RateLimitConfig {
    /// Enable/disable rate limiting
    pub enabled: bool,

    /// Per-IP rate limits
    pub ip: IpRateLimit,

    /// Per-identity rate limits
    pub identity: IdentityRateLimit,

    /// Whitelist (CIDR notation)
    #[serde(default)]
    pub whitelist: Vec<String>,

    /// Rate limit response message
    #[serde(default = "default_message")]
    pub message: String,
}

fn default_message() -> String {
    "Rate limit exceeded. Please try again later.".into()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IpRateLimit {
    /// Read limit: requests per window
    pub read_limit: usize,
    /// Write limit: requests per window
    pub write_limit: usize,
    /// Window duration in seconds
    pub window_secs: u64,
    /// Burst allowance
    pub burst: usize,
    /// Enable IP-based limiting
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdentityRateLimit {
    /// Read limit: requests per window
    pub read_limit: usize,
    /// Write limit: requests per window
    pub write_limit: usize,
    /// Window duration in seconds
    pub window_secs: u64,
    /// Burst allowance
    pub burst: usize,
    /// Enable identity-based limiting
    pub enabled: bool,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ip: IpRateLimit {
                enabled: true,
                read_limit: 100,
                write_limit: 10,
                window_secs: 60,
                burst: 20,
            },
            identity: IdentityRateLimit {
                enabled: true,
                read_limit: 500,
                write_limit: 50,
                window_secs: 60,
                burst: 100,
            },
            whitelist: vec!["127.0.0.0/8".into(), "::1".into()],
            message: default_message(),
        }
    }
}

/// Main rate limiter
pub struct RateLimiter {
    /// Per-IP limiters
    ip_limiters: Arc<RwLock<AHashMap<String, AHashMap<RateLimitKind, HybridLimiter>>>>,
    /// Per-identity limiters
    identity_limiters: Arc<RwLock<AHashMap<String, AHashMap<RateLimitKind, HybridLimiter>>>>,
    /// Configuration
    config: RateLimitConfig,
    /// Cleanup interval
    #[allow(dead_code)]
    cleanup_interval: Duration,
}

#[allow(dead_code)]
impl RateLimiter {
    /// Create a new rate limiter from config
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            ip_limiters: Arc::new(RwLock::new(AHashMap::new())),
            identity_limiters: Arc::new(RwLock::new(AHashMap::new())),
            config,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create from TOML file
    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: RateLimitConfig = toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self::new(config))
    }

    /// Check if an IP is whitelisted
    fn is_whitelisted(&self, ip: &str) -> bool {
        // Simple exact match for now
        // TODO: Support CIDR matching
        self.config.whitelist.iter().any(|w| w == ip || w == "*")
    }

    /// Get or create an IP limiter
    async fn get_ip_limiter(
        &self,
        ip: &str,
        _kind: RateLimitKind,
    ) -> Arc<RwLock<AHashMap<RateLimitKind, HybridLimiter>>> {
        // First check if we have an entry for this IP
        {
            let limiters = self.ip_limiters.read().await;
            if let Some(entry) = limiters.get(ip) {
                // Return wrapped in Arc<RwLock>
                return Arc::new(RwLock::new(entry.clone()));
            }
        }

        // Create new entry
        let entry: AHashMap<RateLimitKind, HybridLimiter> = AHashMap::new();

        {
            let mut limiters = self.ip_limiters.write().await;
            limiters.insert(ip.to_string(), entry.clone());
        }

        // Return the newly inserted entry wrapped in Arc<RwLock>
        Arc::new(RwLock::new(entry))
    }

    /// Get or create an identity limiter
    async fn get_identity_limiter(
        &self,
        identity: &str,
        _kind: RateLimitKind,
    ) -> Arc<RwLock<AHashMap<RateLimitKind, HybridLimiter>>> {
        // First check if we have an entry for this identity
        {
            let limiters = self.identity_limiters.read().await;
            if let Some(entry) = limiters.get(identity) {
                return Arc::new(RwLock::new(entry.clone()));
            }
        }

        // Create new entry
        let entry: AHashMap<RateLimitKind, HybridLimiter> = AHashMap::new();

        {
            let mut limiters = self.identity_limiters.write().await;
            limiters.insert(identity.to_string(), entry.clone());
        }

        // Return the newly inserted entry wrapped in Arc<RwLock>
        Arc::new(RwLock::new(entry))
    }

    /// Check rate limit for an IP
    pub async fn check_ip(&self, ip: &str, kind: RateLimitKind) -> RateLimitResult {
        if !self.config.enabled || !self.config.ip.enabled {
            return RateLimitResult::Allowed {
                remaining: u32::MAX,
                reset_in: 0,
            };
        }

        if self.is_whitelisted(ip) {
            return RateLimitResult::Allowed {
                remaining: u32::MAX,
                reset_in: 0,
            };
        }

        let limiters = self.get_ip_limiter(ip, kind).await;
        let mut limiters = limiters.write().await;

        let (limit, burst) = match kind {
            RateLimitKind::Read => (self.config.ip.read_limit, self.config.ip.burst),
            RateLimitKind::Write => (self.config.ip.write_limit, self.config.ip.burst / 2),
            RateLimitKind::Api => (self.config.ip.read_limit, self.config.ip.burst),
            RateLimitKind::Admin => (self.config.ip.write_limit, self.config.ip.burst / 4),
        };

        let window = Duration::from_secs(self.config.ip.window_secs);

        let limiter = limiters
            .entry(kind)
            .or_insert_with(|| HybridLimiter::new(window, limit, burst));

        limiter.try_acquire()
    }

    /// Check rate limit for an identity
    pub async fn check_identity(
        &self,
        identity: &str,
        kind: RateLimitKind,
    ) -> RateLimitResult {
        if !self.config.enabled || !self.config.identity.enabled {
            return RateLimitResult::Allowed {
                remaining: u32::MAX,
                reset_in: 0,
            };
        }

        if identity == "anonymous" {
            // Anonymous users share IP-based limits only
            return RateLimitResult::Allowed {
                remaining: u32::MAX,
                reset_in: 0,
            };
        }

        let limiters = self.get_identity_limiter(identity, kind).await;
        let mut limiters = limiters.write().await;

        let (limit, burst) = match kind {
            RateLimitKind::Read => (self.config.identity.read_limit, self.config.identity.burst),
            RateLimitKind::Write => (self.config.identity.write_limit, self.config.identity.burst / 2),
            RateLimitKind::Api => (self.config.identity.read_limit, self.config.identity.burst),
            RateLimitKind::Admin => (self.config.identity.write_limit, self.config.identity.burst / 4),
        };

        let window = Duration::from_secs(self.config.identity.window_secs);

        let limiter = limiters
            .entry(kind)
            .or_insert_with(|| HybridLimiter::new(window, limit, burst));

        limiter.try_acquire()
    }

    /// Combined check: both IP and identity limits apply
    pub async fn check(&self, ip: &str, identity: &str, kind: RateLimitKind) -> RateLimitResult {
        // Check IP limit
        let ip_result = self.check_ip(ip, kind).await;
        if !ip_result.is_allowed() {
            return ip_result;
        }

        // Check identity limit
        let identity_result = self.check_identity(identity, kind).await;
        if !identity_result.is_allowed() {
            return identity_result;
        }

        // Return the more restrictive of the two
        match (&ip_result, &identity_result) {
            (
                RateLimitResult::Allowed { remaining: r1, .. },
                RateLimitResult::Allowed { remaining: r2, .. },
            ) => RateLimitResult::Allowed {
                remaining: (*r1).min(*r2),
                reset_in: 0,
            },
            _ => identity_result,
        }
    }

    /// Get current status for an IP
    pub async fn status_ip(&self, ip: &str, kind: RateLimitKind) -> RateLimitStatus {
        let limiters = self.get_ip_limiter(ip, kind).await;
        let limiters = limiters.read().await;

        if let Some(limiter) = limiters.get(&kind) {
            RateLimitStatus {
                allowed: true,
                remaining: limiter.window_counter.remaining() as u32,
                limit: limiter.window_counter.limit as u32,
                reset_in: limiter.window_counter.window.as_secs() as u32,
            }
        } else {
            RateLimitStatus {
                allowed: true,
                remaining: self.config.ip.read_limit as u32,
                limit: self.config.ip.read_limit as u32,
                reset_in: self.config.ip.window_secs as u32,
            }
        }
    }

    /// Get current status for an identity
    pub async fn status_identity(&self, identity: &str, kind: RateLimitKind) -> RateLimitStatus {
        let limiters = self.get_identity_limiter(identity, kind).await;
        let limiters = limiters.read().await;

        if let Some(limiter) = limiters.get(&kind) {
            RateLimitStatus {
                allowed: true,
                remaining: limiter.window_counter.remaining() as u32,
                limit: limiter.window_counter.limit as u32,
                reset_in: limiter.window_counter.window.as_secs() as u32,
            }
        } else {
            RateLimitStatus {
                allowed: true,
                remaining: self.config.identity.read_limit as u32,
                limit: self.config.identity.read_limit as u32,
                reset_in: self.config.identity.window_secs as u32,
            }
        }
    }

    /// Cleanup old entries (call periodically)
    pub async fn cleanup(&self) {
        let cutoff = Instant::now() - Duration::from_secs(3600); // 1 hour

        // Cleanup IP limiters
        {
            let mut limiters = self.ip_limiters.write().await;
            limiters.retain(|_, kind_limiters| {
                kind_limiters.retain(|_, limiter| {
                    // Keep if has recent activity
                    limiter.window_counter.timestamps.iter().any(|t| *t > cutoff)
                });
                !kind_limiters.is_empty()
            });
        }

        // Cleanup identity limiters
        {
            let mut limiters = self.identity_limiters.write().await;
            limiters.retain(|_, kind_limiters| {
                kind_limiters.retain(|_, limiter| {
                    limiter.window_counter.timestamps.iter().any(|t| *t > cutoff)
                });
                !kind_limiters.is_empty()
            });
        }

        tracing::debug!(
            "Rate limiter cleanup: IP entries={}, Identity entries={}",
            self.ip_limiters.read().await.len(),
            self.identity_limiters.read().await.len()
        );
    }

    /// Reset limits for a specific IP
    pub async fn reset_ip(&self, ip: &str) {
        let mut limiters = self.ip_limiters.write().await;
        if let Some(entry) = limiters.get_mut(ip) {
            for limiter in entry.values_mut() {
                limiter.window_counter.reset();
            }
        }
    }

    /// Reset limits for a specific identity
    pub async fn reset_identity(&self, identity: &str) {
        let mut limiters = self.identity_limiters.write().await;
        if let Some(entry) = limiters.get_mut(identity) {
            for limiter in entry.values_mut() {
                limiter.window_counter.reset();
            }
        }
    }

    /// Get configuration
    pub fn config(&self) -> &RateLimitConfig {
        &self.config
    }
}

/// Rate limit status for API response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStatus {
    pub allowed: bool,
    pub remaining: u32,
    pub limit: u32,
    pub reset_in: u32,
}

/// Rate limit headers for HTTP response
pub struct RateLimitHeaders {
    pub limit: u32,
    pub remaining: u32,
    pub reset: u32,
}

impl RateLimitHeaders {
    pub fn from_result(result: &RateLimitResult, kind: RateLimitKind) -> Option<Self> {
        match result {
            RateLimitResult::Allowed { remaining, reset_in } => {
                let (limit, _) = match kind {
                    RateLimitKind::Read => (100, 0), // Will be overridden
                    RateLimitKind::Write => (10, 0),
                    RateLimitKind::Api => (100, 0),
                    RateLimitKind::Admin => (10, 0),
                };
                Some(Self {
                    limit,
                    remaining: *remaining,
                    reset: *reset_in,
                })
            }
            RateLimitResult::Denied { retry_after, .. } => Some(Self {
                limit: 0,
                remaining: 0,
                reset: retry_after.unwrap_or(60),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_window_counter() {
        let mut counter = WindowCounter::new(Duration::from_secs(60), 3);

        // First 3 requests should succeed
        assert!(counter.try_acquire());
        assert!(counter.try_acquire());
        assert!(counter.try_acquire());

        // 4th request should fail
        assert!(!counter.try_acquire());

        // Should have 0 remaining
        assert_eq!(counter.remaining(), 0);
    }

    #[test]
    fn test_token_bucket() {
        let mut bucket = TokenBucket::new(10.0, 1.0); // 10 tokens, refill 1/sec

        // Consume all tokens
        assert!(bucket.try_consume(5.0));
        assert!(bucket.try_consume(5.0));
        assert!(!bucket.try_consume(1.0)); // Should fail

        // Wait for refill
        std::thread::sleep(Duration::from_millis(1100));
        assert!(bucket.try_consume(1.0));
    }

    #[tokio::test]
    async fn test_rate_limiter_disabled() {
        let config = RateLimitConfig {
            enabled: false,
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let result = limiter.check("192.168.1.1", "user1", RateLimitKind::Read).await;
        assert!(result.is_allowed());
    }

    #[tokio::test]
    async fn test_whitelist() {
        let config = RateLimitConfig {
            enabled: true,
            whitelist: vec!["127.0.0.1".into()],
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        let result = limiter.check_ip("127.0.0.1", RateLimitKind::Read).await;
        assert!(result.is_allowed());

        let result = limiter.check_ip("192.168.1.1", RateLimitKind::Read).await;
        assert!(!result.is_allowed());
    }

    #[tokio::test]
    async fn test_identity_limits() {
        let config = RateLimitConfig {
            enabled: true,
            identity: IdentityRateLimit {
                enabled: true,
                read_limit: 2,
                write_limit: 1,
                window_secs: 60,
                burst: 1,
            },
            ..Default::default()
        };
        let limiter = RateLimiter::new(config);

        // First 2 reads should succeed
        assert!(limiter.check_identity("user1", RateLimitKind::Read).await.is_allowed());
        assert!(limiter.check_identity("user1", RateLimitKind::Read).await.is_allowed());

        // 3rd read should fail
        assert!(!limiter.check_identity("user1", RateLimitKind::Read).await.is_allowed());
    }
}
