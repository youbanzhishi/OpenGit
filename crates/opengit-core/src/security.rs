//! Security module — Input validation, sanitization, and security utilities
//!
//! P9: Security hardening for production use
//!
//! Features:
//! - Input validation and sanitization
//! - Path traversal prevention
//! - Injection attack prevention
//! - Sensitive data masking
//! - Security headers

use std::path::Path;

/// Validate repository name
/// - Only alphanumeric, dash, underscore, dot allowed
/// - Max 100 characters
/// - No leading/trailing dots or dashes
pub fn validate_repo_name(name: &str) -> Result<(), SecurityError> {
    if name.is_empty() {
        return Err(SecurityError::EmptyInput("repository name".into()));
    }

    if name.len() > 100 {
        return Err(SecurityError::InputTooLong {
            field: "repository name".into(),
            max: 100,
            actual: name.len(),
        });
    }

    // Check for invalid characters
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(SecurityError::InvalidCharacters {
            field: "repository name".into(),
            value: name.into(),
            allowed: "alphanumeric, dash, underscore, dot".into(),
        });
    }

    // No leading/trailing dots or dashes
    let chars: Vec<char> = name.chars().collect();
    if chars.first() == Some(&'.') || chars.first() == Some(&'-') {
        return Err(SecurityError::InvalidPrefix {
            field: "repository name".into(),
            char: name.chars().next().unwrap(),
        });
    }
    if chars.last() == Some(&'.') || chars.last() == Some(&'-') {
        return Err(SecurityError::InvalidSuffix {
            field: "repository name".into(),
            char: name.chars().last().unwrap(),
        });
    }

    // Check for dangerous patterns
    let dangerous = ["..", "__", "--", "-.", ".-"];
    for pattern in &dangerous {
        if name.contains(pattern) {
            return Err(SecurityError::DangerousPattern {
                field: "repository name".into(),
                pattern: pattern.to_string(),
            });
        }
    }

    Ok(())
}

/// Validate identity name
pub fn validate_identity_name(name: &str) -> Result<(), SecurityError> {
    if name.is_empty() {
        return Err(SecurityError::EmptyInput("identity name".into()));
    }

    if name.len() > 64 {
        return Err(SecurityError::InputTooLong {
            field: "identity name".into(),
            max: 64,
            actual: name.len(),
        });
    }

    // Only alphanumeric, dash, underscore, at sign for agent identities
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '@')
    {
        return Err(SecurityError::InvalidCharacters {
            field: "identity name".into(),
            value: name.into(),
            allowed: "alphanumeric, dash, underscore, @".into(),
        });
    }

    Ok(())
}

/// Validate file path to prevent path traversal
pub fn validate_repo_path(base: &Path, path: &Path) -> Result<(), SecurityError> {
    // Resolve the path and check it's within base
    let canonical = std::fs::canonicalize(base).map_err(|_| SecurityError::PathNotFound)?;
    let canonical_path = path
        .canonicalize()
        .map_err(|_| SecurityError::PathNotFound)?;

    // Check if the resolved path starts with base
    let canonical_str = canonical_path.to_string_lossy();
    let base_str = canonical.to_string_lossy();

    if !canonical_str.starts_with(&format!("{}/", base_str)) && canonical_str != base_str {
        return Err(SecurityError::PathTraversal {
            requested: path.to_string_lossy().to_string(),
            reason: "path escapes base directory".into(),
        });
    }

    Ok(())
}

/// Sanitize output for logging (mask sensitive data)
pub fn sanitize_for_log(input: &str) -> String {
    let sensitive_patterns = [
        ("token=", "token=***"),
        ("password=", "password=***"),
        ("secret=", "secret=***"),
        ("Authorization: Bearer ", "Authorization: Bearer ***"),
        ("Authorization: Basic ", "Authorization: Basic ***"),
    ];

    let mut output = input.to_string();
    for (pattern, replacement) in &sensitive_patterns {
        output = output.replace(pattern, replacement);
    }

    output
}

/// Mask token for display
pub fn mask_token(token: &str) -> String {
    if token.len() <= 8 {
        return "*".repeat(token.len());
    }

    let prefix = &token[..4];
    let suffix = &token[token.len() - 4..];
    format!("{}...{}", prefix, suffix)
}

/// Check if a string contains potential injection patterns
pub fn contains_injection(s: &str) -> bool {
    let injection_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
        "onclick=",
        "\\x00",
        "\\n",
        "\\r",
    ];

    let lower = s.to_lowercase();
    injection_patterns.iter().any(|p| lower.contains(p))
}

/// Validate URL for webhook or mirror
pub fn validate_url(url: &str) -> Result<(), SecurityError> {
    if url.is_empty() {
        return Err(SecurityError::EmptyInput("URL".into()));
    }

    if url.len() > 2048 {
        return Err(SecurityError::InputTooLong {
            field: "URL".into(),
            max: 2048,
            actual: url.len(),
        });
    }

    // Parse and validate URL
    let parsed = url::Url::parse(url)
        .map_err(|_| SecurityError::InvalidUrl(url.to_string()))?;

    // Only allow HTTP/HTTPS
    match parsed.scheme() {
        "http" | "https" => {}
        "git" | "ssh" => {
            return Err(SecurityError::InvalidUrlScheme {
                url: url.to_string(),
                scheme: parsed.scheme().to_string(),
                allowed: "http, https".to_string(),
            });
        }
        _ => {
            return Err(SecurityError::InvalidUrlScheme {
                url: url.to_string(),
                scheme: parsed.scheme().to_string(),
                allowed: "http, https".to_string(),
            });
        }
    }

    // No credentials in URL
    let username = parsed.username();
    let password = parsed.password();
    if username.is_some_and(|u| !u.is_empty()) || password.is_some_and(|p| !p.is_empty()) {
        return Err(SecurityError::CredentialsInUrl(url.to_string()));
    }

    Ok(())
}

/// Validate Git ref name (branch, tag)
pub fn validate_ref_name(name: &str) -> Result<(), SecurityError> {
    if name.is_empty() {
        return Err(SecurityError::EmptyInput("ref name".into()));
    }

    if name.len() > 255 {
        return Err(SecurityError::InputTooLong {
            field: "ref name".into(),
            max: 255,
            actual: name.len(),
        });
    }

    // Git ref name rules:
    // - No path components (no refs/heads/foo/bar)
    // - No .git or .lock
    // - No special characters
    let dangerous = [".git", ".lock", "..", "/", "\\", "\0", "\n"];
    for pattern in &dangerous {
        if name.contains(pattern) {
            return Err(SecurityError::DangerousPattern {
                field: "ref name".into(),
                pattern: pattern.to_string(),
            });
        }
    }

    // Cannot start or end with /
    if name.starts_with('/') || name.ends_with('/') {
        return Err(SecurityError::InvalidRefFormat {
            name: name.to_string(),
            reason: "cannot start or end with /".into(),
        });
    }

    Ok(())
}

/// Rate limit hint for security events
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    /// Failed authentication attempt
    AuthFailure { identity: String, ip: String },
    /// Rate limit exceeded
    RateLimitExceeded { identity: String, ip: String },
    /// Suspicious pattern detected
    SuspiciousPattern { pattern: String, context: String },
    /// Path traversal attempt
    PathTraversalAttempt { path: String, ip: String },
    /// Injection attempt
    InjectionAttempt { pattern: String, ip: String },
}

impl SecurityEvent {
    /// Get severity level
    pub fn severity(&self) -> SecuritySeverity {
        match self {
            SecurityEvent::AuthFailure { .. } => SecuritySeverity::Warning,
            SecurityEvent::RateLimitExceeded { .. } => SecuritySeverity::Warning,
            SecurityEvent::SuspiciousPattern { .. } => SecuritySeverity::Warning,
            SecurityEvent::PathTraversalAttempt { .. } => SecuritySeverity::Critical,
            SecurityEvent::InjectionAttempt { .. } => SecuritySeverity::Critical,
        }
    }

    /// Get message for logging
    pub fn log_message(&self) -> String {
        match self {
            SecurityEvent::AuthFailure { identity, ip } => {
                format!("Auth failure: identity={}, ip={}", identity, ip)
            }
            SecurityEvent::RateLimitExceeded { identity, ip } => {
                format!("Rate limit exceeded: identity={}, ip={}", identity, ip)
            }
            SecurityEvent::SuspiciousPattern { pattern, context } => {
                format!("Suspicious pattern detected: pattern={}, context={}", pattern, context)
            }
            SecurityEvent::PathTraversalAttempt { path, ip } => {
                format!("Path traversal attempt: path={}, ip={}", path, ip)
            }
            SecurityEvent::InjectionAttempt { pattern, ip } => {
                format!("Injection attempt: pattern={}, ip={}", pattern, ip)
            }
        }
    }
}

/// Security severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecuritySeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecuritySeverity::Info => write!(f, "INFO"),
            SecuritySeverity::Warning => write!(f, "WARNING"),
            SecuritySeverity::Error => write!(f, "ERROR"),
            SecuritySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Security errors
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Empty input for field: {0}")]
    EmptyInput(String),

    #[error("Input too long: {field} max={max} actual={actual}")]
    InputTooLong {
        field: String,
        max: usize,
        actual: usize,
    },

    #[error("Invalid characters in {field}: value={value} allowed={allowed}")]
    InvalidCharacters {
        field: String,
        value: String,
        allowed: String,
    },

    #[error("Invalid prefix in {field}: char={char}")]
    InvalidPrefix { field: String, char: char },

    #[error("Invalid suffix in {field}: char={char}")]
    InvalidSuffix { field: String, char: char },

    #[error("Dangerous pattern in {field}: pattern={pattern}")]
    DangerousPattern { field: String, pattern: String },

    #[error("Path traversal detected: requested={requested} reason={reason}")]
    PathTraversal { requested: String, reason: String },

    #[error("Path not found or inaccessible")]
    PathNotFound,

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("Invalid URL scheme: url={url} scheme={scheme} allowed={allowed}")]
    InvalidUrlScheme { url: String, scheme: String, allowed: String },

    #[error("Credentials embedded in URL (use headers instead): {0}")]
    CredentialsInUrl(String),

    #[error("Invalid ref format: name={name} reason={reason}")]
    InvalidRefFormat { name: String, reason: String },
}

/// Security configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecurityConfig {
    /// Enable security features
    pub enabled: bool,

    /// Enable input validation
    pub validate_input: bool,

    /// Enable path traversal prevention
    pub prevent_path_traversal: bool,

    /// Enable injection detection
    pub detect_injection: bool,

    /// Mask tokens in logs
    pub mask_tokens: bool,

    /// Security event logging level
    pub log_level: String,

    /// Trusted proxies (for X-Forwarded-For)
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            validate_input: true,
            prevent_path_traversal: true,
            detect_injection: true,
            mask_tokens: true,
            log_level: "info".into(),
            trusted_proxies: vec!["127.0.0.1".into(), "::1".into()],
        }
    }
}

/// Security manager for centralized security checks
pub struct SecurityManager {
    config: SecurityConfig,
}

impl SecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        Self { config }
    }

    pub fn from_file(path: &std::path::Path) -> std::io::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: SecurityConfig = toml::from_str(&content)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        Ok(Self::new(config))
    }

    /// Validate all inputs for a request
    pub fn validate_request(&self, repo_name: &str) -> Result<(), SecurityError> {
        if !self.config.enabled || !self.config.validate_input {
            return Ok(());
        }

        validate_repo_name(repo_name)?;
        Ok(())
    }

    /// Log security event with appropriate level
    pub fn log_security_event(&self, event: &SecurityEvent) {
        let severity = event.severity();
        let message = event.log_message();

        match severity {
            SecuritySeverity::Info => tracing::info!("[SECURITY] {}", message),
            SecuritySeverity::Warning => tracing::warn!("[SECURITY] {}", message),
            SecuritySeverity::Error => tracing::error!("[SECURITY] {}", message),
            SecuritySeverity::Critical => tracing::error!("[SECURITY] [CRITICAL] {}", message),
        }
    }

    /// Sanitize log output
    pub fn sanitize_log(&self, input: &str) -> String {
        if self.config.mask_tokens {
            sanitize_for_log(input)
        } else {
            input.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_repo_name() {
        // Valid names
        assert!(validate_repo_name("my-repo").is_ok());
        assert!(validate_repo_name("MyProject").is_ok());
        assert!(validate_repo_name("repo_v2").is_ok());
        assert!(validate_repo_name("api.client").is_ok());

        // Invalid names
        assert!(validate_repo_name("").is_err());
        assert!(validate_repo_name("-starts-with-dash").is_err());
        assert!(validate_repo_name("ends-with-dash-").is_err());
        assert!(validate_repo_name("has space").is_err());
        assert!(validate_repo_name("has/slash").is_err());
        assert!(validate_repo_name("has..dot").is_err());
    }

    #[test]
    fn test_mask_token() {
        assert_eq!(mask_token("short"), "*****");
        assert_eq!(mask_token("abcdefghij"), "abcd...efgh");
        assert_eq!(mask_token("verylongtoken123456"), "very...3456");
    }

    #[test]
    fn test_sanitize_log() {
        let input = "Authorization: Bearer abc123xyz";
        let sanitized = sanitize_for_log(input);
        assert!(sanitized.contains("***"));
        assert!(!sanitized.contains("abc123xyz"));
    }

    #[test]
    fn test_validate_url() {
        // Valid
        assert!(validate_url("https://example.com/webhook").is_ok());
        assert!(validate_url("http://localhost:8080/callback").is_ok());

        // Invalid
        assert!(validate_url("git@github.com:user/repo.git").is_err());
        assert!(validate_url("ssh://git@github.com/repo").is_err());
    }
}
