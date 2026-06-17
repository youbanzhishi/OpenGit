//! OpenGit Core — Policy Engine, Identity, Hook Pipeline, Plugin System, AI Guard
//!
//! The heart of OpenGit: a fine-grained permission model designed for
//! agent-first, human-friendly Git operations.
//!
//! P4: Added plugin system for extensible hook logic.
//! P5: Added mirror system for repository replication.
//! P6: Added external repository import (any Git URL) + Web Dashboard + Agent API.
//! P7: Added AI Guard for code semantic analysis and dangerous operation detection.
//! P7.2: Added smart branch protection based on CI status.
//! P7.3: Added AI audit log for anomaly detection.
//! P7.4: Added token policy for dynamic permission management.
//! P7.5: Added code fingerprint for traceable provenance.

pub mod ai_audit;
pub mod ai_guard;
pub mod audit;
pub mod branch_protection;
pub mod code_fingerprint;
pub mod hook;
pub mod identity;
pub mod import;
pub mod mirror;
pub mod plugin;
pub mod policy;
pub mod performance;
pub mod rate_limiter;
pub mod repository;
pub mod security;
pub mod tls;
pub mod token_policy;
pub mod webhook;

pub use ai_audit::{
    AiAuditor, AiAuditConfig, AlertChannelConfig, AlertDispatcher, AnomalyEvent, AnomalyThresholds,
    AnomalyType, Severity, UserBehaviorBaseline,
};
pub use ai_guard::{
    AiGuard, AiGuardConfig, GuardResult, GuardRule, MatchedRule, Severity as GuardSeverity,
};
pub use audit::{AuditEntry, AuditLog};
pub use branch_protection::{
    BranchProtectionConfig, BranchProtectionStatus, BranchProtector, CiCheck, CiProvider,
    CiResult, CiStatus, CiStatusChecker, GithubActionsProvider, GitlabCiProvider, ProtectionResult,
};
pub use code_fingerprint::{
    CodeFingerprint, EvidenceItem, FingerprintConfig, FingerprintGenerator, FingerprintStore,
    IdentityMatch, TraceResult,
};
pub use hook::{HookContext, HookPipeline, HookResult};
pub use identity::{Identity, IdentityKind, Token};
pub use import::{
    migrate_from_gitea, GiteaClient, GiteaLabel, GiteaMetadata, GiteaMigrateConfig, GiteaMilestone,
    GiteaRelease, GiteaRepo, ImportEngine, ImportRequest, ImportResult, ImportSource,
    MigrationResult,
};
pub use mirror::{
    MirrorError, MirrorManager, MirrorPushContext, MirrorPushResult, MirrorSeverity, MirrorStatus,
    MirrorTarget, MirrorsFile, TargetStatus,
};
pub use performance::{
    CacheStatsSnapshot, ConnectionPoolConfig, PerfConfig, PerfManager, PerfStats,
};
pub use plugin::{HookPlugin, PluginManager, PluginsFile};
pub use policy::{Action, Permission, Policy, PolicyEngine};
pub use rate_limiter::{
    RateLimitConfig, RateLimitHeaders, RateLimitKind, RateLimitResult, RateLimitStatus, RateLimiter,
};
pub use repository::Repository;
pub use security::{
    mask_token, sanitize_for_log, validate_identity_name, validate_ref_name, validate_repo_name,
    validate_repo_path, validate_url, SecurityConfig, SecurityError, SecurityEvent,
    SecurityManager, SecuritySeverity,
};
pub use tls::{
    audit_encryption, generate_self_signed_cert, token_encryption, SecurityHeadersConfig,
    TlsConfig, TlsVersion,
};
pub use token_policy::{
    Consequence, Condition, PolicyRule, TokenLifecycleManager, TokenPolicy, TokenPolicyEngine,
    TokenRotation,
};
pub use webhook::{AlertConfig, AlertDispatcher as MirrorAlertDispatcher, AlertEntry as MirrorAlertEntry, AlertStore};
