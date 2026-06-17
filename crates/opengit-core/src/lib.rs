//! OpenGit Core — Policy Engine, Identity, Hook Pipeline, Plugin System, AI Guard
//!
//! The heart of OpenGit: a fine-grained permission model designed for
//! agent-first, human-friendly Git operations.
//!
//! P4: Added plugin system for extensible hook logic.
//! P5: Added mirror system for repository replication.
//! P6: Added external repository import (any Git URL) + Web Dashboard + Agent API.
//! P7: Added AI Guard for code semantic analysis and dangerous operation detection.

pub mod ai_guard;
pub mod audit;
pub mod hook;
pub mod identity;
pub mod import;
pub mod mirror;
pub mod plugin;
pub mod policy;
pub mod repository;
pub mod webhook;

pub use ai_guard::{
    AiGuard, AiGuardConfig, GuardResult, GuardRule, MatchedRule, Severity,
};
pub use audit::{AuditEntry, AuditLog};
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
pub use plugin::{HookPlugin, PluginManager, PluginsFile};
pub use policy::{Action, Permission, Policy, PolicyEngine};
pub use repository::Repository;
pub use webhook::{AlertConfig, AlertDispatcher, AlertEntry as MirrorAlertEntry, AlertStore};
