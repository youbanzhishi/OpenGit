//! OpenGit Core — Policy Engine, Identity, and Hook Pipeline
//!
//! The heart of OpenGit: a fine-grained permission model designed for
//! agent-first, human-friendly Git operations.
//!
//! P4: Added plugin system for extensible hook logic.

pub mod audit;
pub mod hook;
pub mod identity;
pub mod plugin;
pub mod policy;
pub mod repository;

pub use audit::{AuditEntry, AuditLog};
pub use hook::{HookContext, HookPipeline, HookResult};
pub use identity::{Identity, IdentityKind, Token};
pub use plugin::{HookPlugin, PluginManager, PluginsFile};
pub use policy::{Action, Permission, Policy, PolicyEngine};
pub use repository::Repository;
