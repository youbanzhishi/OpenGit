//! OpenGit Storage — Repository storage management
//!
//! Handles bare repo CRUD, compatibility with existing repos,
//! and hooks installation.

pub mod hooks;
pub mod manager;

pub use hooks::HookInstaller;
pub use manager::StorageManager;
