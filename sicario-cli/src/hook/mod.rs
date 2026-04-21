//! Pre-commit hook management module — install/uninstall/status.

pub mod manager;

pub use manager::{HookManagement, HookManager, HookStatus};
