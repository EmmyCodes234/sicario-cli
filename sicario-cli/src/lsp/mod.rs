//! Language Server Protocol module — LSP JSON-RPC over stdin/stdout.
//!
//! Provides real-time security diagnostics to editors via the standard LSP
//! interface. The server scans open documents using the SAST engine and
//! publishes findings as diagnostics with quick-fix code actions.

pub mod server;

pub use server::{discover_rule_paths, SicarioLspServer};
