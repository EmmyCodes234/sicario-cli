//! Backward-compatible re-export of the provider-agnostic LLM client.
//!
//! This module is preserved so existing code that references `CerebrasClient`
//! continues to compile. New code should use `LlmClient` directly.

pub use super::llm_client::LlmClient as CerebrasClient;
