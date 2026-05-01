//! BYOK key management — keyring integration and precedence resolution.
//!
//! Provides a layered key resolution chain so Sicario works with any
//! OpenAI-compatible LLM provider without hard-coding credentials.

pub mod cloud_config;
pub mod config_file;
pub mod manager;
pub mod provider_registry;

pub use manager::{
    delete_key_from_keyring, keyring_has_key, resolve_api_key, resolve_endpoint,
    resolve_endpoint_with_source, resolve_key_source_no_network, resolve_model,
    resolve_model_with_source, spawn_local_llm_detection, store_key_in_keyring, ConfigSource,
    KeySource, ResolvedKey, ResolvedValue,
};

pub use provider_registry::{find_provider, AuthStyle, ProviderPreset, PROVIDERS};
