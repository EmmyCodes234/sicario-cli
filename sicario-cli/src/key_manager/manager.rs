//! API key resolution with layered precedence.
//!
//! Resolution order:
//!   1. `SICARIO_LLM_API_KEY` env var (highest priority — explicit Sicario config)
//!   2. OS keyring via `keyring` crate (set by `sicario config set-key`)
//!   3. `OPENAI_API_KEY` env var (de facto standard — most devs already have this)
//!   4. `CEREBRAS_API_KEY` env var (backward compatibility)
//!
//! Requirements: 20.1–20.8

use anyhow::{anyhow, Result};

const KEYRING_SERVICE: &str = "sicario-cli";
const KEYRING_USER: &str = "llm-api-key";

/// Describes where the resolved key came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySource {
    EnvSicario,
    Keyring,
    EnvOpenAi,
    EnvCerebras,
    None,
}

impl KeySource {
    pub fn label(&self) -> &'static str {
        match self {
            Self::EnvSicario => "SICARIO_LLM_API_KEY",
            Self::Keyring => "OS keyring",
            Self::EnvOpenAi => "OPENAI_API_KEY",
            Self::EnvCerebras => "CEREBRAS_API_KEY",
            Self::None => "not configured",
        }
    }
}

/// Result of key resolution — the key value and where it came from.
#[derive(Debug, Clone)]
pub struct ResolvedKey {
    pub key: String,
    pub source: KeySource,
}

/// Resolve the LLM API key using the precedence chain.
pub fn resolve_api_key() -> Option<ResolvedKey> {
    // 1. SICARIO_LLM_API_KEY
    if let Ok(key) = std::env::var("SICARIO_LLM_API_KEY") {
        if !key.is_empty() {
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvSicario,
            });
        }
    }

    // 2. OS keyring
    if let Some(key) = read_keyring() {
        return Some(ResolvedKey {
            key,
            source: KeySource::Keyring,
        });
    }

    // 3. OPENAI_API_KEY (de facto standard)
    if let Ok(key) = std::env::var("OPENAI_API_KEY") {
        if !key.is_empty() {
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvOpenAi,
            });
        }
    }

    // 4. CEREBRAS_API_KEY (backward compat)
    if let Ok(key) = std::env::var("CEREBRAS_API_KEY") {
        if !key.is_empty() {
            return Some(ResolvedKey {
                key,
                source: KeySource::EnvCerebras,
            });
        }
    }

    None
}

/// Resolve the LLM endpoint URL.
///
/// Precedence:
///   1. `SICARIO_LLM_ENDPOINT` env var
///   2. `OPENAI_BASE_URL` env var (standard for OpenAI-compatible tools)
///   3. `CEREBRAS_ENDPOINT` env var (backward compat)
///   4. Default: OpenAI API
pub fn resolve_endpoint() -> String {
    if let Ok(ep) = std::env::var("SICARIO_LLM_ENDPOINT") {
        if !ep.is_empty() {
            return ep;
        }
    }
    if let Ok(ep) = std::env::var("OPENAI_BASE_URL") {
        if !ep.is_empty() {
            // OPENAI_BASE_URL is typically just the base (e.g. http://localhost:11434/v1)
            // Append /chat/completions if not already present
            return if ep.ends_with("/chat/completions") {
                ep
            } else {
                format!("{}/chat/completions", ep.trim_end_matches('/'))
            };
        }
    }
    if let Ok(ep) = std::env::var("CEREBRAS_ENDPOINT") {
        if !ep.is_empty() {
            return ep;
        }
    }
    "https://api.openai.com/v1/chat/completions".to_string()
}

/// Resolve the LLM model name.
///
/// Precedence:
///   1. `SICARIO_LLM_MODEL` env var
///   2. `CEREBRAS_MODEL` env var (backward compat)
///   3. Default: `gpt-4o-mini`
pub fn resolve_model() -> String {
    if let Ok(m) = std::env::var("SICARIO_LLM_MODEL") {
        if !m.is_empty() {
            return m;
        }
    }
    if let Ok(m) = std::env::var("CEREBRAS_MODEL") {
        if !m.is_empty() {
            return m;
        }
    }
    "gpt-4o-mini".to_string()
}

// ── Keyring operations ────────────────────────────────────────────────────────

fn read_keyring() -> Option<String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER).ok()?;
    entry.get_password().ok()
}

/// Store an API key in the OS keyring.
pub fn store_key_in_keyring(key: &str) -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| anyhow!("Failed to access keyring: {e}"))?;
    entry
        .set_password(key)
        .map_err(|e| anyhow!("Failed to store key in keyring: {e}"))
}

/// Delete the API key from the OS keyring.
pub fn delete_key_from_keyring() -> Result<()> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, KEYRING_USER)
        .map_err(|e| anyhow!("Failed to access keyring: {e}"))?;
    entry
        .delete_password()
        .map_err(|e| anyhow!("Failed to delete key from keyring: {e}"))
}

/// Check whether a key exists in the OS keyring (without revealing it).
pub fn keyring_has_key() -> bool {
    read_keyring().is_some()
}
