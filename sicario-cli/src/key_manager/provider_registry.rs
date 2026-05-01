//! Static registry of supported LLM provider presets.
//!
//! Requirements: Req 9.4, 9.5, 9.6, 12.1–12.5

/// Authentication style used by the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStyle {
    /// Standard OpenAI-compatible: `Authorization: Bearer <key>`
    Bearer,
    /// Anthropic native: `x-api-key: <key>`
    XApiKey,
    /// Azure OpenAI: `api-key: <key>` (distinct from Anthropic's `x-api-key`)
    AzureApiKey,
    /// No authentication required (local models)
    None,
}

/// A single LLM provider preset.
#[derive(Debug, Clone)]
pub struct ProviderPreset {
    /// Canonical lowercase name, e.g. `"anthropic"`
    pub name: &'static str,
    /// Base URL (without `/chat/completions` suffix for OpenAI-compat providers)
    pub endpoint: &'static str,
    /// Default model identifier
    pub default_model: &'static str,
    /// Primary API key environment variable name
    pub env_var: &'static str,
    /// Authentication style
    pub auth_style: AuthStyle,
}

/// All 19 supported provider presets.
pub static PROVIDERS: &[ProviderPreset] = &[
    ProviderPreset {
        name: "openai",
        endpoint: "https://api.openai.com/v1",
        default_model: "gpt-4o",
        env_var: "OPENAI_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "anthropic",
        endpoint: "https://api.anthropic.com/v1",
        default_model: "claude-opus-4-5",
        env_var: "ANTHROPIC_API_KEY",
        auth_style: AuthStyle::XApiKey,
    },
    ProviderPreset {
        name: "gemini",
        endpoint: "https://generativelanguage.googleapis.com/v1beta/openai/",
        default_model: "gemini-2.5-pro",
        env_var: "GEMINI_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "azure",
        endpoint: "https://<resource>.openai.azure.com/openai/deployments/<deployment>/",
        default_model: "gpt-4o",
        env_var: "AZURE_OPENAI_API_KEY",
        auth_style: AuthStyle::AzureApiKey,
    },
    ProviderPreset {
        name: "bedrock",
        endpoint: "https://bedrock-runtime.<region>.amazonaws.com",
        default_model: "anthropic.claude-3-5-sonnet",
        env_var: "AWS_ACCESS_KEY_ID",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "deepseek",
        endpoint: "https://api.deepseek.com/v1",
        default_model: "deepseek-chat",
        env_var: "DEEPSEEK_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "groq",
        endpoint: "https://api.groq.com/openai/v1",
        default_model: "llama-3.3-70b-versatile",
        env_var: "GROQ_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "cerebras",
        endpoint: "https://api.cerebras.ai/v1",
        default_model: "llama3.1-70b",
        env_var: "CEREBRAS_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "together",
        endpoint: "https://api.together.xyz/v1",
        default_model: "meta-llama/Llama-3-70b",
        env_var: "TOGETHER_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "fireworks",
        endpoint: "https://api.fireworks.ai/inference/v1",
        default_model: "accounts/fireworks/models/llama-v3p1-70b-instruct",
        env_var: "FIREWORKS_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "openrouter",
        endpoint: "https://openrouter.ai/api/v1",
        default_model: "openai/gpt-4o",
        env_var: "OPENROUTER_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "mistral",
        endpoint: "https://api.mistral.ai/v1",
        default_model: "mistral-large-latest",
        env_var: "MISTRAL_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "ollama",
        endpoint: "http://localhost:11434/v1",
        default_model: "",
        env_var: "",
        auth_style: AuthStyle::None,
    },
    ProviderPreset {
        name: "lmstudio",
        endpoint: "http://localhost:1234/v1",
        default_model: "",
        env_var: "",
        auth_style: AuthStyle::None,
    },
    ProviderPreset {
        name: "xai",
        endpoint: "https://api.x.ai/v1",
        default_model: "grok-3",
        env_var: "XAI_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "perplexity",
        endpoint: "https://api.perplexity.ai",
        default_model: "llama-3.1-sonar-large-128k-online",
        env_var: "PERPLEXITY_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "cohere",
        endpoint: "https://api.cohere.ai/compatibility/v1",
        default_model: "command-r-plus",
        env_var: "COHERE_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "deepinfra",
        endpoint: "https://api.deepinfra.com/v1/openai",
        default_model: "meta-llama/Meta-Llama-3.1-70B-Instruct",
        env_var: "DEEPINFRA_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
    ProviderPreset {
        name: "novita",
        endpoint: "https://api.novita.ai/v3/openai",
        default_model: "meta-llama/llama-3.1-70b-instruct",
        env_var: "NOVITA_API_KEY",
        auth_style: AuthStyle::Bearer,
    },
];

/// Find a provider by name (case-insensitive).
pub fn find_provider(name: &str) -> Option<&'static ProviderPreset> {
    let lower = name.to_lowercase();
    PROVIDERS.iter().find(|p| p.name == lower.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_19_providers_resolve() {
        let names = [
            "openai",
            "anthropic",
            "gemini",
            "azure",
            "bedrock",
            "deepseek",
            "groq",
            "cerebras",
            "together",
            "fireworks",
            "openrouter",
            "mistral",
            "ollama",
            "lmstudio",
            "xai",
            "perplexity",
            "cohere",
            "deepinfra",
            "novita",
        ];
        assert_eq!(names.len(), 19);
        for name in &names {
            assert!(
                find_provider(name).is_some(),
                "provider '{}' not found",
                name
            );
        }
    }

    #[test]
    fn test_case_insensitive_lookup() {
        assert!(find_provider("Anthropic").is_some());
        assert!(find_provider("OPENAI").is_some());
        assert!(find_provider("DeepSeek").is_some());
    }

    #[test]
    fn test_unknown_provider_returns_none() {
        assert!(find_provider("unknown-provider").is_none());
        assert!(find_provider("").is_none());
    }

    #[test]
    fn test_anthropic_uses_x_api_key() {
        let p = find_provider("anthropic").unwrap();
        assert_eq!(p.auth_style, AuthStyle::XApiKey);
    }

    #[test]
    fn test_ollama_uses_no_auth() {
        let p = find_provider("ollama").unwrap();
        assert_eq!(p.auth_style, AuthStyle::None);
    }
}
