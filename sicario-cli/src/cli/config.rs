//! Config subcommand arguments.

use clap::{Parser, Subcommand};

/// Manage Sicario configuration and API keys.
#[derive(Parser, Debug)]
pub struct ConfigCommand {
    #[command(subcommand)]
    pub action: ConfigAction,
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Set the LLM API key (stored in OS credential store)
    SetKey,
    /// Set the LLM provider by name (e.g. anthropic, openai, groq, ollama).
    ///
    /// Sets llm_endpoint and llm_model in ~/.sicario/config.toml.
    /// Run `sicario config show` to see all 19 supported providers.
    ///
    /// Examples:
    ///   sicario config set-provider anthropic
    ///   sicario config set-provider groq
    ///   sicario config set-provider ollama
    SetProvider(SetProviderArgs),
    /// Set a configuration value in ~/.sicario/config.toml
    ///
    /// Valid keys: ANTHROPIC_API_KEY, OPENAI_API_KEY, llm_endpoint, llm_model
    ///
    /// Examples:
    ///   sicario config set ANTHROPIC_API_KEY sk-ant-...
    ///   sicario config set OPENAI_API_KEY sk-...
    ///   sicario config set llm_model claude-3-5-sonnet-20241022
    Set(SetArgs),
    /// Show current configuration and all supported providers
    Show,
    /// Delete the stored API key
    DeleteKey,
    /// Test connectivity to the configured LLM provider
    Test,
}

/// Arguments for `config set-provider`.
///
/// Accepts either a provider name (looked up from the registry) or explicit
/// `--endpoint` / `--model` flags for custom providers.
#[derive(Parser, Debug)]
pub struct SetProviderArgs {
    /// Provider name (e.g. anthropic, openai, groq, ollama).
    /// Run `sicario config show` to see all 19 supported providers.
    /// If omitted, --endpoint must be provided.
    #[arg(value_name = "NAME")]
    pub name: Option<String>,

    /// LLM API endpoint URL (overrides the preset endpoint for the named provider)
    #[arg(long)]
    pub endpoint: Option<String>,

    /// LLM model name (overrides the preset default model)
    #[arg(long)]
    pub model: Option<String>,
}

/// Arguments for `config set <KEY> <VALUE>`.
#[derive(Parser, Debug)]
pub struct SetArgs {
    /// Configuration key to set.
    /// Valid keys: ANTHROPIC_API_KEY, OPENAI_API_KEY, llm_endpoint, llm_model
    pub key: String,

    /// Value to assign to the key.
    pub value: String,
}
