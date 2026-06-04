//! Configuration module for LLM provider settings.
//!
//! This module handles loading LLM configuration from environment variables,
//! making it easy to switch providers and models without code changes.
//!
//! # Environment Variables
//!
//! - `LLM_PROVIDER`: The LLM provider to use (openai, anthropic, groq, gemini)
//! - `LLM_MODEL`: The model name to use (provider-specific)
//! - `LLM_TEMPERATURE`: Temperature for generation (0.0 - 1.0, default: 0.3)
//! - `LLM_MAX_TOKENS`: Maximum tokens in response (default: 4096)
//!
//! Provider-specific API keys:
//! - `OPENAI_API_KEY`: OpenAI API key
//! - `ANTHROPIC_API_KEY`: Anthropic API key
//! - `GROQ_API_KEY`: Groq API key
//! - `GEMINI_API_KEY`: Google Gemini API key

use std::env;
use std::fmt;

/// Supported LLM providers
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LlmProvider {
    #[default]
    OpenAI,
    Anthropic,
    Groq,
    Gemini,
}

impl fmt::Display for LlmProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LlmProvider::OpenAI => write!(f, "openai"),
            LlmProvider::Anthropic => write!(f, "anthropic"),
            LlmProvider::Groq => write!(f, "groq"),
            LlmProvider::Gemini => write!(f, "gemini"),
        }
    }
}

impl LlmProvider {
    /// Parse provider from string (case-insensitive)
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "openai" | "gpt" => Some(LlmProvider::OpenAI),
            "anthropic" | "claude" => Some(LlmProvider::Anthropic),
            "groq" | "llama" => Some(LlmProvider::Groq),
            "gemini" | "google" => Some(LlmProvider::Gemini),
            _ => None,
        }
    }

    /// Get the default model for this provider
    pub fn default_model(&self) -> &'static str {
        match self {
            LlmProvider::OpenAI => "gpt-4o",
            LlmProvider::Anthropic => "claude-sonnet-4-20250514",
            LlmProvider::Groq => "llama-3.1-70b-versatile",
            LlmProvider::Gemini => "gemini-1.5-flash",
        }
    }

    /// Get the environment variable name for this provider's API key
    pub fn api_key_env_var(&self) -> &'static str {
        match self {
            LlmProvider::OpenAI => "OPENAI_API_KEY",
            LlmProvider::Anthropic => "ANTHROPIC_API_KEY",
            LlmProvider::Groq => "GROQ_API_KEY",
            LlmProvider::Gemini => "GEMINI_API_KEY",
        }
    }
}

/// LLM configuration loaded from environment variables
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// The LLM provider to use
    pub provider: LlmProvider,
    /// The model name (provider-specific)
    pub model: String,
    /// API key for the selected provider
    pub api_key: String,
    /// Temperature for generation (0.0 - 1.0)
    pub temperature: f32,
    /// Maximum tokens in response
    pub max_tokens: u32,
}

impl LlmConfig {
    /// Load configuration from environment variables
    ///
    /// # Environment Variables
    ///
    /// - `LLM_PROVIDER`: Provider name (default: "openai")
    /// - `LLM_MODEL`: Model name (default: provider-specific)
    /// - `LLM_TEMPERATURE`: Temperature 0.0-1.0 (default: 0.3)
    /// - `LLM_MAX_TOKENS`: Max response tokens (default: 4096)
    /// - Provider-specific API key environment variable
    ///
    /// # Returns
    ///
    /// Returns `Ok(LlmConfig)` if configuration is valid,
    /// or `Err` with a descriptive error message.
    pub fn from_env() -> Result<Self, ConfigError> {
        // Load .env file if present
        dotenv::dotenv().ok();

        // Parse provider
        let provider = match env::var("LLM_PROVIDER") {
            Ok(p) => LlmProvider::from_str(&p)
                .ok_or_else(|| ConfigError::InvalidProvider(p))?,
            Err(_) => LlmProvider::default(),
        };

        // Get model (use provider default if not specified)
        let model = env::var("LLM_MODEL")
            .unwrap_or_else(|_| provider.default_model().to_string());

        // Get API key for the selected provider
        let api_key_var = provider.api_key_env_var();
        let api_key = env::var(api_key_var)
            .map_err(|_| ConfigError::MissingApiKey {
                provider: provider.clone(),
                env_var: api_key_var.to_string(),
            })?;

        if api_key.is_empty() {
            return Err(ConfigError::MissingApiKey {
                provider,
                env_var: api_key_var.to_string(),
            });
        }

        // Parse temperature
        let temperature = env::var("LLM_TEMPERATURE")
            .ok()
            .and_then(|t| t.parse::<f32>().ok())
            .unwrap_or(0.3)
            .clamp(0.0, 1.0);

        // Parse max tokens (default: 4096)
        let max_tokens = env::var("LLM_MAX_TOKENS")
            .ok()
            .and_then(|t| t.parse::<u32>().ok())
            .unwrap_or(4096);

        Ok(Self {
            provider,
            model,
            api_key,
            temperature,
            max_tokens,
        })
    }

    /// Check if the configuration is valid and ready to use
    pub fn is_valid(&self) -> bool {
        !self.api_key.is_empty() && !self.model.is_empty()
    }

    /// Create a configuration with explicit values (useful for testing)
    pub fn new(
        provider: LlmProvider,
        model: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            model: model.into(),
            api_key: api_key.into(),
            temperature: 0.3,
            max_tokens: 4096,
        }
    }

    /// Set the temperature
    pub fn with_temperature(mut self, temperature: f32) -> Self {
        self.temperature = temperature.clamp(0.0, 1.0);
        self
    }

    /// Set the max tokens
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }
}

/// Configuration errors
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// Invalid provider name specified
    InvalidProvider(String),
    /// API key not found for provider
    MissingApiKey {
        provider: LlmProvider,
        env_var: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidProvider(name) => {
                write!(
                    f,
                    "Invalid LLM provider '{}'. Valid options: openai, anthropic, groq, gemini",
                    name
                )
            }
            ConfigError::MissingApiKey { provider, env_var } => {
                write!(
                    f,
                    "API key not found for provider '{}'. Set the {} environment variable.",
                    provider, env_var
                )
            }
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_parsing() {
        assert_eq!(LlmProvider::from_str("openai"), Some(LlmProvider::OpenAI));
        assert_eq!(LlmProvider::from_str("OPENAI"), Some(LlmProvider::OpenAI));
        assert_eq!(LlmProvider::from_str("gpt"), Some(LlmProvider::OpenAI));
        assert_eq!(LlmProvider::from_str("anthropic"), Some(LlmProvider::Anthropic));
        assert_eq!(LlmProvider::from_str("claude"), Some(LlmProvider::Anthropic));
        assert_eq!(LlmProvider::from_str("groq"), Some(LlmProvider::Groq));
        assert_eq!(LlmProvider::from_str("gemini"), Some(LlmProvider::Gemini));
        assert_eq!(LlmProvider::from_str("invalid"), None);
    }

    #[test]
    fn test_default_models() {
        assert_eq!(LlmProvider::OpenAI.default_model(), "gpt-4o");
        assert_eq!(LlmProvider::Anthropic.default_model(), "claude-sonnet-4-20250514");
        assert_eq!(LlmProvider::Groq.default_model(), "llama-3.1-70b-versatile");
    }

    #[test]
    fn test_api_key_env_vars() {
        assert_eq!(LlmProvider::OpenAI.api_key_env_var(), "OPENAI_API_KEY");
        assert_eq!(LlmProvider::Anthropic.api_key_env_var(), "ANTHROPIC_API_KEY");
        assert_eq!(LlmProvider::Groq.api_key_env_var(), "GROQ_API_KEY");
    }

    #[test]
    fn test_config_builder() {
        let config = LlmConfig::new(LlmProvider::OpenAI, "gpt-4", "test-key")
            .with_temperature(0.7)
            .with_max_tokens(2000);

        assert_eq!(config.provider, LlmProvider::OpenAI);
        assert_eq!(config.model, "gpt-4");
        assert_eq!(config.api_key, "test-key");
        assert_eq!(config.temperature, 0.7);
        assert_eq!(config.max_tokens, 2000);
    }

    #[test]
    fn test_temperature_clamping() {
        let config = LlmConfig::new(LlmProvider::OpenAI, "gpt-4", "key")
            .with_temperature(1.5);
        assert_eq!(config.temperature, 1.0);

        let config = LlmConfig::new(LlmProvider::OpenAI, "gpt-4", "key")
            .with_temperature(-0.5);
        assert_eq!(config.temperature, 0.0);
    }
}
