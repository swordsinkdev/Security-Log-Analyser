//! Multi-provider LLM analyzer for security log analysis.
//!
//! This module provides the main `LlmAnalyzer` struct that uses rig-core
//! to interact with multiple LLM providers (OpenAI, Anthropic, Groq, etc.)
//! for intelligent security log analysis.

use crate::config::{LlmConfig, LlmProvider};
use crate::prompts::{build_analysis_prompt, SYSTEM_PROMPT};
use crate::report::SecurityReport;
use crate::error::AnalyzerError;
use security_common::parsers::ApacheLog;

use rig::providers::{anthropic, openai};
use rig::completion::Prompt;

/// Maximum number of logs to include in a single analysis prompt
const MAX_LOGS_PER_ANALYSIS: usize = 100;

/// Multi-provider LLM analyzer for security log analysis
pub struct LlmAnalyzer {
    config: LlmConfig,
}

impl LlmAnalyzer {
    /// Create a new analyzer with configuration loaded from environment variables
    ///
    /// # Environment Variables
    ///
    /// - `LLM_PROVIDER`: openai, anthropic, groq, gemini (default: openai)
    /// - `LLM_MODEL`: Model name (default: provider-specific)
    /// - `LLM_TEMPERATURE`: 0.0-1.0 (default: 0.3)
    /// - `LLM_MAX_TOKENS`: Max response tokens (default: 4096)
    /// - Provider-specific API key (e.g., `OPENAI_API_KEY`)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use security_analyzer_llm::LlmAnalyzer;
    ///
    /// let analyzer = LlmAnalyzer::from_env()?;
    /// let report = analyzer.analyze_logs(logs).await?;
    /// ```
    pub fn from_env() -> Result<Self, AnalyzerError> {
        let config = LlmConfig::from_env()
            .map_err(|e| AnalyzerError::Configuration(e.to_string()))?;
        Ok(Self { config })
    }

    /// Create a new analyzer with explicit configuration
    pub fn with_config(config: LlmConfig) -> Self {
        Self { config }
    }

    /// Check if the analyzer is properly configured and ready to use
    pub fn is_configured(&self) -> bool {
        self.config.is_valid()
    }

    /// Get the current provider name
    pub fn provider(&self) -> &LlmProvider {
        &self.config.provider
    }

    /// Get the current model name
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Analyze security logs using the configured LLM provider
    ///
    /// # Arguments
    ///
    /// * `logs` - A slice of parsed Apache logs to analyze
    ///
    /// # Returns
    ///
    /// Returns a `SecurityReport` containing threat analysis, IOCs,
    /// MITRE ATT&CK mappings, and recommendations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The analyzer is not properly configured
    /// - The LLM API call fails
    /// - The response cannot be parsed
    pub async fn analyze_logs(&self, logs: &[ApacheLog]) -> Result<SecurityReport, AnalyzerError> {
        if !self.is_configured() {
            return Err(AnalyzerError::Configuration(format!(
                "Analyzer not configured. Set {} environment variable.",
                self.config.provider.api_key_env_var()
            )));
        }

        if logs.is_empty() {
            return Ok(SecurityReport::empty());
        }

        // Build the analysis prompt
        let prompt = build_analysis_prompt(logs, MAX_LOGS_PER_ANALYSIS);

        // Call the appropriate provider
        let response = match self.config.provider {
            LlmProvider::OpenAI => self.call_openai(&prompt).await?,
            LlmProvider::Anthropic => self.call_anthropic(&prompt).await?,
            LlmProvider::Groq => self.call_groq(&prompt).await?,
            LlmProvider::Gemini => self.call_gemini(&prompt).await?,
        };

        // Parse the response into a SecurityReport
        self.parse_response(&response, logs.len())
    }

    /// Call OpenAI API using rig-core
    async fn call_openai(&self, prompt: &str) -> Result<String, AnalyzerError> {
        let client = openai::Client::new(&self.config.api_key);
        
        let agent = client
            .agent(&self.config.model)
            .preamble(SYSTEM_PROMPT)
            .temperature(self.config.temperature as f64)
            .max_tokens(self.config.max_tokens as u64)
            .build();

        agent
            .prompt(prompt)
            .await
            .map_err(|e| AnalyzerError::ApiError {
                provider: "OpenAI".to_string(),
                message: e.to_string(),
            })
    }

    /// Call Anthropic API using rig-core
    async fn call_anthropic(&self, prompt: &str) -> Result<String, AnalyzerError> {
        let client = anthropic::Client::new(
            &self.config.api_key,
            "https://api.anthropic.com",
            None,
            "2023-06-01"
        );
        
        let agent = client
            .agent(&self.config.model)
            .preamble(SYSTEM_PROMPT)
            .temperature(self.config.temperature as f64)
            .max_tokens(self.config.max_tokens as u64)
            .build();

        agent
            .prompt(prompt)
            .await
            .map_err(|e| AnalyzerError::ApiError {
                provider: "Anthropic".to_string(),
                message: e.to_string(),
            })
    }

    /// Call Groq API (OpenAI-compatible) using rig-core
    async fn call_groq(&self, prompt: &str) -> Result<String, AnalyzerError> {
        // Groq uses OpenAI-compatible API with custom base URL
        let client = openai::Client::from_url(
            &self.config.api_key,
            "https://api.groq.com/openai/v1"
        );
        
        let agent = client
            .agent(&self.config.model)
            .preamble(SYSTEM_PROMPT)
            .temperature(self.config.temperature as f64)
            .max_tokens(self.config.max_tokens as u64)
            .build();

        agent
            .prompt(prompt)
            .await
            .map_err(|e| AnalyzerError::ApiError {
                provider: "Groq".to_string(),
                message: e.to_string(),
            })
    }

    /// Call Gemini API using direct HTTP calls
    async fn call_gemini(&self, prompt: &str) -> Result<String, AnalyzerError> {
        // Gemini API endpoint - use v1beta for newer models
        let url = format!(
            "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
            self.config.model, self.config.api_key
        );

        // Build request body
        let request_body = serde_json::json!({
            "contents": [{
                "parts": [{
                    "text": format!("{}\n\n{}", SYSTEM_PROMPT, prompt)
                }]
            }],
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
            }
        });

        // Make API call
        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| AnalyzerError::ApiError {
                provider: "Gemini".to_string(),
                message: format!("Failed to call Gemini API: {}", e),
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AnalyzerError::ApiError {
                provider: "Gemini".to_string(),
                message: format!("Gemini API error ({}): {}", status, error_text),
            });
        }

        // Parse response
        let response_json: serde_json::Value = response.json().await.map_err(|e| {
            AnalyzerError::ApiError {
                provider: "Gemini".to_string(),
                message: format!("Failed to parse Gemini response: {}", e),
            }
        })?;

        // Extract text from response
        let text = response_json["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .ok_or_else(|| AnalyzerError::ApiError {
                provider: "Gemini".to_string(),
                message: "Failed to extract text from Gemini response".to_string(),
            })?;

        Ok(text.to_string())
    }

    /// Parse the LLM response into a SecurityReport
    fn parse_response(&self, response: &str, total_logs: usize) -> Result<SecurityReport, AnalyzerError> {
        // Try to parse as JSON directly
        if let Ok(report) = serde_json::from_str::<SecurityReport>(response) {
            return Ok(report);
        }

        // Try to extract JSON from markdown code blocks
        let json_str = self.extract_json_from_response(response);
        
        if let Ok(report) = serde_json::from_str::<SecurityReport>(&json_str) {
            return Ok(report);
        }

        // If parsing fails, create a fallback report with the raw response
        Ok(SecurityReport::fallback(response, total_logs))
    }

    /// Extract JSON from a response that may contain markdown code blocks
    fn extract_json_from_response(&self, response: &str) -> String {
        // Try ```json ... ``` blocks
        if let Some(json_block) = self.extract_code_block(response, "```json") {
            return json_block;
        }

        // Try generic ``` ... ``` blocks
        if let Some(json_block) = self.extract_code_block(response, "```") {
            return json_block;
        }

        // Try to find raw JSON object
        if let Some(start) = response.find('{') {
            if let Some(end) = response.rfind('}') {
                if end > start {
                    return response[start..=end].to_string();
                }
            }
        }

        response.to_string()
    }

    /// Extract content from a markdown code block
    fn extract_code_block(&self, text: &str, delimiter: &str) -> Option<String> {
        let parts: Vec<&str> = text.split(delimiter).collect();
        if parts.len() >= 3 {
            let content = parts[1].trim();
            // Handle ```json case where first line might be the language identifier
            let content = if content.starts_with("json") || content.starts_with('\n') {
                content
                    .lines()
                    .skip_while(|line| line.trim() == "json" || line.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join("\n")
            } else {
                content.to_string()
            };
            Some(content)
        } else {
            None
        }
    }
}

impl Default for LlmAnalyzer {
    fn default() -> Self {
        Self::from_env().unwrap_or_else(|_| {
            Self {
                config: LlmConfig::new(
                    LlmProvider::OpenAI,
                    "gpt-4o",
                    String::new(),
                ),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_default() {
        let analyzer = LlmAnalyzer::default();
        // Will not be configured without env vars
        assert!(!analyzer.is_configured() || analyzer.config.api_key.is_empty() == false);
    }

    #[test]
    fn test_extract_json_from_code_block() {
        let analyzer = LlmAnalyzer::default();
        
        let response = r#"Here is the analysis:
```json
{"threat_level": "High", "summary": "Test"}
```
"#;
        
        let json = analyzer.extract_json_from_response(response);
        assert!(json.contains("threat_level"));
        assert!(json.contains("High"));
    }

    #[test]
    fn test_extract_raw_json() {
        let analyzer = LlmAnalyzer::default();
        
        let response = r#"Some text before {"threat_level": "Low"} some text after"#;
        
        let json = analyzer.extract_json_from_response(response);
        assert_eq!(json, r#"{"threat_level": "Low"}"#);
    }

    #[test]
    fn test_provider_info() {
        let config = LlmConfig::new(LlmProvider::Anthropic, "claude-3-opus", "test-key");
        let analyzer = LlmAnalyzer::with_config(config);
        
        assert_eq!(*analyzer.provider(), LlmProvider::Anthropic);
        assert_eq!(analyzer.model(), "claude-3-opus");
    }
}