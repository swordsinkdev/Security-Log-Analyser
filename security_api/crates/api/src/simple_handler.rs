//! Simple Mode handler for beginner-friendly log explanations
//!
//! This handler provides a simplified interface for users to paste logs
//! and receive easy-to-understand security analysis with risk scores,
//! threat descriptions, and actionable fixes.

use axum::{
    extract::Json,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use security_analyzer_llm::{LlmAnalyzer, AnalyzerError};
use security_common::parsers::apache::parse_apache_combined;

/// Request payload for simple log explanation
#[derive(Debug, Deserialize)]
pub struct ExplainLogsRequest {
    /// Raw log text pasted by the user
    pub logs: String,
}

/// Simplified threat information for beginners
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleThreat {
    /// Type of threat (e.g., "SQL Injection Attempt")
    #[serde(rename = "type")]
    pub threat_type: String,
    /// Plain English description
    pub description: String,
    /// Severity level (Low, Medium, High, Critical)
    pub severity: String,
}

/// Actionable fix with optional command
#[derive(Debug, Serialize, Deserialize)]
pub struct SimpleFix {
    /// Title of the fix
    pub title: String,
    /// Description of what to do
    pub description: String,
    /// Optional command to execute
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
}

/// Response for simple log explanation
#[derive(Debug, Serialize, Deserialize)]
pub struct ExplainLogsResponse {
    /// Plain English summary of what happened
    pub summary: String,
    /// Risk score from 0-10
    pub risk_score: f32,
    /// List of detected threats
    pub threats: Vec<SimpleThreat>,
    /// List of suggested fixes
    pub fixes: Vec<SimpleFix>,
}

/// Beginner-friendly system prompt for Simple Mode
const SIMPLE_MODE_PROMPT: &str = r#"You are a friendly security expert explaining log analysis to beginners (junior sysadmins, students, small business owners).

Your job is to analyze security logs and explain them in PLAIN ENGLISH without technical jargon.

IMPORTANT: You MUST respond with ONLY valid JSON in this exact format:
{
  "summary": "A 2-3 sentence plain English explanation of what happened in these logs",
  "risk_score": 5.5,
  "threats": [
    {
      "type": "SQL Injection Attempt",
      "description": "Someone tried to trick your database into giving them unauthorized access",
      "severity": "High"
    }
  ],
  "fixes": [
    {
      "title": "Block the attacker's IP address",
      "description": "Prevent this IP from accessing your server",
      "command": "sudo iptables -A INPUT -s 10.0.0.50 -j DROP"
    }
  ]
}

Guidelines:
1. Use simple language - explain like you're talking to a friend
2. Avoid technical terms or explain them simply
3. Risk score: 0-2 (Low), 3-5 (Medium), 6-8 (High), 9-10 (Critical)
4. Focus on what matters - don't overwhelm with details
5. Provide actionable fixes with clear steps
6. If logs look normal, say so! Don't create false alarms

Remember: Output ONLY the JSON, no markdown formatting, no explanations before or after."#;

/// Analyze logs with beginner-friendly explanations
pub async fn explain_logs(
    Json(payload): Json<ExplainLogsRequest>,
) -> impl IntoResponse {
    // Parse the logs with unified parser (supports any log format)
    let mut logs = Vec::new();
    let mut _parse_errors = 0;

    for line in payload.logs.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // Try Apache format first, fall back to generic parsing
        match parse_apache_combined(line) {
            Ok(log) => logs.push(log),
            Err(_) => {
                // Use generic parser to convert any log format to Apache-like structure
                if let Some(entry) = security_common::parsers::parse_log_line_unified(line) {
                    // Convert generic LogEntry to ApacheLog for LLM analysis
                    use security_common::parsers::apache::ApacheLog;
                    use chrono::Utc;
                    
                    let apache_log = ApacheLog {
                        ip: entry.ip_address.clone().unwrap_or_else(|| "unknown".to_string()),
                        timestamp: Utc::now(), // Use current time as fallback
                        method: "GENERIC".to_string(),
                        path: entry.message.clone(),
                        protocol: "LOG/1.0".to_string(),
                        status: match entry.level.as_str() {
                            "CRITICAL" => 500,
                            "ERROR" => 400,
                            "WARN" => 300,
                            _ => 200,
                        },
                        size: 0,
                        referer: "-".to_string(),
                        user_agent: entry.username.clone().unwrap_or_else(|| "-".to_string()),
                        is_suspicious: entry.level == "ERROR" || entry.level == "CRITICAL",
                        threat_type: if entry.level == "CRITICAL" {
                            Some("Critical Alert".to_string())
                        } else if entry.level == "ERROR" {
                            Some("Error Event".to_string())
                        } else {
                            None
                        },
                        severity: Some(entry.level.clone()),
                    };
                    logs.push(apache_log);
                } else {
                    _parse_errors += 1;
                }
            }
        }
    }

    if logs.is_empty() {
        return Json(serde_json::json!({
            "error": "Could not parse any logs. Please paste log entries with timestamps and messages."
        }));
    }

    // Create LLM analyzer
    let analyzer = match LlmAnalyzer::from_env() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("[ERROR] LLM Analyzer configuration error: {}", e);
            return Json(serde_json::json!({
                "error": "LLM service is not configured. Please contact support.",
                "details": format!("{}", e)
            }));
        }
    };

    println!(
        "[INFO] Simple Mode: Analyzing {} logs with {} ({})",
        logs.len(),
        analyzer.provider(),
        analyzer.model()
    );

    // Build simplified prompt
    let log_sample = if logs.len() > 20 {
        &logs[..20]
    } else {
        &logs[..]
    };

    let mut prompt = String::from("Analyze these security logs and explain what's happening:\n\n");
    for log in log_sample {
        prompt.push_str(&format!(
            "{} - {} {} - Status: {}\n",
            log.ip, log.method, log.path, log.status
        ));
    }
    
    if logs.len() > 20 {
        prompt.push_str(&format!("\n... and {} more logs\n", logs.len() - 20));
    }

    prompt.push_str("\nProvide your analysis in the JSON format specified.");

    // Call LLM with simple mode prompt
    let response = match call_llm_simple(&analyzer, &prompt).await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[ERROR] LLM call failed: {}", e);
            return Json(serde_json::json!({
                "error": "Failed to analyze logs. Please try again.",
                "details": format!("{}", e)
            }));
        }
    };

    // Parse LLM response
    match parse_simple_response(&response) {
        Ok(result) => Json(serde_json::to_value(result).unwrap()),
        Err(e) => {
            eprintln!("[ERROR] Failed to parse LLM response: {}", e);
            
            // Fallback response
            Json(serde_json::json!({
                "summary": "We analyzed your logs and found some activity. The AI had trouble formatting the results, but your logs have been processed.",
                "risk_score": 3.0,
                "threats": [],
                "fixes": []
            }))
        }
    }
}

/// Call LLM with simple mode prompt
async fn call_llm_simple(analyzer: &LlmAnalyzer, prompt: &str) -> Result<String, AnalyzerError> {
    // Build the full prompt with system instructions
    let full_prompt = format!("{}\n\n{}", SIMPLE_MODE_PROMPT, prompt);
    
    // Call the LLM using the analyzer's internal methods
    use security_analyzer_llm::LlmProvider;
    
    let response = match analyzer.provider() {
        LlmProvider::OpenAI => {
            use rig::providers::openai;
            use rig::completion::Prompt;
            
            let client = openai::Client::new(&std::env::var("OPENAI_API_KEY")
                .map_err(|_| AnalyzerError::Configuration("OPENAI_API_KEY not set".to_string()))?);
            
            let agent = client
                .agent(analyzer.model())
                .preamble(SIMPLE_MODE_PROMPT)
                .temperature(0.3)
                .max_tokens(2048)
                .build();
            
            agent.prompt(prompt).await
                .map_err(|e| AnalyzerError::ApiError {
                    provider: "OpenAI".to_string(),
                    message: e.to_string(),
                })?
        }
        LlmProvider::Anthropic => {
            use rig::providers::anthropic;
            use rig::completion::Prompt;
            
            let client = anthropic::Client::new(
                &std::env::var("ANTHROPIC_API_KEY")
                    .map_err(|_| AnalyzerError::Configuration("ANTHROPIC_API_KEY not set".to_string()))?,
                "https://api.anthropic.com",
                None,
                "2023-06-01"
            );
            
            let agent = client
                .agent(analyzer.model())
                .preamble(SIMPLE_MODE_PROMPT)
                .temperature(0.3)
                .max_tokens(2048)
                .build();
            
            agent.prompt(prompt).await
                .map_err(|e| AnalyzerError::ApiError {
                    provider: "Anthropic".to_string(),
                    message: e.to_string(),
                })?
        }
        LlmProvider::Groq => {
            use rig::providers::openai;
            use rig::completion::Prompt;
            
            let client = openai::Client::from_url(
                &std::env::var("GROQ_API_KEY")
                    .map_err(|_| AnalyzerError::Configuration("GROQ_API_KEY not set".to_string()))?,
                "https://api.groq.com/openai/v1"
            );
            
            let agent = client
                .agent(analyzer.model())
                .preamble(SIMPLE_MODE_PROMPT)
                .temperature(0.3)
                .max_tokens(2048)
                .build();
            
            agent.prompt(prompt).await
                .map_err(|e| AnalyzerError::ApiError {
                    provider: "Groq".to_string(),
                    message: e.to_string(),
                })?
        }
        LlmProvider::Gemini => {
            let api_key = std::env::var("GEMINI_API_KEY")
                .map_err(|_| AnalyzerError::Configuration("GEMINI_API_KEY not set".to_string()))?;
            let model = analyzer.model();
            
            let url = format!(
                "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
                model, api_key
            );
            
            let request_body = serde_json::json!({
                "contents": [{
                    "parts": [{
                        "text": full_prompt
                    }]
                }],
                "generationConfig": {
                    "temperature": 0.3,
                    "maxOutputTokens": 2048
                }
            });
            
            let client = reqwest::Client::new();
            let response = client
                .post(&url)
                .json(&request_body)
                .send()
                .await
                .map_err(|e| AnalyzerError::ApiError {
                    provider: "Gemini".to_string(),
                    message: format!("HTTP request failed: {}", e),
                })?;
            
            if !response.status().is_success() {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                return Err(AnalyzerError::ApiError {
                    provider: "Gemini".to_string(),
                    message: format!("API returned {}: {}", status, error_text),
                });
            }
            
            let response_json: serde_json::Value = response.json().await
                .map_err(|e| AnalyzerError::ApiError {
                    provider: "Gemini".to_string(),
                    message: format!("Failed to parse response: {}", e),
                })?;
            
            response_json["candidates"][0]["content"]["parts"][0]["text"]
                .as_str()
                .ok_or_else(|| AnalyzerError::ApiError {
                    provider: "Gemini".to_string(),
                    message: "Invalid response format".to_string(),
                })?
                .to_string()
        }
    };
    
    Ok(response)
}

/// Parse the LLM response into structured format
fn parse_simple_response(response: &str) -> Result<ExplainLogsResponse, String> {
    // Try to extract JSON from the response
    let json_str = extract_json(response);
    
    // Parse JSON
    serde_json::from_str::<ExplainLogsResponse>(&json_str)
        .map_err(|e| format!("Failed to parse JSON: {}", e))
}

/// Extract JSON from response (handles markdown code blocks)
fn extract_json(text: &str) -> String {
    // Remove markdown code blocks if present
    let text = text.trim();
    
    if text.starts_with("```json") {
        text.trim_start_matches("```json")
            .trim_end_matches("```")
            .trim()
            .to_string()
    } else if text.starts_with("```") {
        text.trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string()
    } else {
        text.to_string()
    }
}
