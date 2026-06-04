use regex::Regex;
use chrono::{DateTime, Utc, NaiveDateTime};
use crate::LogEntry;

/// Parse any log format with multiple fallback strategies
/// 
/// This parser tries multiple strategies in order:
/// 1. Structured format with timestamp, level, and message
/// 2. Timestamp and message only
/// 3. Minimal parsing (extract IPs and keywords from any text)
pub fn parse_generic_log(line: &str) -> Option<LogEntry> {
    if line.trim().is_empty() {
        return None;
    }

    // Strategy 1: Try structured format (timestamp + level + message)
    if let Some(entry) = try_structured_format(line) {
        return Some(entry);
    }

    // Strategy 2: Try timestamp + message format
    if let Some(entry) = try_timestamp_message_format(line) {
        return Some(entry);
    }

    // Strategy 3: Minimal parsing - extract what we can from any text
    Some(try_minimal_parsing(line))
}

/// Try to parse structured log format: YYYY-MM-DD HH:MM:SS [LEVEL] message
/// Also handles variations like:
/// - 2025-02-20 10:30:45 ERROR message
/// - [2025-02-20 10:30:45] [ERROR] message
/// - 2025/02/20 10:30:45 [ERROR] message
fn try_structured_format(line: &str) -> Option<LogEntry> {
    // Pattern: timestamp [level] message
    // Only match valid log levels: INFO, WARN, ERROR, CRITICAL, DEBUG, TRACE, FATAL, EMERGENCY
    let re = Regex::new(
        r"^[\[\s]*(\d{4}[-/]\d{2}[-/]\d{2}[\sT]+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)[\]\s]*[\[\s]*(INFO|WARN|WARNING|ERROR|CRITICAL|DEBUG|TRACE|FATAL|EMERGENCY|PANIC)[\]\s]+(.+)$"
    ).ok()?;

    if let Some(caps) = re.captures(line) {
        let timestamp = caps.get(1)?.as_str().to_string();
        let level = caps.get(2)?.as_str().to_uppercase();
        let message = caps.get(3)?.as_str().to_string();

        // Normalize WARNING to WARN
        let level = if level == "WARNING" {
            "WARN".to_string()
        } else {
            level
        };

        // Extract IP address if present
        let ip_address = extract_ip_address(&message);
        let username = extract_username(&message);

        return Some(LogEntry {
            timestamp,
            level,
            ip_address,
            username,
            message,
        });
    }

    None
}

/// Try to parse timestamp + message format (no explicit level)
/// Examples:
/// - 2025-02-20 10:30:45 User login failed from 192.168.1.1
/// - [2025-02-20 10:30:45] Connection attempt from 10.0.0.1
fn try_timestamp_message_format(line: &str) -> Option<LogEntry> {
    let re = Regex::new(
        r"^[\[\s]*(\d{4}[-/]\d{2}[-/]\d{2}[\sT]+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)[\]\s]+(.+)$"
    ).ok()?;

    if let Some(caps) = re.captures(line) {
        let timestamp = caps.get(1)?.as_str().to_string();
        let message = caps.get(2)?.as_str().to_string();

        // Infer level from message content
        let level = infer_log_level(&message);
        let ip_address = extract_ip_address(&message);
        let username = extract_username(&message);

        return Some(LogEntry {
            timestamp,
            level,
            ip_address,
            username,
            message,
        });
    }

    None
}

/// Minimal parsing - extract what we can from any text line
/// This ensures NO log lines are lost
fn try_minimal_parsing(line: &str) -> LogEntry {
    let message = line.to_string();
    let level = infer_log_level(&message);
    let ip_address = extract_ip_address(&message);
    let username = extract_username(&message);

    // Use current time as fallback timestamp
    let timestamp = Utc::now().to_rfc3339();

    LogEntry {
        timestamp,
        level,
        ip_address,
        username,
        message,
    }
}

/// Extract IP address from message text
fn extract_ip_address(text: &str) -> Option<String> {
    let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").ok()?;
    ip_re.captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

/// Extract username from message text
fn extract_username(text: &str) -> Option<String> {
    // Common patterns: "user: username", "user=username", "username@", etc.
    let patterns = [
        r"user[:\s=]+([a-zA-Z0-9_-]+)",
        r"username[:\s=]+([a-zA-Z0-9_-]+)",
        r"([a-zA-Z0-9_-]+)@",
        r"login[:\s]+([a-zA-Z0-9_-]+)",
    ];

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text) {
                if let Some(m) = caps.get(1) {
                    let username = m.as_str().to_string();
                    // Filter out common false positives
                    if username != "root" && username.len() > 1 {
                        return Some(username);
                    }
                }
            }
        }
    }

    None
}

/// Infer log level from message content
fn infer_log_level(message: &str) -> String {
    let msg_lower = message.to_lowercase();

    // Critical indicators
    if msg_lower.contains("critical") 
        || msg_lower.contains("fatal") 
        || msg_lower.contains("emergency")
        || msg_lower.contains("panic") {
        return "CRITICAL".to_string();
    }

    // Error indicators
    if msg_lower.contains("error") 
        || msg_lower.contains("fail") 
        || msg_lower.contains("denied")
        || msg_lower.contains("unauthorized")
        || msg_lower.contains("forbidden")
        || msg_lower.contains("invalid")
        || msg_lower.contains("rejected") {
        return "ERROR".to_string();
    }

    // Warning indicators
    if msg_lower.contains("warn") 
        || msg_lower.contains("suspicious")
        || msg_lower.contains("attempt")
        || msg_lower.contains("retry") {
        return "WARN".to_string();
    }

    // Default to INFO
    "INFO".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_structured_format() {
        let line = "2025-02-20 10:30:45 [ERROR] Failed login from 192.168.1.100";
        let entry = parse_generic_log(line).unwrap();
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.ip_address, Some("192.168.1.100".to_string()));
        assert!(entry.message.contains("Failed login"));
    }

    #[test]
    fn test_timestamp_message_format() {
        let line = "2025-02-20 10:30:45 Connection from 10.0.0.1 denied";
        let entry = parse_generic_log(line).unwrap();
        assert_eq!(entry.level, "ERROR"); // Inferred from "denied"
        assert_eq!(entry.ip_address, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_minimal_parsing() {
        let line = "Suspicious activity detected from IP 172.16.0.50";
        let entry = parse_generic_log(line).unwrap();
        assert_eq!(entry.level, "WARN"); // Inferred from "suspicious"
        assert_eq!(entry.ip_address, Some("172.16.0.50".to_string()));
    }

    #[test]
    fn test_syslog_format() {
        let line = "Feb 20 10:30:45 server sshd[1234]: Failed password for user from 192.168.1.1";
        let entry = parse_generic_log(line).unwrap();
        assert_eq!(entry.level, "ERROR"); // Inferred from "Failed"
        assert_eq!(entry.ip_address, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn test_json_like_content() {
        let line = r#"{"timestamp":"2025-02-20T10:30:45Z","level":"ERROR","message":"Authentication failed","ip":"10.0.0.1"}"#;
        let entry = parse_generic_log(line).unwrap();
        assert_eq!(entry.level, "ERROR");
        assert_eq!(entry.ip_address, Some("10.0.0.1".to_string()));
    }

    #[test]
    fn test_empty_line() {
        let line = "   ";
        assert!(parse_generic_log(line).is_none());
    }

    #[test]
    fn test_level_inference() {
        assert_eq!(infer_log_level("Critical system failure"), "CRITICAL");
        assert_eq!(infer_log_level("Error processing request"), "ERROR");
        assert_eq!(infer_log_level("Warning: high memory usage"), "WARN");
        assert_eq!(infer_log_level("User logged in successfully"), "INFO");
    }

    #[test]
    fn test_ip_extraction() {
        assert_eq!(extract_ip_address("Connection from 192.168.1.1"), Some("192.168.1.1".to_string()));
        assert_eq!(extract_ip_address("IP: 10.0.0.50 attempted access"), Some("10.0.0.50".to_string()));
        assert_eq!(extract_ip_address("No IP here"), None);
    }
}
