// Log Parser Module
// Structured parsers for different log formats

pub mod apache;
pub mod generic;

pub use apache::{ApacheLog, parse_apache_combined};
pub use generic::parse_generic_log;

use crate::LogEntry;

/// Unified log parser that tries multiple formats with fallback
/// 
/// Parsing strategy:
/// 1. Try Apache Combined Log Format (most specific)
/// 2. Try generic structured formats (timestamp + level + message)
/// 3. Fall back to minimal parsing (extract IPs and keywords)
/// 
/// This ensures NO log lines are lost - every line gets analyzed
pub fn parse_log_line_unified(line: &str) -> Option<LogEntry> {
    if line.trim().is_empty() {
        return None;
    }

    // Strategy 1: Try Apache Combined format first
    if let Ok(apache_log) = parse_apache_combined(line) {
        return Some(LogEntry {
            timestamp: apache_log.timestamp.to_rfc3339(),
            level: if apache_log.status >= 500 {
                "CRITICAL".to_string()
            } else if apache_log.status >= 400 {
                "ERROR".to_string()
            } else {
                "INFO".to_string()
            },
            ip_address: Some(apache_log.ip.clone()),
            username: None,
            message: format!(
                "{} {} - Status: {} - {}",
                apache_log.method,
                apache_log.path,
                apache_log.status,
                apache_log.threat_type.as_deref().unwrap_or("Normal")
            ),
        });
    }

    // Strategy 2 & 3: Use generic parser with fallback
    parse_generic_log(line)
}
