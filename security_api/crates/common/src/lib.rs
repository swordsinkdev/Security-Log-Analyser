// Common library for security log analysis
// Contains shared models, parsers, CVSS scoring, and database integration

pub mod cvss;
pub mod parsers;
pub mod database;

use serde::{Deserialize, Serialize};

/// Log entry parsed from security logs
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub ip_address: Option<String>,
    pub username: Option<String>,
    pub message: String,
}

/// Complete analysis result returned to API
#[derive(Serialize)]
pub struct AnalysisResult {
    pub threat_statistics: ThreatStats,
    pub ip_analysis: IpAnalysis,
    pub risk_assessment: RiskAssessment,
    pub parsing_info: ParsingInfo,
    pub alerts: Vec<Alert>,
}

/// Information about log parsing quality
#[derive(Serialize)]
pub struct ParsingInfo {
    pub total_lines: usize,
    pub parsed_lines: usize,
    pub skipped_lines: usize,
    pub errors: Vec<ParseError>,
    pub format_quality: FormatQuality,
}

/// Quality metrics for different log formats
#[derive(Serialize)]
pub struct FormatQuality {
    pub perfect_format: usize,      // Format 1 (standard)
    pub alternative_format: usize,  // Formats 2-6 (valid alternatives)
    pub fallback_format: usize,     // Format 7+ (no timestamp/minimal structure)
}

/// Parse error details
#[derive(Serialize)]
pub struct ParseError {
    pub line_number: usize,
    pub line_content: String,
    pub error_type: String,
    pub suggestion: String,
}

/// Threat statistics with CVSS scores
#[derive(Serialize)]
pub struct ThreatStats {
    pub failed_logins: usize,
    pub root_attempts: usize,
    pub suspicious_file_access: usize,
    pub critical_alerts: usize,
    pub sql_injection_attempts: usize,
    pub port_scanning_attempts: usize,
    pub malware_detections: usize,
    pub cvss_scores: Vec<ThreatCVSS>,
}

/// CVSS score for a specific threat type
#[derive(Serialize, Clone)]
pub struct ThreatCVSS {
    pub threat_type: String,
    pub count: usize,
    #[serde(rename = "base_score")]
    pub cvss_score: f32,
    pub severity: String,
    pub vector_string: String,
    pub explanation: String,
}

/// IP address analysis results
#[derive(Serialize)]
pub struct IpAnalysis {
    pub high_risk_ips: Vec<IpInfo>,
    pub all_ips: Vec<IpInfo>,
}

/// Information about a specific IP address
#[derive(Serialize, Clone)]
pub struct IpInfo {
    pub ip: String,
    pub count: usize,
    pub risk_level: String,
    pub country: Option<String>,
    pub city: Option<String>,
    pub is_vpn: bool,
}

/// Geolocation data
#[derive(Serialize, Deserialize)]
pub struct GeoLocation {
    pub country: String,
    pub city: String,
    pub region: String,
    pub timezone: String,
}

/// Security alert
#[derive(Serialize, Deserialize, Clone)]
pub struct Alert {
    pub id: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub timestamp: String,
    pub ip_address: Option<String>,
    pub triggered_by: String,
}

/// Alert rule configuration
#[derive(Serialize)]
pub struct AlertRule {
    pub name: String,
    pub condition: String,
    pub threshold: usize,
    pub timeframe_minutes: u32,
    pub severity: String,
}

/// Overall risk assessment
#[derive(Serialize)]
pub struct RiskAssessment {
    pub level: String,
    pub total_threats: usize,
    pub description: String,
    pub cvss_aggregate_score: f32,
    pub cvss_severity: String,
}
