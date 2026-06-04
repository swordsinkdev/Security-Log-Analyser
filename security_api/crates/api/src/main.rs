use axum::{
    extract::{Multipart, Extension},
    response::{IntoResponse, Json},
    routing::post,
    Router,
};
use tower_http::services::ServeDir;

// Import from workspace crates
use security_common::{
    database::{init_db, test_connection, DbPool},
    cvss,
    AnalysisResult, ThreatStats, IpAnalysis, IpInfo, RiskAssessment, 
    ParsingInfo, ParseError, FormatQuality, LogEntry,
};
use security_analyzer_basic::BasicAnalyzer;

mod llm_handler;
mod simple_handler;

#[tokio::main]
async fn main() {
    // Load environment variables
    dotenv::dotenv().ok();
    
    // Initialize database connection
    println!("Starting Security API Server...");
    let db_pool = match init_db().await {
        Ok(pool) => {
            if let Err(e) = test_connection(&pool).await {
                eprintln!("[ERROR] Database connection test failed: {}", e);
                eprintln!("  Server will run but database features will be unavailable");
            }
            Some(pool)
        }
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            eprintln!("Server will run but database features will be unavailable");
            eprintln!("Check your DATABASE_URL in .env file");
            None
        }
    };
    
    let static_files = ServeDir::new("crates/api/static");
    
    let mut app = Router::new()
        .route("/api/analyze", post(analyze_logs))
        .route("/api/analyze-with-llm", post(llm_handler::analyze_logs_with_llm))
        .route("/api/llm-health", axum::routing::get(llm_handler::llm_health_check))
        .route("/api/explain-logs", post(simple_handler::explain_logs))
        .nest_service("/", static_files);
    
    // Add database pool to app state if available
    if let Some(pool) = db_pool {
        app = app.layer(Extension(pool));
    }
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    
    println!("[INFO] Security API Server running on http://localhost:3000");
    println!("[INFO] Upload logs at: http://localhost:3000");
    println!("[INFO] LLM Analysis: POST /api/analyze-with-llm");
    println!("[INFO] LLM Health:   GET  /api/llm-health");
    
    axum::serve(listener, app).await.unwrap();
}

// Basic analysis endpoint
async fn analyze_logs(
    Extension(db_pool): Extension<DbPool>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let mut content = String::new();
    let mut filename = String::from("unknown");
    
    while let Some(field) = multipart.next_field().await.unwrap() {
        let name = field.name().unwrap_or("").to_string();
        
        if name == "file" {
            filename = field.file_name().unwrap_or("unknown").to_string();
            let data = field.bytes().await.unwrap();
            content = String::from_utf8_lossy(&data).to_string();
        }
    }
    
    // TODO: Save to database with proper NewLogUpload struct
    println!("📝 Processing log file: {}", filename);
    
    // Parse logs and analyze
    let result = process_logs(&content);
    
    println!("✅ Analysis complete");
    
    Json(result)
}

// Process logs with basic analyzer
pub fn process_logs(content: &str) -> AnalysisResult {
    use security_common::parsers::{parse_log_line_unified, parse_apache_combined};
    
    let mut entries = Vec::new();
    let mut total_lines = 0;
    let mut parsed_lines = 0;
    let mut parse_errors: Vec<ParseError> = Vec::new();
    let mut perfect_format = 0;
    let mut alternative_format = 0;
    let mut fallback_format = 0;
    
    // Parse all lines with unified parser (supports multiple formats)
    for line in content.lines() {
        total_lines += 1;
        
        if line.trim().is_empty() {
            continue;
        }
        
        // Try unified parser - supports Apache, generic, and fallback formats
        if let Some(entry) = parse_log_line_unified(line) {
            parsed_lines += 1;
            
            // Track format quality
            if parse_apache_combined(line).is_ok() {
                perfect_format += 1; // Apache format
            } else if entry.timestamp.contains('-') && !entry.level.is_empty() {
                alternative_format += 1; // Generic structured format
            } else {
                fallback_format += 1; // Minimal parsing
            }
            
            entries.push(entry);
        } else if parse_errors.len() < 10 {
            parse_errors.push(ParseError {
                line_number: total_lines,
                line_content: if line.len() > 100 {
                    format!("{}...", &line[..100])
                } else {
                    line.to_string()
                },
                error_type: "Parse failed".to_string(),
                suggestion: "Line was empty or invalid".to_string(),
            });
        }
    }
    
    // Run basic analysis
    let analyzer = BasicAnalyzer::new();
    let analysis = analyzer.analyze(&entries);
    let cvss_scores = analyzer.generate_cvss_scores(&analysis);
    
    // Build IP analysis
    let mut ip_vec: Vec<_> = analysis.ip_frequency.iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(a.1));
    
    let high_risk_ips: Vec<IpInfo> = ip_vec.iter()
        .filter(|(_, count)| **count >= 3)
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: "high".to_string(),
            country: None,
            city: None,
            is_vpn: false,
        })
        .collect();
    
    let all_ips: Vec<IpInfo> = ip_vec.iter()
        .map(|(ip, count)| IpInfo {
            ip: ip.to_string(),
            count: **count,
            risk_level: if **count >= 3 { "high" } else { "low" }.to_string(),
            country: None,
            city: None,
            is_vpn: false,
        })
        .collect();
    
    // Calculate aggregate CVSS
    let total_threats = analysis.failed_logins + analysis.root_attempts + 
                        analysis.suspicious_file_access + analysis.critical_alerts + 
                        analysis.sql_injection_attempts + analysis.port_scanning_attempts + 
                        analysis.malware_detections;
    
    let mut threat_types_for_aggregate = Vec::new();
    if analysis.sql_injection_attempts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::SQLInjection, analysis.sql_injection_attempts));
    }
    if analysis.failed_logins > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::FailedLogin, analysis.failed_logins));
    }
    if analysis.root_attempts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::RootAccess, analysis.root_attempts));
    }
    if analysis.suspicious_file_access > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::SuspiciousFileAccess, analysis.suspicious_file_access));
    }
    if analysis.port_scanning_attempts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::PortScanning, analysis.port_scanning_attempts));
    }
    if analysis.malware_detections > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::Malware, analysis.malware_detections));
    }
    if analysis.critical_alerts > 0 {
        threat_types_for_aggregate.push((cvss::ThreatType::CriticalAlert, analysis.critical_alerts));
    }
    
    let aggregate_cvss = cvss::calculate_aggregate_score(&threat_types_for_aggregate);
    
    let (level, description) = if total_threats > 20 {
        ("CRITICAL", "Immediate action required")
    } else if total_threats > 10 {
        ("HIGH", "Urgent attention needed")
    } else if total_threats > 5 {
        ("MEDIUM", "Review recommended")
    } else {
        ("LOW", "Normal activity")
    };
    
    AnalysisResult {
        threat_statistics: ThreatStats {
            failed_logins: analysis.failed_logins,
            root_attempts: analysis.root_attempts,
            suspicious_file_access: analysis.suspicious_file_access,
            critical_alerts: analysis.critical_alerts,
            sql_injection_attempts: analysis.sql_injection_attempts,
            port_scanning_attempts: analysis.port_scanning_attempts,
            malware_detections: analysis.malware_detections,
            cvss_scores,
        },
        ip_analysis: IpAnalysis {
            high_risk_ips,
            all_ips,
        },
        risk_assessment: RiskAssessment {
            level: level.to_string(),
            total_threats,
            description: description.to_string(),
            cvss_aggregate_score: aggregate_cvss.base_score,
            cvss_severity: aggregate_cvss.severity.as_str().to_string(),
        },
        parsing_info: ParsingInfo {
            total_lines,
            parsed_lines,
            skipped_lines: total_lines - parsed_lines,
            errors: parse_errors,
            format_quality: FormatQuality {
                perfect_format,
                alternative_format,
                fallback_format,
            },
        },
        alerts: Vec::new(),
    }
}

// Simple log parser
fn parse_log_line(line: &str) -> Option<LogEntry> {
    use regex::Regex;
    
    let re = Regex::new(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(\w+)\]\s+(.+)$").ok()?;
    
    if let Some(caps) = re.captures(line) {
        let timestamp = caps.get(1)?.as_str().to_string();
        let level = caps.get(2)?.as_str().to_string();
        let message = caps.get(3)?.as_str().to_string();
        
        // Extract IP if present
        let ip_re = Regex::new(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})").ok()?;
        let ip_address = ip_re.captures(&message)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());
        
        Some(LogEntry {
            timestamp,
            level,
            ip_address,
            username: None,
            message,
        })
    } else {
        None
    }
}
