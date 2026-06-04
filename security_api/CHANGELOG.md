# Changelog

All notable changes to Logr Security Platform will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-14

### Initial Release

#### Added
- **Three Analysis Modes**
  - Simple Mode: Quick log analysis with paste functionality
  - Standard Analysis: Pattern-based threat detection with CVSS scoring
  - AI-Powered Analysis: LLM-driven threat intelligence

- **Core Features**
  - Multi-format log parsing (Apache, Nginx, common formats)
  - Real-time threat detection and classification
  - CVSS vulnerability scoring
  - IP reputation analysis
  - MITRE ATT&CK technique mapping
  - Comprehensive parsing statistics

- **LLM Integration**
  - Support for Groq (Llama 3.3)
  - Support for Google Gemini
  - Support for OpenAI GPT-4
  - Support for Anthropic Claude
  - Provider health monitoring
  - Configurable model selection

- **Export Functionality**
  - JSON format export (complete data structure)
  - CSV format export (spreadsheet-friendly)
  - TXT format export (human-readable reports)
  - Automatic timestamped filenames

- **User Interface**
  - Modern dark theme design
  - Responsive layout for all devices
  - Interactive help documentation
  - Provider availability indicators
  - Real-time analysis progress
  - Professional footer with social links

- **Backend Architecture**
  - Rust-based Axum web server
  - MySQL database integration
  - RESTful API endpoints
  - Multipart file upload support
  - Environment-based configuration

- **Security Features**
  - API key protection via environment variables
  - Secure database connections
  - Input validation and sanitization
  - CORS configuration

- **Documentation**
  - Comprehensive README with setup instructions
  - API endpoint documentation
  - LLM provider setup guides
  - Configuration examples
  - MIT License

#### Technical Details
- **Backend**: Rust 1.70+, Axum, Tokio
- **Frontend**: Vanilla JavaScript, Modern CSS
- **Database**: MySQL 8.0+
- **Supported Log Formats**: Apache, Nginx, Common Log Format
- **API Endpoints**: 4 core endpoints for analysis and health checks

#### Known Limitations
- Standard Analysis requires file upload (no paste support)
- AI Analysis requires valid API keys
- Database must be manually initialized
- No user authentication system (single-user deployment)

---

## Future Roadmap

### Planned for v1.1.0
- [ ] User authentication and multi-user support
- [ ] Saved analysis history
- [ ] Custom rule creation
- [ ] Scheduled log analysis
- [ ] Email notifications for critical threats
- [ ] Docker containerization
- [ ] API rate limiting

### Planned for v1.2.0
- [ ] Dashboard analytics and metrics
- [ ] Threat trend visualization
- [ ] Integration with SIEM platforms
- [ ] Webhook support for alerts
- [ ] Advanced filtering and search
- [ ] PDF report generation

---

**Logr™** - Advanced Security Log Analysis Platform
