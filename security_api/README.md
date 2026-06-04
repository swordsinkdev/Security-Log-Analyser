# Logr — Security Log Analysis Platform

[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-active-success.svg)]()

Advanced security log analysis platform powered by AI and traditional threat detection. Analyze Apache, Nginx, and other log formats with real-time threat intelligence, CVSS scoring, and comprehensive reporting.

![Logr Platform](https://img.shields.io/badge/Platform-Security%20Analysis-cyan)

## Features

### **Three Analysis Modes**

1. **Simple Mode**
   - Paste logs directly for instant analysis
   - Beginner-friendly interface
   - Risk scoring and threat identification
   - Actionable security fixes

2. **Standard Analysis**
   - Pattern-based threat detection
   - CVSS vulnerability scoring
   - IP reputation analysis
   - Parsing statistics
   - No API keys required

3. **AI-Powered Analysis**
   - LLM-driven threat intelligence
   - Contextual security insights
   - MITRE ATT&CK technique mapping
   - Natural language explanations
   - Supports multiple LLM providers

### **Key Capabilities**

- **Multi-Format Support**: Apache, Nginx, and common log formats
- **Real-time Analysis**: Instant threat detection and classification
- **Export Options**: JSON, CSV, and formatted text reports
- **LLM Integration**: Groq (free), Gemini, OpenAI, Anthropic
- **CVSS Scoring**: Industry-standard vulnerability assessment
- **IP Reputation**: Cross-reference with threat databases
- **MITRE ATT&CK**: Map threats to attack techniques
- **Modern UI**: Dark theme, responsive design

## Architecture

```
security_api/
├── crates/
│   ├── api/              # Axum web server & REST API
│   ├── analyzer-basic/   # Pattern-based threat detection
│   ├── analyzer-llm/     # LLM integration layer
│   ├── common/           # Shared types & log parsers
│   └── db/              # Database models & queries
├── database/            # MySQL schema & migrations
└── .env.example        # Configuration template
```

**Tech Stack:**
- **Backend**: Rust, Axum, Tokio
- **Frontend**: Vanilla JS, Modern CSS
- **Database**: MySQL
- **LLMs**: Groq, Gemini, OpenAI, Anthropic

## Installation

### Prerequisites

- **Rust** 1.70+ ([Install](https://rustup.rs/))
- **MySQL** 8.0+ ([Install](https://dev.mysql.com/downloads/))
- **LLM API Keys** (optional, for AI analysis):
  - [Groq](https://console.groq.com) (Free)
  - [Google Gemini](https://ai.google.dev/)

### Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/security-log-analyzer.git
   cd security-log-analyzer
   ```

2. **Set up the database**
   ```bash
   # Create MySQL database
   mysql -u root -p < database/schema.sql
   ```

3. **Configure environment**
   ```bash
   # Copy example config
   cp .env.example .env
   
   # Edit .env with your settings
   nano .env
   ```

4. **Build and run**
   ```bash
   # Development mode
   cargo run -p security-api
   
   # Production mode (optimized)
   cargo run -p security-api --release
   ```

5. **Access the platform**
   ```
   Open http://localhost:3000 in your browser
   ```

## Configuration

Edit `.env` file:

```bash
# Database
DATABASE_URL=mysql://root:password@localhost:3306/security_LogsDB

# LLM Provider (groq, gemini, openai, anthropic)
LLM_PROVIDER=groq
LLM_MODEL=llama-3.3-70b-versatile

# API Keys (get from respective providers)
GROQ_API_KEY=your_groq_key_here
GEMINI_API_KEY=your_gemini_key_here
OPENAI_API_KEY=your_openai_key_here
ANTHROPIC_API_KEY=your_anthropic_key_here
```

### LLM Provider Setup

- **Groq** (Recommended - Free): [Get API Key](https://console.groq.com)
- **Gemini**: [Get API Key](https://ai.google.dev/)
- **OpenAI**: [Get API Key](https://platform.openai.com/)
- **Anthropic**: [Get API Key](https://console.anthropic.com/)

## Usage

### Simple Mode
1. Navigate to "Simple Mode"
2. Paste your logs or generate sample logs
3. Click "Analyze Logs"
4. View threats, risk score, and recommended fixes
5. Export results in JSON, CSV, or TXT format

### Standard Analysis
1. Navigate to "Advanced Mode" → "Standard Analysis"
2. Upload log file (.log or .txt)
3. View comprehensive threat analysis
4. Export detailed reports

### AI-Powered Analysis
1. Navigate to "Advanced Mode" → "AI Analysis"
2. Select LLM provider (Groq or Gemini)
3. Upload log file
4. Get AI-generated threat intelligence
5. View MITRE ATT&CK mappings and recommendations

## API Endpoints

```
POST   /api/explain-logs        # Simple Mode analysis
POST   /api/analyze              # Standard analysis
POST   /api/analyze-with-llm     # AI-powered analysis
GET    /api/llm-health           # LLM provider health check
```

## Security

- **API Keys**: Never commit `.env` file (already in `.gitignore`)
- **Database**: Use strong passwords and secure connections
- **HTTPS**: Enable in production environments
- **Rate Limiting**: Implement for public deployments

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **MITRE ATT&CK** for threat intelligence framework
- **CVSS** for vulnerability scoring standards
- **Groq** for free LLM API access
- **Rust Community** for excellent tooling

## Contact

**Developer**: YOUR_NAME

- LinkedIn: [YOUR_LINKEDIN_URL](YOUR_LINKEDIN_URL)
- GitHub: [YOUR_GITHUB_URL](YOUR_GITHUB_URL)
- Website: [YOUR_WEBSITE_URL](YOUR_WEBSITE_URL)

---

**Logr™** - Advanced Security Log Analysis Platform

© 2026 Logr Security Platform. All rights reserved.
