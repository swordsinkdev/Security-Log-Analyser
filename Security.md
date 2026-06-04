# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of our security log analyzer seriously. If you discover a security vulnerability, please follow these steps:

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **sena.devx@gmail.com**

Include the following information:

- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### What to Expect

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Updates**: We will send you regular updates about our progress
- **Timeline**: We aim to patch critical vulnerabilities within 7 days
- **Credit**: We will credit you in the security advisory (unless you prefer to remain anonymous)

## Security Best Practices

When using this tool:

1. **API Keys**: Never commit API keys to the repository. Use environment variables.
2. **Log Files**: Sanitize logs before uploading if they contain sensitive information
3. **Network**: Run the server behind a firewall or reverse proxy in production
4. **Updates**: Keep dependencies updated regularly
5. **Access Control**: Implement authentication if exposing the API publicly

## Known Security Considerations

- This tool analyzes log files which may contain sensitive information
- LLM API calls send log data to third-party providers (OpenAI, Anthropic, Groq, Gemini)
- Ensure compliance with your organization's data handling policies
- Consider using the Standard Analysis mode for sensitive logs (no external API calls)

## Vulnerability Disclosure Policy

- We request that you give us reasonable time to fix the issue before public disclosure
- We will work with you to understand and resolve the issue quickly
- We will publicly acknowledge your responsible disclosure (with your permission)

## Security Updates

Security updates will be released as patch versions and announced via:
- GitHub Security Advisories
- Release notes
- README updates

## Contact

For security concerns, contact: sena.devx@gmail.com

For general questions, use GitHub Issues.
