# Contributing to Security Log Analyzer

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/Security-Log-Analyser.git`
3. Create a new branch: `git checkout -b feature/your-feature-name`

## Development Setup

### Prerequisites

- Rust 1.70 or higher
- PostgreSQL 14 or higher
- API keys for LLM providers (Groq, Gemini, OpenAI, or Anthropic)

### Installation

```bash
# Install dependencies
cargo build

# Set up environment variables
cp .env.example .env
# Edit .env with your API keys

# Run the server
cargo run -p security-api
```

## Code Style

- Follow Rust standard formatting: `cargo fmt`
- Run clippy before submitting: `cargo clippy`
- Write tests for new features
- Keep functions focused and well-documented

## Commit Guidelines

Use clear, descriptive commit messages:

```
feat: Add export to PDF functionality
fix: Resolve parsing error for malformed logs
docs: Update README with new configuration options
test: Add unit tests for IP analysis
refactor: Simplify LLM provider selection logic
```

## Pull Request Process

1. Update documentation for any new features
2. Add tests for bug fixes and new functionality
3. Ensure all tests pass: `cargo test`
4. Update the README.md if needed
5. Submit your PR with a clear description of changes

### PR Checklist

- [ ] Code follows project style guidelines
- [ ] Tests added/updated and passing
- [ ] Documentation updated
- [ ] No compiler warnings
- [ ] Commit messages are clear

## Testing

```bash
# Run all tests
cargo test

# Run specific crate tests
cargo test -p security-analyzer-basic
cargo test -p security-analyzer-llm

# Run with output
cargo test -- --nocapture
```

## Reporting Bugs

When reporting bugs, please include:

- Rust version (`rustc --version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant log output

## Feature Requests

We welcome feature requests! Please:

- Check existing issues first
- Clearly describe the use case
- Explain why it would be useful
- Consider submitting a PR if you can implement it

## Code Review

All submissions require review. We aim to:

- Respond to PRs within 48 hours
- Provide constructive feedback
- Merge quality contributions promptly

## Questions?

Feel free to open an issue for questions or reach out via:
- GitHub Issues
- LinkedIn: https://www.linkedin.com/in/sena-raufi-610187293/

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
