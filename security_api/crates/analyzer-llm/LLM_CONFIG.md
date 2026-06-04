# LLM Configuration Guide

This document describes how to configure the multi-provider LLM analyzer for security log analysis.

## Quick Start

1. Copy the example configuration below to your `.env` file
2. Set your preferred provider and API key
3. The analyzer will automatically use your configuration

## Environment Variables

### Provider Selection

| Variable | Description | Default | Options |
|----------|-------------|---------|---------|
| `LLM_PROVIDER` | The LLM provider to use | `openai` | `openai`, `anthropic`, `groq`, `gemini` |
| `LLM_MODEL` | The model name | Provider default | See provider-specific models below |
| `LLM_TEMPERATURE` | Generation temperature | `0.3` | `0.0` - `1.0` |
| `LLM_MAX_TOKENS` | Maximum response tokens | `4096` | Any positive integer |

### API Keys

Set the API key for your chosen provider:

| Provider | Environment Variable |
|----------|---------------------|
| OpenAI | `OPENAI_API_KEY` |
| Anthropic | `ANTHROPIC_API_KEY` |
| Groq | `GROQ_API_KEY` |
| Google Gemini | `GEMINI_API_KEY` |

## Example Configurations

### Using OpenAI (GPT-4o)

```env
# OpenAI Configuration
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
LLM_TEMPERATURE=0.3
LLM_MAX_TOKENS=4096
OPENAI_API_KEY=sk-your-openai-api-key-here
```

### Using Anthropic (Claude)

```env
# Anthropic Configuration
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-20250514
LLM_TEMPERATURE=0.3
LLM_MAX_TOKENS=4096
ANTHROPIC_API_KEY=sk-ant-your-anthropic-api-key-here
```

### Using Groq (Llama - Fast Inference)

```env
# Groq Configuration (fast, cost-effective)
LLM_PROVIDER=groq
LLM_MODEL=llama-3.1-70b-versatile
LLM_TEMPERATURE=0.3
LLM_MAX_TOKENS=4096
GROQ_API_KEY=gsk_your-groq-api-key-here
```

### Using Google Gemini

```env
# Gemini Configuration
LLM_PROVIDER=gemini
LLM_MODEL=gemini-1.5-flash
LLM_TEMPERATURE=0.3
LLM_MAX_TOKENS=4096
GEMINI_API_KEY=your-gemini-api-key-here
```

## Available Models

### OpenAI Models

| Model | Description | Best For |
|-------|-------------|----------|
| `gpt-4o` | Latest GPT-4 Omni | Best accuracy (default) |
| `gpt-4o-mini` | Smaller, faster GPT-4 | Good balance of speed/accuracy |
| `gpt-4-turbo` | GPT-4 Turbo | Large context windows |

### Anthropic Models

| Model | Description | Best For |
|-------|-------------|----------|
| `claude-sonnet-4-20250514` | Claude Sonnet 4 | Best accuracy (default) |
| `claude-3-5-sonnet-20241022` | Claude 3.5 Sonnet | Great balance |
| `claude-3-5-haiku-20241022` | Claude 3.5 Haiku | Fast, cost-effective |

### Groq Models

| Model | Description | Best For |
|-------|-------------|----------|
| `llama-3.1-70b-versatile` | Llama 3.1 70B | Best accuracy (default) |
| `llama-3.1-8b-instant` | Llama 3.1 8B | Ultra-fast responses |
| `mixtral-8x7b-32768` | Mixtral 8x7B | Large context |

### Gemini Models

| Model | Description | Best For |
|-------|-------------|----------|
| `gemini-1.5-flash` | Gemini 1.5 Flash | Fast, cost-effective (default) |
| `gemini-1.5-pro` | Gemini 1.5 Pro | Best accuracy, larger context |
| `gemini-2.0-flash-exp` | Gemini 2.0 Flash (Experimental) | Latest experimental features |

## Switching Providers

To switch providers, simply update the `.env` file:

1. Change `LLM_PROVIDER` to your desired provider
2. Update or add the corresponding API key
3. Optionally specify a different model with `LLM_MODEL`
4. Restart the application

No code changes are required!

## Programmatic Configuration

You can also configure the analyzer programmatically:

```rust
use security_analyzer_llm::{LlmAnalyzer, LlmConfig, LlmProvider};

// From environment variables (recommended)
let analyzer = LlmAnalyzer::from_env()?;

// Or with explicit configuration
let config = LlmConfig::new(
    LlmProvider::Anthropic,
    "claude-sonnet-4-20250514",
    "your-api-key-here",
)
.with_temperature(0.3)
.with_max_tokens(4096);

let analyzer = LlmAnalyzer::with_config(config);
```

## Troubleshooting

### "API key not found" error

Ensure you've set the correct environment variable for your provider:
- For OpenAI: `OPENAI_API_KEY`
- For Anthropic: `ANTHROPIC_API_KEY`
- For Groq: `GROQ_API_KEY`

### "Invalid provider" error

Check that `LLM_PROVIDER` is one of: `openai`, `anthropic`, `groq`, `gemini`

### Rate limiting

If you're hitting rate limits:
1. Use a model with higher rate limits
2. Reduce the number of logs analyzed at once
3. Add delays between requests
4. Upgrade your API plan

## Security Best Practices

1. **Never commit API keys** - Use `.env` files and add them to `.gitignore`
2. **Use environment variables** - Don't hardcode keys in source code
3. **Rotate keys regularly** - Especially for production environments
4. **Use least privilege** - Only grant necessary API permissions