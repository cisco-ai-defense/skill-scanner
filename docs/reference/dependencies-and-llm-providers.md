# Dependencies and LLM Providers

## Core Runtime Dependencies

All versions from [`pyproject.toml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/pyproject.toml). Requires Python >= 3.10.

### Web Framework and API

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | >= 0.125.0 | REST API framework |
| `uvicorn[standard]` | >= 0.29.0 | ASGI server |
| `pydantic` | >= 2.6.0 | Data validation and serialization |
| `python-multipart` | >= 0.0.6 | File upload handling |
| `httpx` | >= 0.28.1 | Async HTTP client |

### CLI and TUI

| Package | Version | Purpose |
|---------|---------|---------|
| `click` | >= 8.1.0 | CLI framework |
| `rich` | >= 13.0.0 | Terminal formatting |
| `textual` | >= 1.0.0 | Interactive TUI (policy configurator) |
| `tabulate` | >= 0.9.0 | Table output formatting |

### Analysis and Detection

| Package | Version | Purpose |
|---------|---------|---------|
| `yara-x` | >= 1.12.0 | Pattern-matching rule engine |
| `magika` | >= 0.6.0 | AI-powered file type detection (200+ types) |
| `pdfid` | >= 1.1.0 | Structural PDF analysis (JS, OpenAction, Launch) |
| `oletools` | >= 0.60.1 | Office document macro/VBA detection |
| `confusable-homoglyphs` | >= 3.3.0 | Unicode homoglyph attack detection |

### Data and Configuration

| Package | Version | Purpose |
|---------|---------|---------|
| `PyYAML` | >= 6.0.1 | YAML parsing (policies, rules) |
| `python-frontmatter` | >= 1.0.0 | SKILL.md frontmatter parsing |
| `python-dotenv` | >= 1.0.0 | Environment variable loading from `.env` |

### LLM SDKs

| Package | Version | Purpose |
|---------|---------|---------|
| `anthropic` | >= 0.40.0 | Anthropic Claude SDK |
| `openai` | >= 1.0.0 | OpenAI SDK |
| `litellm` | >= 1.77.0 | Multi-provider LLM routing |
| `google-genai` | >= 0.2.0 | Google AI SDK |
| `google-generativeai` | >= 0.8.0 | Google Generative AI SDK |

## Optional Provider Extras

Install only what you need:

```bash
# AWS Bedrock
pip install "cisco-ai-skill-scanner[bedrock]"

# Google Vertex AI
pip install "cisco-ai-skill-scanner[vertex]"

# Azure OpenAI
pip install "cisco-ai-skill-scanner[azure]"

# All provider extras
pip install "cisco-ai-skill-scanner[all]"
```

| Extra | Package | Version | Purpose |
|-------|---------|---------|---------|
| `bedrock` | `boto3` | >= 1.28.57 | AWS Bedrock IAM credential support |
| `vertex` | `google-cloud-aiplatform` | >= 1.38.0 | Google Vertex AI support |
| `azure` | `azure-identity` | >= 1.15.0 | Azure managed identity auth |
| `all` | all of the above | | Install all provider extras |

## Supported LLM Providers

### Model Naming

Set `SKILL_SCANNER_LLM_MODEL` using the provider prefix convention:

| Provider | Model example | Notes |
|----------|--------------|-------|
| Anthropic | `anthropic/claude-sonnet-4-20250514` | Default provider |
| OpenAI | `openai/gpt-4o` | |
| AWS Bedrock | `bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0` | Requires `[bedrock]` extra or API key |
| Google Vertex AI | `vertex_ai/gemini-2.5-pro` | Requires `[vertex]` extra |
| Google AI Studio | `gemini/gemini-2.5-flash` | Via LiteLLM |
| Azure OpenAI | `azure/my-deployment-name` | Requires `[azure]` extra |
| Ollama (local) | `ollama/llama3` | No API key needed |

### Authentication

| Provider | Auth method | Required env vars |
|----------|-------------|-------------------|
| Anthropic | API key | `SKILL_SCANNER_LLM_API_KEY` |
| OpenAI | API key | `SKILL_SCANNER_LLM_API_KEY` |
| AWS Bedrock (API key) | API key | `SKILL_SCANNER_LLM_API_KEY` |
| AWS Bedrock (IAM) | AWS credentials | `AWS_REGION`, `AWS_PROFILE` (optional: `AWS_SESSION_TOKEN`) |
| Google Vertex AI | Service account | `GOOGLE_APPLICATION_CREDENTIALS` |
| Google AI Studio | API key | `SKILL_SCANNER_LLM_API_KEY` (auto-sets `GEMINI_API_KEY`) |
| Azure OpenAI | API key + endpoint | `SKILL_SCANNER_LLM_API_KEY`, `SKILL_SCANNER_LLM_BASE_URL`, `SKILL_SCANNER_LLM_API_VERSION` |
| Ollama | None | — |

## Related

- [Installation and Configuration](/user-guide/installation-and-configuration)
- [LLM Analyzer](/architecture/analyzers/llm-analyzer)
- [Configuration Reference](/reference/configuration-reference)
