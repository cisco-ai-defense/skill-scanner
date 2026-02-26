<!-- GENERATED FILE. DO NOT EDIT DIRECTLY.
     Regenerate with: uv run python scripts/generate_reference_docs.py -->

# Configuration Reference

This page is generated from `.env.example` and runtime source references.

> [!TIP]
> **Quick Start**
> Most users only need to set one or two variables. Create a `.env` file in your project root:
>
> ```bash
> # Minimal .env for Anthropic
> SKILL_SCANNER_LLM_API_KEY="sk-ant-..."
> SKILL_SCANNER_LLM_MODEL="anthropic/claude-sonnet-4-20250514"
> ```
>
> See [Installation and Configuration](../user-guide/installation-and-configuration.md) for provider-specific setup.

## LLM Configuration

Primary settings for the LLM semantic analyzer.

| Variable | Description | Example |
|---|---|---|
| `SKILL_SCANNER_LLM_API_KEY` | Primary API key for LLM analyzer and meta fallback. **(required)** | `sk-ant-...` |
| `SKILL_SCANNER_LLM_MODEL` | Primary model identifier for semantic analysis. | `anthropic/claude-sonnet-4-20250514` |
| `SKILL_SCANNER_LLM_BASE_URL` | Optional custom endpoint base URL for provider routing. | `https://api.openai.com/v1` |
| `SKILL_SCANNER_LLM_API_VERSION` | Optional API version for providers that require one. | `2024-02-15-preview` |

## Meta Analyzer

Override LLM settings for the meta (cross-correlation) analyzer. Falls back to the primary LLM values.

| Variable | Description | Example |
|---|---|---|
| `SKILL_SCANNER_META_LLM_API_KEY` | Meta-analyzer API key override. | `(falls back to LLM_API_KEY)` |
| `SKILL_SCANNER_META_LLM_MODEL` | Meta-analyzer model override. | `(falls back to LLM_MODEL)` |
| `SKILL_SCANNER_META_LLM_BASE_URL` | Meta-analyzer base URL override. | `(falls back to LLM_BASE_URL)` |
| `SKILL_SCANNER_META_LLM_API_VERSION` | Meta-analyzer API version override. | `(falls back to LLM_API_VERSION)` |

## AWS / Bedrock

Required when using a `bedrock/...` model with IAM credentials instead of an API key.

| Variable | Description | Example |
|---|---|---|
| `AWS_REGION` | AWS region for Bedrock-backed flows. | `us-east-1` |
| `AWS_PROFILE` | AWS credential profile for Bedrock IAM auth. | `my-bedrock-profile` |
| `AWS_SESSION_TOKEN` | Optional AWS session token. | `(temporary STS token)` |

## Google / Vertex

Credentials for Vertex AI and Google AI Studio.

| Variable | Description | Example |
|---|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account credentials. | `/path/to/sa-key.json` |
| `GEMINI_API_KEY` | Google AI Studio key; auto-set from `SKILL_SCANNER_LLM_API_KEY` when using Gemini via LiteLLM. | `(auto-set from LLM_API_KEY)` |

## VirusTotal

Enable the VirusTotal hash-lookup analyzer.

| Variable | Description | Example |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal analyzer API key. | `(your VT key)` |
| `VIRUSTOTAL_UPLOAD_FILES` | Enable upload mode for unknown binaries. | `false` |

## Cisco AI Defense

Enable the Cisco AI Defense cloud analyzer.

| Variable | Description | Example |
|---|---|---|
| `AI_DEFENSE_API_KEY` | Cisco AI Defense analyzer API key. | `(your AI Defense key)` |
| `AI_DEFENSE_API_URL` | Cisco AI Defense endpoint override. | `https://us.api.inspect.aidefense.security.cisco.com/api/v1` |

## Feature Toggles

Override default analyzer enablement via environment. Values: `true`/`1` or `false`/`0`.

| Variable | Description | Example |
|---|---|---|
| `ENABLE_STATIC_ANALYZER` | Optional environment toggle for static analyzer default. | `true` |
| `ENABLE_LLM_ANALYZER` | Optional environment toggle for LLM analyzer default. | `false` |
| `ENABLE_BEHAVIORAL_ANALYZER` | Optional environment toggle for behavioral analyzer default. | `false` |
| `ENABLE_AIDEFENSE` | Optional environment toggle for AI Defense analyzer default. | `false` |

## Advanced

Paths, allowlists, and other advanced settings.

| Variable | Description | Example |
|---|---|---|
| `SKILL_SCANNER_ALLOWED_ROOTS` | Colon-delimited API path allowlist for server-side path access. | `/srv/skills:/home/user/skills` |
| `SKILL_SCANNER_TAXONOMY_PATH` | Path to a custom Cisco AI taxonomy YAML file (overridden by `--taxonomy`). | `/path/to/taxonomy.yaml` |
| `SKILL_SCANNER_THREAT_MAPPING_PATH` | Path to a custom threat mapping YAML file (overridden by `--threat-mapping`). | `/path/to/threats.yaml` |

<details>
<summary>Source file mapping</summary>

| Variable | Source(s) |
|---|---|
| `AI_DEFENSE_API_KEY` | `.env.example`, `skill_scanner/config/config.py`, `skill_scanner/core/analyzer_factory.py`, `skill_scanner/core/analyzers/aidefense_analyzer.py` |
| `AI_DEFENSE_API_URL` | `.env.example`, `skill_scanner/core/analyzer_factory.py`, `skill_scanner/core/analyzers/aidefense_analyzer.py` |
| `AWS_PROFILE` | `.env.example`, `skill_scanner/config/config.py`, `skill_scanner/core/analyzers/llm_provider_config.py` |
| `AWS_REGION` | `.env.example`, `skill_scanner/config/config.py`, `skill_scanner/core/analyzers/llm_provider_config.py` |
| `AWS_SESSION_TOKEN` | `skill_scanner/config/config.py`, `skill_scanner/core/analyzers/llm_provider_config.py` |
| `ENABLE_AIDEFENSE` | `skill_scanner/config/config.py` |
| `ENABLE_BEHAVIORAL_ANALYZER` | `skill_scanner/config/config.py` |
| `ENABLE_LLM_ANALYZER` | `skill_scanner/config/config.py` |
| `ENABLE_STATIC_ANALYZER` | `skill_scanner/config/config.py` |
| `GEMINI_API_KEY` | `skill_scanner/core/analyzers/llm_provider_config.py` |
| `GOOGLE_APPLICATION_CREDENTIALS` | `.env.example`, `skill_scanner/core/analyzers/llm_provider_config.py` |
| `SKILL_SCANNER_ALLOWED_ROOTS` | `skill_scanner/api/router.py` |
| `SKILL_SCANNER_LLM_API_KEY` | `.env.example`, `skill_scanner/cli/cli.py`, `skill_scanner/config/config.py`, `skill_scanner/core/analyzer_factory.py`, `skill_scanner/core/analyzers/behavioral_analyzer.py`, `skill_scanner/core/analyzers/llm_analyzer.py`, `skill_scanner/core/analyzers/llm_provider_config.py`, `skill_scanner/core/analyzers/meta_analyzer.py` |
| `SKILL_SCANNER_LLM_API_VERSION` | `.env.example`, `skill_scanner/cli/cli.py`, `skill_scanner/core/analyzer_factory.py`, `skill_scanner/core/analyzers/meta_analyzer.py` |
| `SKILL_SCANNER_LLM_BASE_URL` | `.env.example`, `skill_scanner/cli/cli.py`, `skill_scanner/core/analyzer_factory.py`, `skill_scanner/core/analyzers/meta_analyzer.py` |
| `SKILL_SCANNER_LLM_MODEL` | `.env.example`, `skill_scanner/cli/cli.py`, `skill_scanner/config/config.py`, `skill_scanner/core/analyzer_factory.py`, `skill_scanner/core/analyzers/behavioral_analyzer.py`, `skill_scanner/core/analyzers/llm_analyzer.py`, `skill_scanner/core/analyzers/meta_analyzer.py` |
| `SKILL_SCANNER_META_LLM_API_KEY` | `.env.example`, `skill_scanner/cli/cli.py`, `skill_scanner/core/analyzers/meta_analyzer.py` |
| `SKILL_SCANNER_META_LLM_API_VERSION` | `.env.example`, `skill_scanner/cli/cli.py`, `skill_scanner/core/analyzers/meta_analyzer.py` |
| `SKILL_SCANNER_META_LLM_BASE_URL` | `.env.example`, `skill_scanner/cli/cli.py`, `skill_scanner/core/analyzers/meta_analyzer.py` |
| `SKILL_SCANNER_META_LLM_MODEL` | `.env.example`, `skill_scanner/cli/cli.py`, `skill_scanner/core/analyzers/meta_analyzer.py` |
| `SKILL_SCANNER_TAXONOMY_PATH` | `skill_scanner/threats/cisco_ai_taxonomy.py` |
| `SKILL_SCANNER_THREAT_MAPPING_PATH` | `skill_scanner/threats/threats.py` |
| `VIRUSTOTAL_API_KEY` | `.env.example`, `skill_scanner/config/config.py`, `skill_scanner/core/analyzer_factory.py` |
| `VIRUSTOTAL_UPLOAD_FILES` | `skill_scanner/config/config.py` |

</details>

## Related

- CLI flags: [CLI Command Reference](cli-command-reference.md)
- Policy YAML: [Custom Policy Configuration](../user-guide/custom-policy-configuration.md)
- Presets: [Scan Policies Overview](../user-guide/scan-policies-overview.md)
