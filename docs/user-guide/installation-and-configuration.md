# Installation and Configuration

::: tip Minimal Setup
```bash
pip install cisco-ai-skill-scanner
skill-scanner scan ./my-skill
```
That's it for basic static analysis. The sections below cover optional providers, LLM keys, and advanced toggles.
:::

## Installation

### PyPI (recommended)

```bash
uv pip install cisco-ai-skill-scanner
# or
pip install cisco-ai-skill-scanner
```

### Optional provider extras

```bash
pip install cisco-ai-skill-scanner[bedrock]
pip install cisco-ai-skill-scanner[vertex]
pip install cisco-ai-skill-scanner[azure]
pip install cisco-ai-skill-scanner[all]
```

### From source

```bash
git clone https://github.com/cisco-ai-defense/skill-scanner
cd skill-scanner
uv sync --all-extras
```

## Configuration Priority

Runtime precedence is:

1. CLI flags
2. Environment variables
3. Built-in defaults

## Environment Variables

You only need to set these if you're using the corresponding features. Click a section to expand it. For the full list with examples and defaults, see **[Configuration Reference](/reference/configuration-reference)**.

::: details Core LLM
- `SKILL_SCANNER_LLM_API_KEY`
- `SKILL_SCANNER_LLM_MODEL`
- `SKILL_SCANNER_LLM_BASE_URL`
- `SKILL_SCANNER_LLM_API_VERSION`
:::

::: details Meta analyzer overrides (optional)
- `SKILL_SCANNER_META_LLM_API_KEY`
- `SKILL_SCANNER_META_LLM_MODEL`
- `SKILL_SCANNER_META_LLM_BASE_URL`
- `SKILL_SCANNER_META_LLM_API_VERSION`
:::

::: details External analyzers
- `VIRUSTOTAL_API_KEY`
- `VIRUSTOTAL_UPLOAD_FILES` — set to `true` to upload unknown binaries to VirusTotal
- `AI_DEFENSE_API_KEY`
- `AI_DEFENSE_API_URL`
:::

::: details Cloud provider settings
- `AWS_REGION`
- `AWS_PROFILE`
- `AWS_SESSION_TOKEN`
- `GOOGLE_APPLICATION_CREDENTIALS`
- `GEMINI_API_KEY` — auto-set from `SKILL_SCANNER_LLM_API_KEY` when using Gemini via LiteLLM
:::

::: details Custom taxonomy and threat mapping
- `SKILL_SCANNER_TAXONOMY_PATH` — path to a custom Cisco AI taxonomy YAML file (overridden by `--taxonomy`)
- `SKILL_SCANNER_THREAT_MAPPING_PATH` — path to a custom threat mapping YAML file (overridden by `--threat-mapping`)
:::

::: details API server
- `SKILL_SCANNER_ALLOWED_ROOTS` — colon-delimited path allowlist for server-side path access
:::

::: details Analyzer toggles
These environment variables override the default enabled/disabled state of analyzers:

- `ENABLE_STATIC_ANALYZER` — set to `false` to disable the static analyzer
- `ENABLE_LLM_ANALYZER` — set to `true` to enable the LLM analyzer
- `ENABLE_BEHAVIORAL_ANALYZER` — set to `true` to enable the behavioral analyzer
- `ENABLE_AIDEFENSE` — set to `true` to enable the AI Defense analyzer
:::

## Verify Installation

```bash
skill-scanner --help
skill-scanner list-analyzers
```

## Next Steps

- [Quick Start](/getting-started/quick-start)
- [CLI Usage](/user-guide/cli-usage)
- [Configuration Reference](/reference/configuration-reference)
