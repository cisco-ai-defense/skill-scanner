# Installation and Configuration

> [!TIP]
> **Minimal Setup**
> ```bash
> pip install cisco-ai-skill-scanner
> skill-scanner scan ./my-skill
> ```
> That's it for basic static analysis. The sections below cover optional providers, LLM keys, and advanced toggles.

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

You only need to set these if you're using the corresponding features. Click a section to expand it. For the full list with examples and defaults, see **[Configuration Reference](../reference/configuration-reference.md)**.

<details>
<summary>Core LLM</summary>

- `SKILL_SCANNER_LLM_API_KEY`
- `SKILL_SCANNER_LLM_MODEL`
- `SKILL_SCANNER_LLM_BASE_URL`
- `SKILL_SCANNER_LLM_API_VERSION`

</details>

<details>
<summary>Meta analyzer overrides (optional)</summary>

- `SKILL_SCANNER_META_LLM_API_KEY`
- `SKILL_SCANNER_META_LLM_MODEL`
- `SKILL_SCANNER_META_LLM_BASE_URL`
- `SKILL_SCANNER_META_LLM_API_VERSION`

</details>

<details>
<summary>External analyzers</summary>

- `VIRUSTOTAL_API_KEY`
- `VIRUSTOTAL_UPLOAD_FILES` — set to `true` to upload unknown binaries to VirusTotal
- `AI_DEFENSE_API_KEY`
- `AI_DEFENSE_API_URL`

</details>

<details>
<summary>Cloud provider settings</summary>

- `AWS_REGION`
- `AWS_PROFILE`
- `AWS_SESSION_TOKEN`
- `GOOGLE_APPLICATION_CREDENTIALS`
- `GEMINI_API_KEY` — auto-set from `SKILL_SCANNER_LLM_API_KEY` when using Gemini via LiteLLM

</details>

<details>
<summary>Custom taxonomy and threat mapping</summary>

- `SKILL_SCANNER_TAXONOMY_PATH` — path to a custom Cisco AI taxonomy YAML file (overridden by `--taxonomy`)
- `SKILL_SCANNER_THREAT_MAPPING_PATH` — path to a custom threat mapping YAML file (overridden by `--threat-mapping`)

</details>

<details>
<summary>API server</summary>

- `SKILL_SCANNER_ALLOWED_ROOTS` — colon-delimited path allowlist for server-side path access

</details>

<details>
<summary>Analyzer toggles</summary>

These environment variables override the default enabled/disabled state of analyzers when using the programmatic `Config` object. The CLI and API server use their own flags (`--use-llm`, `--use-behavioral`, etc.) and do not read these variables.

- `ENABLE_STATIC_ANALYZER` — set to `false` to disable the static analyzer
- `ENABLE_LLM_ANALYZER` — set to `true` to enable the LLM analyzer
- `ENABLE_BEHAVIORAL_ANALYZER` — set to `true` to enable the behavioral analyzer
- `ENABLE_AIDEFENSE` — set to `true` to enable the AI Defense analyzer

</details>

## Verify Installation

```bash
skill-scanner --help
skill-scanner list-analyzers
```

## Next Steps

- [Quick Start](../getting-started/quick-start.md)
- [CLI Usage](cli-usage.md)
- [Configuration Reference](../reference/configuration-reference.md)
