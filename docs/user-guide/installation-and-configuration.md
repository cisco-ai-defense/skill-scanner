# Installation and Configuration

> [!TIP]
> **Minimal Setup**
> ```bash
> pip install cisco-ai-skill-scanner
> skill-scanner scan ./my-skill
> ```
> Published wheels already include the required CEL helper. The sections below
> cover supported platforms, optional providers, LLM keys, and advanced toggles.

## Installation

Skill Scanner supports CPython 3.11, 3.12, 3.13, and 3.14. Python 3.10 and
Python 3.15+ are rejected; consumers that still need 3.10 must pin the previous
scanner release.

Published wheels support glibc Linux x86-64/ARM64, macOS x86-64/ARM64, and
Windows x86-64. The CEL helper supports macOS 13+, but the complete scanner
currently requires macOS 14+ because of the YARA-X wheel floor. Alpine/musl,
PyPy, and Windows ARM are unsupported.

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

Source installations additionally require Go 1.27.1 or newer. The build hook
compiles the pinned `cel.dev/cel-go` v0.32.0 helper for the host platform.

```bash
git clone https://github.com/cisco-ai-defense/skill-scanner
cd skill-scanner
uv sync --all-extras
```

If the helper needs to be rebuilt explicitly:

```bash
uv run python scripts/build_cel_helper.py --in-place
```

`SKILL_SCANNER_CEL_GO_HELPER` is a trusted administrator/developer override for
a locally built helper. Do not point it at an executable supplied by a scanned
package or downloaded rule pack.

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
- `SKILL_SCANNER_LLM_PROVIDER` — set to `openai` for OpenAI-compatible custom endpoints when the model name is not enough to infer routing
- `SKILL_SCANNER_LLM_MODEL`
- `SKILL_SCANNER_LLM_BASE_URL`
- `SKILL_SCANNER_LLM_API_VERSION`
- `SKILL_SCANNER_LLM_USER` — optional raw Chat Completions `user` field for OpenAI-compatible routes
- `SKILL_SCANNER_LLM_REASONING_EFFORT` — optional `disabled`, `minimal`, `low`, `medium`, `high`, `xhigh`, or `max`; unset preserves the provider default. Direct Google GenAI SDK requests reject configured controls, while LiteLLM-backed Gemini requests support them.
- `SKILL_SCANNER_LLM_FORCE_JSON_OBJECT` — start in plain JSON mode for proxies that reject `json_schema`

</details>

<details>
<summary>Meta analyzer overrides (optional)</summary>

- `SKILL_SCANNER_META_LLM_API_KEY`
- `SKILL_SCANNER_META_LLM_MODEL`
- `SKILL_SCANNER_META_LLM_BASE_URL`
- `SKILL_SCANNER_META_LLM_API_VERSION`
- `SKILL_SCANNER_META_LLM_REASONING_EFFORT` — direct Google GenAI SDK requests reject configured controls, while LiteLLM-backed Gemini requests support them

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
skill-scanner validate-rules
```

`validate-rules` validates pack metadata and compiles/type-checks every selected
CEL expression. A missing or incompatible helper is an installation error even
when the selected policy uses CEL `off`.

## Next Steps

- [Quick Start](../getting-started/quick-start.md)
- [CLI Usage](cli-usage.md)
- [Configuration Reference](../reference/configuration-reference.md)
