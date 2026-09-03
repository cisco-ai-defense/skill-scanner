# Dependencies and LLM Providers

## Core Runtime Dependencies

All versions come from [`pyproject.toml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/pyproject.toml).
The supported interpreter range is CPython >= 3.11 and < 3.15.

### Web Framework and API

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | >= 0.125.0 | REST API framework |
| `uvicorn[standard]` | >= 0.29.0 | ASGI server |
| `pydantic` | >= 2.6.0 | Data validation and serialization |
| `python-multipart` | >= 0.0.6 | File upload handling |
| `httpx` | >= 0.28.1 | HTTP client (also used by the VirusTotal, AI Defense, and OSV external analyzers) |

### CLI and TUI

| Package | Version | Purpose |
|---------|---------|---------|
| `click` | >= 8.1.0 | CLI framework |
| `rich` | >= 13.0.0 | Terminal formatting |
| `textual` | >= 7.0, < 9 | Interactive TUI (policy configurator) |
| `tabulate` | >= 0.9.0 | Table output formatting |

### Analysis and Detection

| Package | Version | Purpose |
|---------|---------|---------|
| `yara-x` | >= 1.10, < 2 | Pattern-matching rule engine |
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
| `protobuf` | >= 5.29, < 7 | Runtime for generated CEL fact-model messages |

### LLM SDKs

| Package | Version | Purpose |
|---------|---------|---------|
| `anthropic` | >= 0.40.0 | Anthropic Claude SDK |
| `openai` | >= 1.0.0 | OpenAI SDK |
| `litellm` | >= 1.77.0 | Multi-provider LLM routing |
| `google-genai` | optional via `[google]` | Google AI Studio / Gemini SDK |
| `google-generativeai` | optional via `[google]` | Legacy Google Generative AI SDK compatibility |

## Optional Provider Extras

Install only what you need:

```bash
# AWS Bedrock
pip install "cisco-ai-skill-scanner[bedrock]"

# Google AI Studio / Gemini
pip install "cisco-ai-skill-scanner[google]"

# Google Vertex AI
pip install "cisco-ai-skill-scanner[vertex]"

# Azure OpenAI
pip install "cisco-ai-skill-scanner[azure]"

# All provider extras
pip install "cisco-ai-skill-scanner[all]"
```

| Extra | Package | Version | Purpose |
|-------|---------|---------|---------|
| `google` | `google-genai`, `google-generativeai` | varies | Google AI Studio / Gemini SDK support |
| `bedrock` | `boto3` | >= 1.28.57 | AWS Bedrock IAM credential support |
| `vertex` | `google-cloud-aiplatform` | >= 1.38.0 | Google Vertex AI support |
| `azure` | `azure-identity` | >= 1.15.0 | Azure managed identity auth |
| `all` | all of the above | | Install all provider extras |

### Bundled CEL Runtime

CEL is a core runtime. Skill Scanner pins the official `cel.dev/cel-go` module
at `v0.32.0` and ships it as a bounded local helper process; it does not depend
on `cel-expr-python`. Each binary is built with `CGO_ENABLED=0`, bound to helper
protocol 2 and the canonical `ScanFacts` descriptor, and checked against the
SHA-256 and target identity in its packaged manifest before execution.

Release wheels explicitly name CPython 3.11, 3.12, 3.13, and 3.14—there is no
unbounded future-Python or `abi3` claim. Five native artifacts are required:
glibc Linux x86-64/ARM64, macOS 13+ x86-64/ARM64, and Windows x86-64. Alpine/
musl, PyPy, Windows ARM, Python 3.10, Python 3.15 or newer, and any unlisted
platform are unsupported.

The current `yara-x` wheels impose a stricter floor on the complete scanner:
official CPython `abi3` artifacts cover macOS x86-64/ARM64 from macOS 14,
manylinux glibc 2.28 x86-64/ARM64, and Windows x86-64. Consequently, the
packaged scanner's effective macOS minimum is 14 even though its bundled CEL
helper is compatible with macOS 13. Alpine/musl and Windows ARM remain
unsupported unless upstream publishes matching YARA-X wheels.

Release assets include `cel-go-dependencies.json`, with every Go module version
and Go checksum, and `cel-go-helpers.json`, with every wheel/helper SHA-256.
Those components and dependency edges are also merged into the CycloneDX SBOM.
Homebrew selects the hash-pinned Darwin release wheel for the host CPU, injects
that prebuilt helper into the source build without networked Go-module fetches,
and runs `validate-rules` before accepting the formula. Formula generation
downloads the hash-verified sdist for the exact requested release and resolves
dependencies from that archive's `pyproject.toml`, never from `main` or the
operator's working tree. Both Apple Silicon and Intel runners install the
generated formula. Wheel-only dependencies are also emitted as CPU-conditional
resources, so an ARM dependency wheel cannot enter an Intel installation (or
vice versa). Each runner verifies the Mach-O/helper manifest architecture,
compiles all rules, and runs the Homebrew test before the formula is committed.

From a source checkout, `uv sync` builds the host helper during the editable
install. To bootstrap or refresh it directly, run:

```bash
uv run python scripts/build_cel_helper.py --in-place
```

`SKILL_SCANNER_CEL_GO_HELPER` is an explicit trusted administrator/developer
override for a locally built helper. It bypasses packaged-resource manifest
discovery, so never point it at a downloaded rule pack, dataset artifact, or
other untrusted executable.

Go 1.27.1 is the minimum supported source-build toolchain. CI, release
evidence, wheels, SBOMs, and Homebrew qualification pin exactly Go 1.27.1 for
reproducibility. Earlier Go releases cannot build the same Darwin contract:
with `CGO_ENABLED=0`, they emit an older Mach-O deployment floor and ignore
`MACOSX_DEPLOYMENT_TARGET`. A qualified release-toolchain change requires
rebuilding and natively smoking every target.

## Supported LLM Providers

### Model Naming

Set `SKILL_SCANNER_LLM_MODEL` using the provider prefix convention:

| Provider | Model example | Notes |
|----------|--------------|-------|
| Anthropic | `anthropic/claude-sonnet-4-20250514` | Default provider |
| OpenAI | `openai/gpt-4o` | |
| OpenAI-compatible custom endpoint | `Cloud-Gemini-3.1-Pro` with `SKILL_SCANNER_LLM_PROVIDER=openai` | Uses `SKILL_SCANNER_LLM_BASE_URL` |
| AWS Bedrock | `bedrock/anthropic.claude-sonnet-4-20250514-v1:0` | Requires `[bedrock]` extra or API key |
| Google Vertex AI | `vertex_ai/gemini-2.5-pro` | Requires `[vertex]` extra |
| Google AI Studio | `gemini/gemini-2.5-flash` | Requires `[google]` extra |
| Azure OpenAI | `azure/my-deployment-name` | Requires `[azure]` extra |
| Ollama (local) | `ollama/llama3` | No API key needed |
| OrcaRouter | `orcarouter/anthropic/claude-sonnet-5` | OpenAI-compatible gateway; default endpoint `https://api.orcarouter.ai/v1` (override with `SKILL_SCANNER_LLM_BASE_URL`) |

For OpenAI and OpenAI-compatible custom endpoints, `SKILL_SCANNER_LLM_USER` can set the raw Chat Completions `user` request field. The value is passed through unchanged and is ignored for non-OpenAI routes.

### Authentication

| Provider | Auth method | Required env vars |
|----------|-------------|-------------------|
| Anthropic | API key | `SKILL_SCANNER_LLM_API_KEY` |
| OpenAI | API key | `SKILL_SCANNER_LLM_API_KEY` |
| OpenAI-compatible custom endpoint | API key + endpoint | `SKILL_SCANNER_LLM_API_KEY`, `SKILL_SCANNER_LLM_PROVIDER=openai`, `SKILL_SCANNER_LLM_BASE_URL` |
| AWS Bedrock (API key) | API key | `SKILL_SCANNER_LLM_API_KEY` |
| AWS Bedrock (IAM) | AWS credentials | `AWS_REGION`, `AWS_PROFILE` (optional: `AWS_SESSION_TOKEN`) |
| Google Vertex AI (service account) | Service account key file | `GOOGLE_APPLICATION_CREDENTIALS` |
| Google Vertex AI (ambient ADC) | Workload Identity / attached service account | none -- falls back automatically, like Bedrock IAM |
| Google AI Studio | API key | `SKILL_SCANNER_LLM_API_KEY` (auto-sets `GEMINI_API_KEY`) |
| Azure OpenAI | API key + endpoint | `SKILL_SCANNER_LLM_API_KEY`, `SKILL_SCANNER_LLM_BASE_URL`, `SKILL_SCANNER_LLM_API_VERSION` |
| Ollama | None | — |
| OrcaRouter | API key | `SKILL_SCANNER_LLM_API_KEY` |

## Related

- [Installation and Configuration](../user-guide/installation-and-configuration.md)
- [LLM Analyzer](../architecture/analyzers/llm-analyzer.md)
- [Configuration Reference](configuration-reference.md)
