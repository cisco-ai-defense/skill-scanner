# Dependencies and LLM Providers

## Core Runtime Dependencies

The ranges below come from this checkout's
[`pyproject.toml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/pyproject.toml)
and apply to a release that contains these changes. The supported interpreter
range for that release is CPython >= 3.11 and < 3.15. The checked-in Homebrew
formula still packages version 1.0.2 and must not be used as evidence that this
unreleased dependency or platform contract is already published.

### Web Framework and API

| Package | Version | Purpose |
|---------|---------|---------|
| `fastapi` | >= 0.115, < 1 | REST API framework |
| `uvicorn[standard]` | >= 0.34, < 1 | ASGI server |
| `pydantic` | >= 2.10, < 3 | Data validation and serialization |
| `python-multipart` | >= 0.0.31, < 0.1 | File upload handling |
| `httpx` | >= 0.27, < 1 | HTTP client (also used by the VirusTotal, AI Defense, and OSV external analyzers) |

### CLI and TUI

| Package | Version | Purpose |
|---------|---------|---------|
| `click` | >= 8.3.3 | CLI framework |
| `rich` | >= 14.0, < 15 | Terminal formatting |
| `textual` | >= 7.0, < 9 | Interactive TUI (policy configurator) |
| `tabulate` | >= 0.9, < 1 | Table output formatting |

### Analysis and Detection

| Package | Version | Purpose |
|---------|---------|---------|
| `yara-x` | >= 1.10, < 2 | Pattern-matching rule engine |
| `magika` | >= 1.0, < 2 | AI-powered file type detection (200+ types) |
| `pdfid` | >= 1.1, < 2 | Structural PDF analysis (JS, OpenAction, Launch) |
| `oletools` | >= 0.60, < 1 | Office document macro/VBA detection |
| `confusable-homoglyphs` | >= 3.3, < 4 | Unicode homoglyph attack detection |

### Data and Configuration

| Package | Version | Purpose |
|---------|---------|---------|
| `PyYAML` | >= 6.0, < 7 | YAML parsing (policies, rules) |
| `python-frontmatter` | >= 1.1, < 2 | SKILL.md frontmatter parsing |
| `python-dotenv` | >= 1.0, < 2 | Environment variable loading from `.env` |
| `protobuf` | >= 5.29, < 7 | Runtime for generated CEL fact-model messages |

### LLM SDKs

| Package | Version | Purpose |
|---------|---------|---------|
| `anthropic` | >= 0.50, < 1 | Anthropic Claude SDK |
| `openai` | >= 2.0, < 3 | OpenAI SDK |
| `litellm` | >= 1.84, < 2 | Multi-provider LLM routing |
| `google-genai` | >= 1.60, < 2 via `[google]` | Google AI Studio / Gemini SDK |
| `google-generativeai` | >= 0.8, < 1 via `[google]` | Legacy Google Generative AI SDK compatibility |

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
| `google` | `google-genai` | >= 1.60, < 2 | Google AI Studio / Gemini SDK support |
| `google` | `google-generativeai` | >= 0.8, < 1 | Legacy Google Generative AI SDK compatibility |
| `bedrock` | `boto3` | >= 1.40, < 2 | AWS Bedrock IAM credential support |
| `vertex` | `google-cloud-aiplatform` | >= 1.130, < 2 | Google Vertex AI support |
| `azure` | `azure-identity` | >= 1.20, < 2 | Azure managed identity auth |
| `all` | all of the above | | Install all provider extras |

The `google` and `vertex` extras also carry the security floors
`httplib2>=0.32.0` and `pyasn1>=0.6.4`; `[all]` includes those floors as well.

### Bundled CEL Runtime

CEL is a core runtime in this checkout. A release containing these changes will
pin the official `cel.dev/cel-go` module at `v0.32.0` and ship it as a bounded
local helper process; it does not depend on `cel-expr-python`. Each binary is
built with `CGO_ENABLED=0`, bound to helper protocol 2 and the canonical
`ScanFacts` descriptor, and checked against the SHA-256 and target identity in
its packaged manifest before execution.

A release containing these changes is configured to publish wheels explicitly
for CPython 3.11, 3.12, 3.13, and 3.14—there is no unbounded future-Python or
`abi3` claim. Its five required native targets are glibc Linux x86-64/ARM64,
macOS 13+ x86-64/ARM64, and Windows x86-64. Alpine/musl, PyPy, Windows ARM,
Python 3.10, Python 3.15 or newer, and any unlisted platform are outside that
planned support matrix. The release workflow clean-installs every native wheel
and exercises its packaged CEL helper and rules on each supported CPython minor;
it applies the same check to the sdist with the exact prebuilt helper.

For that future release, the current `yara-x` wheels impose a stricter floor on
the complete scanner:
official CPython `abi3` artifacts cover macOS x86-64/ARM64 from macOS 14,
manylinux glibc 2.28 x86-64/ARM64, and Windows x86-64. Consequently, the
packaged scanner's effective macOS minimum is 14 even though its bundled CEL
helper is compatible with macOS 13. Alpine/musl and Windows ARM remain
unsupported unless upstream publishes matching YARA-X wheels.

That release is configured to include `cel-go-dependencies.json`, with every Go
module version and checksum, and `cel-go-helpers.json`, with every wheel/helper
SHA-256. The workflow also merges those components and dependency edges into
the CycloneDX SBOM.

For a release containing these changes, formula generation is configured to
download the hash-verified sdist for the exact requested release and resolve
both runtime dependencies and `[build-system].requires`—including the build
backend's transitive dependencies—from that archive's `pyproject.toml`, never
from `main` or the operator's working tree. Resolution runs independently for
macOS ARM64 and x86-64, so Linux host markers cannot affect the generated
formula. Every dependency becomes a hash-pinned, CPU-conditional wheel resource.
The generated formula selects the Darwin wheel for the host CPU, injects its
prebuilt helper into the source build without networked Go-module fetches,
installs dependencies with index access disabled, and installs the project with
PEP 517 build isolation disabled. It explicitly requires macOS Sonoma (14) or
newer. Apple Silicon and Intel runners must then verify the Mach-O/helper
manifest architecture, compile all rules, and pass the Homebrew test before the
generated formula can be committed. The checked-in version 1.0.2 formula does
not yet implement or prove this future-release contract.

From a source checkout, `uv sync` builds the host helper during the editable
install. To bootstrap or refresh it directly, run:

```bash
uv run python scripts/build_cel_helper.py --in-place
```

`SKILL_SCANNER_CEL_GO_HELPER` is an explicit trusted administrator/developer
override for a locally built helper. It bypasses packaged-resource manifest
discovery, so never point it at a downloaded rule pack, dataset artifact, or
other untrusted executable.

Go 1.27.1 is the minimum supported source-build toolchain for this checkout.
Its CI and release workflows pin exactly Go 1.27.1 for reproducibility; a
release containing these changes will carry that pin into its wheels, SBOMs,
release evidence, and Homebrew qualification. Earlier Go releases cannot build
the same Darwin contract:
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
