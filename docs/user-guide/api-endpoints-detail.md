# API Endpoints Detail

Full request/response documentation for every Skill Scanner API endpoint. For a high-level overview, see the [API Server](/user-guide/api-server) page.

::: tip Quick reference
For a compact table of all endpoints and Pydantic models, see the auto-generated [API Endpoint Reference](/reference/api-endpoint-reference).
:::

## Root

```http
GET /
```

Returns service metadata and links:

```json
{
  "service": "Skill Scanner API",
  "version": "<installed-package-version>",
  "docs": "/docs",
  "health": "/health"
}
```

## Health Check

```http
GET /health
```

Returns server status and available analyzers.

**Response:**

```json
{
  "status": "healthy",
  "version": "<installed-package-version>",
  "analyzers_available": [
    "static_analyzer",
    "bytecode_analyzer",
    "pipeline_analyzer",
    "behavioral_analyzer",
    "llm_analyzer",
    "virustotal_analyzer",
    "trigger_analyzer",
    "meta_analyzer",
    "aidefense_analyzer"
  ]
}
```

::: info Analyzer naming
The `/health` and `/analyzers` endpoints use suffixed names (`bytecode_analyzer`, `pipeline_analyzer`) from a static list in the API router. The core analyzers report shorter names (`bytecode`, `pipeline`) in `analyzers_used` within scan results. Both refer to the same analyzers.
:::

For LLM/meta auth, Bedrock models can use AWS credentials/IAM when configured with a `bedrock/...` model.

## Scan Single Skill

```http
POST /scan
Content-Type: application/json

{
  "skill_directory": "/path/to/skill",
  "policy": "balanced",
  "custom_rules": null,
  "use_behavioral": false,
  "use_llm": false,
  "llm_provider": "anthropic",
  "use_virustotal": false,
  "vt_api_key": null,
  "vt_upload_files": false,
  "use_trigger": false,
  "enable_meta": false,
  "llm_consensus_runs": 1,
  "use_aidefense": false,
  "aidefense_api_key": null,
  "aidefense_api_url": null
}
```

**Request Parameters:**

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `skill_directory` | string | required | Path to skill directory |
| `policy` | string | null | Scan policy: preset name (`strict`, `balanced`, `permissive`) or path to custom YAML |
| `custom_rules` | string | null | Path to custom YARA rules directory |
| `use_behavioral` | boolean | false | Enable behavioral dataflow analyzer |
| `use_llm` | boolean | false | Enable LLM semantic analyzer |
| `llm_provider` | string | `"anthropic"` | LLM provider shortcut (`anthropic` or `openai`) |
| `llm_consensus_runs` | integer | `1` | Number of LLM passes for majority voting |
| `use_virustotal` | boolean | false | Enable VirusTotal binary analyzer |
| `vt_api_key` | string | null | VirusTotal API key (or set `VIRUSTOTAL_API_KEY`) |
| `vt_upload_files` | boolean | false | Upload unknown binaries to VirusTotal |
| `use_aidefense` | boolean | false | Enable Cisco AI Defense analyzer |
| `aidefense_api_key` | string | null | AI Defense API key (or set `AI_DEFENSE_API_KEY`) |
| `aidefense_api_url` | string | null | Optional AI Defense API URL override |
| `use_trigger` | boolean | false | Enable trigger specificity analyzer |
| `enable_meta` | boolean | false | Enable meta-analyzer false-positive filtering |

For Bedrock, Vertex, Azure, Gemini, and other LiteLLM backends, configure `SKILL_SCANNER_LLM_MODEL`/provider environment variables instead of relying on the `llm_provider` shortcut.

**Response:**

```json
{
  "scan_id": "uuid",
  "skill_name": "calculator",
  "is_safe": true,
  "max_severity": "SAFE",
  "findings_count": 0,
  "scan_duration_seconds": 0.15,
  "timestamp": "2025-01-01T12:00:00",
  "findings": []
}
```

## Upload and Scan Skill

**Primary use case**: Upload a skill package as a ZIP file for scanning. This is the main workflow for CI/CD and web interfaces.

```http
POST /scan-upload
Content-Type: multipart/form-data

file: skill.zip
policy: balanced
use_llm: false
llm_provider: anthropic
```

Uploads a ZIP file containing a skill package and scans it. The ZIP file is extracted to a temporary directory, scanned, and then cleaned up.

`/scan-upload` accepts the same optional scan flags as `/scan`, but as **multipart form fields** (not query params).

**Form Fields:**

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `file` | file (`.zip`) | yes | ZIP archive containing a skill |
| `policy`, `custom_rules`, `use_behavioral`, `use_llm`, `llm_provider`, `llm_consensus_runs`, `use_virustotal`, `vt_api_key`, `vt_upload_files`, `use_aidefense`, `aidefense_api_key`, `aidefense_api_url`, `use_trigger`, `enable_meta` | mixed | no | Same semantics as `/scan` |

**Response:** Same as `/scan`

## Batch Scan (Async)

```http
POST /scan-batch
Content-Type: application/json

{
  "skills_directory": "/path/to/skills",
  "policy": "balanced",
  "custom_rules": null,
  "recursive": false,
  "check_overlap": false,
  "use_behavioral": false,
  "use_llm": false,
  "llm_provider": "anthropic",
  "use_virustotal": false,
  "vt_api_key": null,
  "vt_upload_files": false,
  "use_trigger": false,
  "enable_meta": false,
  "llm_consensus_runs": 1,
  "use_aidefense": false,
  "aidefense_api_key": null,
  "aidefense_api_url": null
}
```

`/scan-batch` supports the same optional analyzer fields as `/scan`, plus:

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `skills_directory` | string | required | Directory containing skills |
| `recursive` | boolean | false | Recursively search for skills |
| `check_overlap` | boolean | false | Enable cross-skill description overlap analysis |

**Response:**

```json
{
  "scan_id": "uuid",
  "status": "processing",
  "message": "Batch scan started. Use GET /scan-batch/{scan_id} to check status."
}
```

## Get Batch Scan Results

```http
GET /scan-batch/{scan_id}
```

**Response (Processing):**

```json
{
  "scan_id": "uuid",
  "status": "processing",
  "started_at": "2025-01-01T12:00:00"
}
```

**Response (Completed):**

```json
{
  "scan_id": "uuid",
  "status": "completed",
  "started_at": "2025-01-01T12:00:00",
  "completed_at": "2025-01-01T12:05:30",
  "result": {
    "summary": {...},
    "results": [...]
  }
}
```

## List Analyzers

```http
GET /analyzers
```

**Response:**

```json
{
  "analyzers": [
    {
      "name": "static_analyzer",
      "description": "Pattern-based detection using YAML and YARA rules",
      "available": true,
      "rules_count": "90+"
    },
    {
      "name": "bytecode_analyzer",
      "description": "Python bytecode integrity verification against source",
      "available": true
    },
    {
      "name": "pipeline_analyzer",
      "description": "Command pipeline taint analysis for data exfiltration",
      "available": true
    },
    {
      "name": "behavioral_analyzer",
      "description": "Static dataflow analysis for Python files",
      "available": true
    },
    {
      "name": "llm_analyzer",
      "description": "Semantic analysis using LLM as a judge",
      "available": true,
      "providers": ["anthropic", "openai", "azure", "bedrock", "gemini"]
    },
    {
      "name": "aidefense_analyzer",
      "description": "Cisco AI Defense cloud-based threat detection",
      "available": true,
      "requires_api_key": true
    },
    {
      "name": "virustotal_analyzer",
      "description": "Hash-based malware detection for binary files via VirusTotal",
      "available": true,
      "requires_api_key": true
    },
    {
      "name": "trigger_analyzer",
      "description": "Trigger specificity analysis for overly generic descriptions",
      "available": true
    },
    {
      "name": "meta_analyzer",
      "description": "Second-pass LLM analysis for false positive filtering",
      "available": true,
      "requires": "2+ analyzers, LLM API key"
    }
  ]
}
```

## Error Response Format

```json
{
  "detail": "Error message describing what went wrong"
}
```

| Status Code | Error | Solution |
| --- | --- | --- |
| 400 | Invalid request | Check JSON format and required fields |
| 404 | Skill not found | Verify directory path exists |
| 413 | Upload too large | Reduce ZIP size below upload limit |
| 422 | Validation error | Check field names/types in request body |
| 500 | Scan failed | Check logs for detailed error |
