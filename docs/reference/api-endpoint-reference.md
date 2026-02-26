<!-- GENERATED FILE. DO NOT EDIT DIRECTLY.
     Regenerate with: uv run python scripts/generate_reference_docs.py -->

# API Endpoint Reference

This page is generated from `skill_scanner/api/router.py`.

> [!TIP]
> **Interactive Docs**
> Start the API server with `skill-scanner-api` and open `/docs` (Swagger UI) or `/redoc` for interactive exploration.

> [!NOTE]
> **Full details**
> For complete request/response schemas, parameter descriptions, and edge-case guidance, see the hand-written [API Endpoints Detail](../user-guide/api-endpoints-detail.md).

## Endpoints

| Method | Path | Response Model | Description |
|---|---|---|---|
| `GET` | `/` | `dict` | Root endpoint. |
| `GET` | `/analyzers` | `-` | List available analyzers. |
| `GET` | `/health` | `HealthResponse` | Health check endpoint. |
| `POST` | `/scan` | `ScanResponse` | Scan a single skill package. |
| `POST` | `/scan-batch` | `-` | Scan multiple skills in a directory (batch scan). |
| `GET` | `/scan-batch/{scan_id}` | `-` | Get results of a batch scan. |
| `POST` | `/scan-upload` | `-` | Scan an uploaded skill package (ZIP file). |

## Quick Examples

### Health check

```bash
curl http://localhost:8000/health
```

```json
{
  "status": "healthy",
  "version": "1.0.0",
  "analyzers_available": ["static_analyzer", "bytecode_analyzer", "pipeline_analyzer"]
}
```

### Scan a skill

```bash
curl -X POST http://localhost:8000/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "skill_directory": "/path/to/my-skill",
    "use_llm": false,
    "policy": "balanced"
  }'
```

```json
{
  "scan_id": "a1b2c3d4",
  "skill_name": "my-skill",
  "is_safe": false,
  "max_severity": "HIGH",
  "findings_count": 3,
  "scan_duration_seconds": 1.42,
  "timestamp": "2025-01-15T10:30:00Z",
  "findings": [{"...": "..."}]
}
```

### Upload and scan

```bash
curl -X POST http://localhost:8000/scan-upload \
  -F 'file=@my-skill.zip'
```

## Request/Response Models

### `ScanRequest`

| Field | Type |
|---|---|
| `skill_directory` | `str` |
| `policy` | `str | None` |
| `custom_rules` | `str | None` |
| `use_llm` | `bool` |
| `llm_provider` | `str | None` |
| `use_behavioral` | `bool` |
| `use_virustotal` | `bool` |
| `vt_upload_files` | `bool` |
| `use_aidefense` | `bool` |
| `aidefense_api_url` | `str | None` |
| `use_trigger` | `bool` |
| `enable_meta` | `bool` |
| `llm_consensus_runs` | `int` |

### `ScanResponse`

| Field | Type |
|---|---|
| `scan_id` | `str` |
| `skill_name` | `str` |
| `is_safe` | `bool` |
| `max_severity` | `str` |
| `findings_count` | `int` |
| `scan_duration_seconds` | `float` |
| `timestamp` | `str` |
| `findings` | `list[dict]` |

### `HealthResponse`

| Field | Type |
|---|---|
| `status` | `str` |
| `version` | `str` |
| `analyzers_available` | `list[str]` |

### `BatchScanRequest`

| Field | Type |
|---|---|
| `skills_directory` | `str` |
| `policy` | `str | None` |
| `custom_rules` | `str | None` |
| `recursive` | `bool` |
| `check_overlap` | `bool` |
| `use_llm` | `bool` |
| `llm_provider` | `str | None` |
| `use_behavioral` | `bool` |
| `use_virustotal` | `bool` |
| `vt_upload_files` | `bool` |
| `use_aidefense` | `bool` |
| `aidefense_api_url` | `str | None` |
| `use_trigger` | `bool` |
| `enable_meta` | `bool` |
| `llm_consensus_runs` | `int` |

## Notes

- API behavior is policy-aware and mirrors CLI analyzer selection flags.
- API keys for VirusTotal and AI Defense are passed via request headers (`X-VirusTotal-Key`, `X-AIDefense-Key`), not in the JSON body.
- Set `SKILL_SCANNER_ALLOWED_ROOTS` to restrict which directories the API can scan.
- All `POST` endpoints accept JSON bodies. File upload uses `multipart/form-data`.
