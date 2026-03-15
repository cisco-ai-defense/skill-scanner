# API Server

The Skill Scanner API Server provides a REST interface for uploading and scanning Agent Skills packages, enabling integration with web applications, CI/CD pipelines, and other services.

> [!WARNING]
> **Development Use Only**
> This server is unauthenticated by default. Do not expose it on any interface except localhost -- the APIs can be used for denial-of-wallet attacks on your API keys or denial-of-service via uploaded zipbombs. See [API Operations](api-operations.md#security) for authentication and hardening guidance.

**Technology**: FastAPI with async support &bull; **Endpoints**: 7 REST endpoints (+ 3 UI helpers) &bull; **Docs**: auto-generated Swagger/ReDoc &bull; **Optional UI**: local web GUI at `/ui`

## Starting the Server

```bash
skill-scanner-api                              # default: localhost:8000
skill-scanner-api --port 8080                  # custom port
skill-scanner-api --reload                     # dev mode with auto-reload
skill-scanner-api --host 127.0.0.1 --port 9000 # custom host + port
```

Or programmatically:

```python
from skill_scanner.api.api_server import run_server

run_server(host="127.0.0.1", port=8000, reload=False)
```

## Endpoints Summary

| Endpoint | Method | Description |
| --- | --- | --- |
| `/` | GET | Service metadata and links |
| `/health` | GET | Server status and available analyzers |
| `/scan` | POST | Scan a skill by local directory path |
| `/scan-html` | POST | Scan a skill by local directory path and return an HTML report |
| `/scan-upload` | POST | Upload a skill ZIP and scan it (JSON summary) |
| `/scan-upload-html` | POST | Upload a skill ZIP and return an HTML report |
| `/scan-upload-markdown` | POST | Upload a skill ZIP and return a Markdown report |
| `/scan-batch` | POST | Start an async batch scan |
| `/scan-batch/{scan_id}` | GET | Poll batch scan status/results |
| `/analyzers` | GET | List all available analyzers |

For full request schemas, parameters, and response formats, see **[API Endpoints Detail](api-endpoints-detail.md)**.

Upload guardrails: max upload `50 MB`, max ZIP entries `500`, max uncompressed size `200 MB`.

## Built-in Web UI

When the API server is running, a lightweight local web UI is available at:

- `http://localhost:8000/ui`

The UI is served from the same FastAPI application and uses the `/scan-html` and `/scan-upload-*` endpoints to:

- Drag-and-drop a skill ZIP or choose a local skill folder (containing `SKILL.md`)
- Run scans with the same analyzers/policies as the CLI
- View the interactive HTML report inline
- Download both HTML and Markdown versions of the report

> The UI is intended for **local** use only (e.g., localhost in a browser). It does not add authentication or change any security properties of the API server — the warnings in the section above still apply.

## Interactive Documentation

When the server is running, visit:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Quick Test

```bash
# Verify the server is running
curl http://localhost:8000/health

# Run a basic scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"skill_directory": "/path/to/skill"}'
```

For complete request/response examples in curl, Python, and JavaScript, see **[API Endpoints Detail](api-endpoints-detail.md)**. For a quick-lookup table of all endpoints and Pydantic models, see **[API Endpoint Reference](../reference/api-endpoint-reference.md)**.

## Configuration

### Environment Variables

The API server uses the same environment variables as the CLI. The most common ones:

```bash
export SKILL_SCANNER_LLM_API_KEY=your_key
export SKILL_SCANNER_LLM_MODEL=anthropic/claude-sonnet-4-20250514
export AI_DEFENSE_API_KEY=your_key
```

Server bind settings are controlled by CLI flags (`--host`, `--port`) when launching `skill-scanner-api`. See **[Configuration Reference](../reference/configuration-reference.md)** for the full list of environment variables.

### CORS (for web apps)

To enable CORS, create a wrapper that imports the app from the router module and adds middleware:

```python
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from skill_scanner.api.router import router

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)
```

## Performance

- `/scan-batch` runs as a FastAPI background task and is polled by `scan_id`
- Batch status/results are stored in an in-memory bounded cache (`max 1000` entries, `1 hour` TTL)
- `/scan` and `/scan-upload` execute scans via threadpool workers to avoid blocking the event loop
- Throughput depends on analyzer mix, model/provider latency, and uploaded archive size

## Next Steps

- **[API Endpoints Detail](api-endpoints-detail.md)** — full request/response schemas for every endpoint
- **[API Operations](api-operations.md)** — CI/CD, Docker, security, monitoring, and troubleshooting
- **[API Rationale](api-rationale.md)** — when to use the API vs CLI/SDK
