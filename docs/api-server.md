# API Server Documentation

## Overview

The Skill Scanner API Server provides a REST interface for uploading and scanning Agent Skills packages, enabling integration with web applications, CI/CD pipelines, and other services.

**Key Points**:

- **Skills are local packages**: Skills are local file packages that users install on their machines, not remote services
- **API enables uploads**: The API allows uploading skill ZIP files for scanning via HTTP
- **For integration workflows**: Useful for CI/CD, web interfaces, and service integrations
- **CLI is primary**: For most use cases, the CLI is the recommended interface

**Technology**: FastAPI with async support
**Endpoints**: 6 REST endpoints
**Documentation**: Auto-generated Swagger/ReDoc
**Status**: Production ready

## Warnings

This server is for development use, and is unauthenticated. We recommend you do not expose it on any interface except localhost, since these APIs can be used for a denial of wallet attack on your API keys, or denial of service on the hosting machine through uploaded zipbombs.

## Starting the Server

### Command Line

```bash
# Start server (default: localhost:8000)
skill-scanner-api

# Custom port
skill-scanner-api --port 8080

# Development mode with auto-reload
skill-scanner-api --reload

# Custom host and port
skill-scanner-api --host 127.0.0.1 --port 9000
```

### Programmatic

```python
from skill_scanner.api_server import run_server

run_server(host="127.0.0.1", port=8000, reload=False)
```

## Endpoints

### Health Check

```http
GET /health
```

Returns server status and available analyzers.

**Response:**

```json
{
  "status": "healthy",
  "version": "0.2.0",
  "analyzers_available": [
    "static_analyzer",
    "behavioral_analyzer",
    "llm_analyzer",
    "aidefense_analyzer"
  ]
}
```

### Scan Single Skill

```http
POST /scan
Content-Type: application/json

{
  "skill_directory": "/path/to/skill",
  "use_behavioral": false,
  "use_llm": false,
  "llm_provider": "anthropic",
  "use_aidefense": false,
  "aidefense_api_key": null
}
```

**Request Parameters:**

| Parameter           | Type    | Default     | Description                                              |
| ------------------- | ------- | ----------- | -------------------------------------------------------- |
| `skill_directory`   | string  | required    | Path to skill directory                                  |
| `use_behavioral`    | boolean | false       | Enable behavioral dataflow analyzer                      |
| `use_llm`           | boolean | false       | Enable LLM semantic analyzer                             |
| `llm_provider`      | string  | "anthropic" | LLM provider (anthropic, openai, azure, bedrock, gemini) |
| `use_aidefense`     | boolean | false       | Enable Cisco AI Defense analyzer                         |
| `aidefense_api_key` | string  | null        | AI Defense API key (or set `AI_DEFENSE_API_KEY` env var) |

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

### Upload and Scan Skill

**Primary use case**: Upload a skill package as a ZIP file for scanning. This is the main workflow for CI/CD and web interfaces.

```http
POST /scan-upload
Content-Type: multipart/form-data

file: skill.zip
use_llm: false
llm_provider: anthropic
```

Uploads a ZIP file containing a skill package and scans it. The ZIP file is extracted to a temporary directory, scanned, and then cleaned up.

**Response:** Same as `/scan`

### Batch Scan (Async)

```http
POST /scan-batch
Content-Type: application/json

{
  "skills_directory": "/path/to/skills",
  "recursive": false,
  "use_behavioral": false,
  "use_llm": false,
  "llm_provider": "anthropic",
  "use_aidefense": false,
  "aidefense_api_key": null
}
```

**Response:**

```json
{
  "scan_id": "uuid",
  "status": "processing",
  "message": "Batch scan started. Use GET /scan-batch/{scan_id} to check status."
}
```

### Get Batch Scan Results

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

### List Analyzers

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
      "rules_count": "40+"
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
    }
  ]
}
```

## Interactive Documentation

When the server is running, visit:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## Usage Examples

### curl

```bash
# Health check
curl http://localhost:8000/health

# Scan skill (static only)
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "skill_directory": "/path/to/skill"
  }'

# Scan with all analyzers
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "skill_directory": "/path/to/skill",
    "use_behavioral": true,
    "use_llm": true,
    "llm_provider": "anthropic",
    "use_aidefense": true
  }'

# Upload and scan
curl -X POST http://localhost:8000/scan-upload \
  -F "file=@skill.zip" \
  -F "use_behavioral=true" \
  -F "use_llm=true" \
  -F "use_aidefense=true"

# Batch scan with all analyzers
curl -X POST http://localhost:8000/scan-batch \
  -H "Content-Type: application/json" \
  -d '{
    "skills_directory": "/path/to/skills",
    "recursive": true,
    "use_behavioral": true,
    "use_llm": true,
    "use_aidefense": true
  }'

# Check batch status
curl http://localhost:8000/scan-batch/{scan_id}
```

### Python

```python
import requests

# Scan skill
response = requests.post(
    "http://localhost:8000/scan",
    json={
        "skill_directory": "/path/to/skill",
        "use_llm": True,
        "llm_provider": "anthropic"
    }
)

result = response.json()
print(f"Safe: {result['is_safe']}")
print(f"Findings: {result['findings_count']}")

# Upload ZIP
with open("skill.zip", "rb") as f:
    response = requests.post(
        "http://localhost:8000/scan-upload",
        files={"file": f},
        data={"use_llm": "false"}
    )

# Batch scan (async)
response = requests.post(
    "http://localhost:8000/scan-batch",
    json={
        "skills_directory": "/path/to/skills",
        "recursive": True
    }
)

scan_id = response.json()["scan_id"]

# Poll for results
import time
while True:
    response = requests.get(f"http://localhost:8000/scan-batch/{scan_id}")
    status = response.json()

    if status["status"] == "completed":
        print("Scan complete!")
        print(status["result"])
        break
    elif status["status"] == "error":
        print(f"Scan failed: {status['error']}")
        break

    time.sleep(5)
```

### JavaScript

```javascript
// Scan skill
const response = await fetch("http://localhost:8000/scan", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    skill_directory: "/path/to/skill",
    use_llm: false,
  }),
});

const result = await response.json();
console.log(`Safe: ${result.is_safe}`);
console.log(`Findings: ${result.findings_count}`);

// Upload ZIP
const formData = new FormData();
formData.append("file", skillZipFile);
formData.append("use_llm", "false");

const uploadResponse = await fetch("http://localhost:8000/scan-upload", {
  method: "POST",
  body: formData,
});
```

## Configuration

### Environment Variables

```bash
# LLM configuration (for LLM analyzer)
export SKILL_SCANNER_LLM_API_KEY=your_key
export SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022

# For Azure OpenAI
export SKILL_SCANNER_LLM_BASE_URL=https://your-resource.openai.azure.com
export SKILL_SCANNER_LLM_API_VERSION=2025-01-01-preview

# For custom Anthropic endpoint (e.g., Azure-hosted Claude)
export ANTHROPIC_API_BASE=https://your-endpoint.com/anthropic

# Cisco AI Defense (for aidefense analyzer)
export AI_DEFENSE_API_KEY=your_key

# Server settings (optional)
export API_HOST=localhost
export API_PORT=8000
```

### CORS (for web apps)

To enable CORS, modify `api_server.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## CI/CD Integration

### GitHub Actions

```yaml
name: Scan Skills via API

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Start API Server
        run: |
          pip install -r requirements.txt
          skill-scanner-api &
          sleep 5

      - name: Scan Skills
        run: |
          curl -X POST http://localhost:8000/scan-batch \
            -H "Content-Type: application/json" \
            -d '{"skills_directory": "./skills"}' \
            > scan_id.json

          SCAN_ID=$(jq -r '.scan_id' scan_id.json)

          # Poll for results
          while true; do
            STATUS=$(curl http://localhost:8000/scan-batch/$SCAN_ID | jq -r '.status')
            if [ "$STATUS" = "completed" ]; then
              break
            fi
            sleep 10
          done

          # Get results
          curl http://localhost:8000/scan-batch/$SCAN_ID > results.json

          # Check for critical findings
          CRITICAL=$(jq '.result.summary.findings_by_severity.critical' results.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Critical findings detected!"
            exit 1
          fi
```

### Docker

```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY skill_scanner/ ./skill_scanner/

EXPOSE 8000

CMD ["python", "-m", "skill_scanner.api_cli", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
# Build and run
docker build -t skill-scanner-api .
docker run -p 8000:8000 \
  -e SKILL_SCANNER_LLM_API_KEY=your_key \
  -e SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022 \
  skill-scanner-api
```

## Error Handling

### Common Errors

| Status Code | Error               | Solution                                |
| ----------- | ------------------- | --------------------------------------- |
| 400         | Invalid request     | Check JSON format and required fields   |
| 404         | Skill not found     | Verify directory path exists            |
| 500         | Scan failed         | Check logs for detailed error           |
| 503         | Service unavailable | Server may be overloaded or starting up |

### Error Response Format

```json
{
  "detail": "Error message describing what went wrong"
}
```

## Performance

### Benchmarks

- Static analysis: ~100-200 skills/minute
- With LLM: ~5-10 skills/minute
- File upload: Limited by network and ZIP size

### Optimization Tips

1. **Batch scanning**: Use `/scan-batch` for multiple skills
2. **Caching**: Implement Redis for result caching
3. **Async workers**: Use Celery for background processing
4. **Load balancing**: Run multiple API instances behind nginx

## Security

### Authentication

Add API key authentication:

```python
from fastapi import Security, HTTPException
from fastapi.security import APIKeyHeader

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME)

async def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != os.getenv("API_KEY"):
        raise HTTPException(status_code=403, detail="Invalid API Key")
    return api_key

@app.post("/scan")
async def scan_skill(request: ScanRequest, api_key: str = Depends(get_api_key)):
    # ... scan logic
```

### Rate Limiting

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/scan")
@limiter.limit("10/minute")
async def scan_skill(request: Request, scan_request: ScanRequest):
    # ... scan logic
```

### HTTPS

Run behind reverse proxy (nginx, Caddy) with TLS:

```nginx
server {
    listen 443 ssl;
    server_name api.skill_scanner.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Monitoring

### Health Checks

```bash
# Check if server is up
curl http://localhost:8000/health

# Monitor continuously
watch -n 5 'curl -s http://localhost:8000/health | jq'
```

### Logging

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
```

### Metrics

Integrate with Prometheus:

```python
from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app)
```

## Troubleshooting

### Server won't start

```bash
# Check if port is already in use
lsof -i :8000

# Try different port
skill-scanner-api --port 8080
```

### LLM analyzer not available

```bash
# Install dependencies
pip install anthropic openai

# Set API key
export SKILL_SCANNER_LLM_API_KEY=your_key
export SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022
```

### Slow performance

- Enable caching for repeated scans
- Use batch endpoints instead of individual scans
- Consider horizontal scaling

## Conclusion

The API server makes the Skill Scanner accessible to any application or service, enabling automated security scanning at scale. Combined with the LLM analyzer, it provides powerful threat detection capabilities through a simple REST interface. Supports Codex Skills and Cursor Agent Skills formats.
