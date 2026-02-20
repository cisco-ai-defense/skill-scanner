# API Operations

Production deployment, CI/CD integration, security hardening, monitoring, and troubleshooting for the Skill Scanner API server. For endpoint documentation, see [API Endpoints Detail](/user-guide/api-endpoints-detail).

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
          pip install cisco-ai-skill-scanner
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

COPY pyproject.toml .
COPY skill_scanner/ ./skill_scanner/

RUN pip install . && \
    adduser --disabled-password --no-create-home appuser

USER appuser

EXPOSE 8000

CMD ["skill-scanner-api", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
# Build and run
docker build -t skill-scanner-api .
docker run -p 8000:8000 \
  -e SKILL_SCANNER_LLM_API_KEY=your_key \
  -e SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022 \
  skill-scanner-api
```

## Security

### Authentication

Add API key authentication:

```python
import os

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
# Reinstall scanner package and ensure provider dependencies are present
pip install -U cisco-ai-skill-scanner

# Set model credentials
export SKILL_SCANNER_LLM_API_KEY=your_key
export SKILL_SCANNER_LLM_MODEL=claude-3-5-sonnet-20241022
```

### Slow performance

- Enable caching for repeated scans
- Use batch endpoints instead of individual scans
- Consider horizontal scaling
