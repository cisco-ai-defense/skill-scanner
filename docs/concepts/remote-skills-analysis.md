# Remote Skills Analysis

## Summary

Agent skills are local file packages. Skill Scanner analyzes directories or uploaded archives that are extracted locally for scanning. It does not connect to remote skill hosts because the skill format is file-based.

## Code Evidence

### Local Loader Model

[`skill_scanner/core/loader.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/loader.py) expects a local directory containing `SKILL.md` and related files.

### Local Scan Entrypoints

- CLI commands (`scan`, `scan-all`) accept local paths
- API upload flow (`/scan-upload`) extracts uploaded ZIP files to local temp directories before scanning
- Batch API flow (`/scan-batch`) scans local directories

## MCP Servers vs Agent Skills

| Dimension | MCP Server | Agent Skill Package |
|---|---|---|
| Primary access model | Remote protocol endpoint | Local file tree |
| Scanner input | URL/connection details | Directory path or uploaded ZIP |
| Network requirement for scan target | Yes | No |
| API server necessity | Usually core to workflow | Optional integration layer |

## Why the API Server Still Matters

The Skill Scanner API is still useful for operational workflows:

- CI/CD integration using HTTP requests
- Web UI upload and review flows
- Service-to-service integration in platform architectures
- Asynchronous batch scans and polling

## Documentation Positioning

Use this framing consistently:

- Skills are local packages, not remote services
- CLI is the default interface for local workflows
- API is an optional interface for integration and automation workflows
