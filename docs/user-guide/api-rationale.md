# API Server Rationale

## Context

Skill Scanner primarily analyzes local skill packages. Because the core scan target is local files, the CLI and Python SDK cover most development and authoring workflows.

## Why an API Exists

The API server is an optional integration layer, not a requirement for scanning.

It provides:

- HTTP-native integration for CI/CD systems
- upload-based workflows for web applications
- asynchronous batch processing and result polling
- service-to-service integration in distributed architectures

## When to Use Which Interface

::: info Quick Decision
**CLI/SDK** — local development, one-off scans, scripted scans in the same runtime environment.

**API** — external systems that already integrate via REST, web upload/review portals, queued or remote orchestration workflows.
:::

## Practical Recommendation

Keep the API server available and documented as an optional interface.

- Position CLI as the default user path
- Position API as integration infrastructure
- Avoid describing the API as a remote skill access mechanism

See:

- [API Server](/user-guide/api-server) for endpoint usage
- [Remote Skills Analysis](/concepts/remote-skills-analysis) for local-vs-remote model details
