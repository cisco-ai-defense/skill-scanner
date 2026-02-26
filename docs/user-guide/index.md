# User Guide

Skill Scanner ships as a CLI tool, a Python library, and a REST API. This section covers day-to-day usage for all three interfaces, plus scan-policy tuning and configuration.

## What are you trying to do?

- **[Scan a skill locally](./cli-usage)** -- Run the CLI against a skill directory on your machine or in a CI pipeline.
- **[Embed scanning in Python](./python-sdk)** -- Import the SDK to scan skills programmatically inside your own applications.
- **[Integrate via REST API](./api-server)** -- Upload skill ZIPs over HTTP for CI/CD, web portals, or service-to-service workflows.
- **[Tune detection sensitivity](./scan-policies-overview)** -- Choose a preset policy or write custom YAML to control which rules fire and at what severity.

## Start Here

- [Installation and Configuration](installation-and-configuration.md)
- [Quick Start](../getting-started/quick-start.md)
- [CLI Usage](cli-usage.md)

## Advanced Topics

- [Scan Policies Overview](scan-policies-overview.md)
- [Custom Policy Configuration](custom-policy-configuration.md)
- [API Server](api-server.md)
- [API Rationale](api-rationale.md) — when to use the API vs CLI/SDK
- [Python SDK](python-sdk.md)
