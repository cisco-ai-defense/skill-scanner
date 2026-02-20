# User Guide

Skill Scanner ships as a CLI tool, a Python library, and a REST API. This section covers day-to-day usage for all three interfaces, plus scan-policy tuning and configuration.

## What are you trying to do?

<div class="feature-grid">
  <a class="feature-card" href="./cli-usage">
    <div class="feature-card-title">Scan a skill locally</div>
    <div class="feature-card-desc">Run the CLI against a skill directory on your machine or in a CI pipeline.</div>
  </a>
  <a class="feature-card" href="./python-sdk">
    <div class="feature-card-title">Embed scanning in Python</div>
    <div class="feature-card-desc">Import the SDK to scan skills programmatically inside your own applications.</div>
  </a>
  <a class="feature-card" href="./api-server">
    <div class="feature-card-title">Integrate via REST API</div>
    <div class="feature-card-desc">Upload skill ZIPs over HTTP for CI/CD, web portals, or service-to-service workflows.</div>
  </a>
  <a class="feature-card" href="./scan-policies-overview">
    <div class="feature-card-title">Tune detection sensitivity</div>
    <div class="feature-card-desc">Choose a preset policy or write custom YAML to control which rules fire and at what severity.</div>
  </a>
</div>

## Start Here

- [Installation and Configuration](/user-guide/installation-and-configuration)
- [Quick Start](/getting-started/quick-start)
- [CLI Usage](/user-guide/cli-usage)

## Advanced Topics

- [Scan Policies Overview](/user-guide/scan-policies-overview)
- [Custom Policy Configuration](/user-guide/custom-policy-configuration)
- [API Server](/user-guide/api-server)
- [API Rationale](/user-guide/api-rationale) — when to use the API vs CLI/SDK
- [Python SDK](/user-guide/python-sdk)
