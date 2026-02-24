# Skill Scanner Documentation

Security scanning for AI agent skills. Detects prompt injection, data exfiltration, and malicious code patterns with multi-engine analysis.

## Getting Started

- [Quick Start](getting-started/quick-start.md) -- Install, configure, and run your first scan

## Architecture

- [Overview](architecture/index.md) -- System design, scanning pipeline, and risk model
- [Scanning Pipeline](architecture/scanning-pipeline.md) -- How files flow through the analysis stages
- [Threat Taxonomy](architecture/threat-taxonomy.md) -- AITech threat taxonomy with examples
- [Binary Handling](architecture/binary-handling.md) -- How compiled and binary files are processed

### Analyzers

- [Analyzer Overview](architecture/analyzers/index.md) -- Summary of all available analyzers
- [Static Analyzer](architecture/analyzers/static-analyzer.md) -- YAML + YARA pattern matching
- [Behavioral Analyzer](architecture/analyzers/behavioral-analyzer.md) -- AST dataflow analysis
- [LLM Analyzer](architecture/analyzers/llm-analyzer.md) -- LLM-as-a-judge semantic analysis
- [Meta-Analyzer](architecture/analyzers/meta-analyzer.md) -- False positive filtering and prioritization
- [Meta & External Analyzers](architecture/analyzers/meta-and-external-analyzers.md) -- AI Defense, VirusTotal, and meta-analysis
- [AI Defense Analyzer](architecture/analyzers/aidefense-analyzer.md) -- Cisco AI Defense cloud analyzer
- [Writing Custom Rules](architecture/analyzers/writing-custom-rules.md) -- Author YAML signatures, YARA rules, and Python checks

## Concepts

- [Security Model](concepts/security-model.md) -- Threat model and security assumptions
- [Remote Skills Analysis](concepts/remote-skills-analysis.md) -- Scanning skills fetched from remote sources

## Features

- [Feature Overview](features/index.md) -- All scanner capabilities at a glance

## User Guide

- [User Guide Overview](user-guide/index.md) -- Getting the most out of Skill Scanner
- [Installation & Configuration](user-guide/installation-and-configuration.md) -- Setup and environment
- [CLI Usage](user-guide/cli-usage.md) -- Command-line interface
- [Python SDK](user-guide/python-sdk.md) -- Programmatic scanning
- [API Server](user-guide/api-server.md) -- REST API server
- [API Operations](user-guide/api-operations.md) -- API usage patterns
- [API Endpoints Detail](user-guide/api-endpoints-detail.md) -- Endpoint reference
- [API Rationale](user-guide/api-rationale.md) -- Design decisions behind the API
- [Scan Policies Overview](user-guide/scan-policies-overview.md) -- Policy presets and tuning
- [Custom Policy Configuration](user-guide/custom-policy-configuration.md) -- Writing your own policy YAML

## Guides

- [Examples & How-To](guides/examples-and-how-to.md) -- Common workflows and recipes

## Reference

- [Reference Overview](reference/index.md) -- Quick links to all reference material
- [CLI Command Reference](reference/cli-command-reference.md) -- All commands and options
- [API Endpoint Reference](reference/api-endpoint-reference.md) -- REST API endpoints
- [Configuration Reference](reference/configuration-reference.md) -- Environment variables and config
- [Output Formats](reference/output-formats.md) -- JSON, SARIF, Markdown, HTML, and table formats
- [Policy Quick Reference](reference/policy-quick-reference.md) -- Compact policy section and knob reference
- [Dependencies & LLM Providers](reference/dependencies-and-llm-providers.md) -- Supported providers and extras

## Development

- [Development Overview](development/index.md) -- Contributing to Skill Scanner
- [Setup & Testing](development/setup-and-testing.md) -- Dev environment and test suite
- [Integrations](development/integrations.md) -- CI/CD, GitHub Code Scanning, and more
