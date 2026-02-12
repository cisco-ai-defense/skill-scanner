# Skill Scanner — Feature Reference

> **Package:** `cisco-ai-skill-scanner`
> **License:** Apache-2.0
> **Python:** 3.10 – 3.13
> **Current branch:** `feat/scan-policy-and-analyzers` (4 commits ahead of `main`)

This document is the single source of truth for every feature in the Skill Scanner project. It compares what is available on the **`main`** branch (latest public release) versus the **`feat/scan-policy-and-analyzers`** local feature branch.

---

## Feature Availability Matrix

| # | Feature | `main` | `local` | Category | Change Summary |
|---|---------|:------:|:-------:|----------|----------------|
| 1 | [Static Pattern Analyzer (YAML + YARA)](#1-static-pattern-analyzer-yaml--yara) | Yes | Enhanced | Core Analyzer | Integrated scan policy (rule scoping, disabled rules, severity overrides); added Magika-based file classification; migrated from `yara-python` to `yara-x`; tightened YAML signature patterns |
| 2 | [LLM Semantic Analyzer](#2-llm-semantic-analyzer) | Yes | Enhanced | Optional Analyzer | Prompt builder now includes scan-policy context; improved error handling in request handler; wired into analyzer factory |
| 3 | [Meta-Analyzer (FP Filtering)](#3-meta-analyzer-fp-filtering) | Yes | Enhanced | Optional Analyzer | Better analyzer-factory integration; richer metadata retained on filtered findings |
| 4 | [Behavioral / Dataflow Analyzer](#4-behavioral--dataflow-analyzer) | Yes | Yes | Optional Analyzer | No changes |
| 5 | [VirusTotal Analyzer](#5-virustotal-analyzer) | Yes | Enhanced | Optional Analyzer | Post-processing tied to scan-policy validation behavior; improved API rate-limit and error handling |
| 6 | [Cisco AI Defense Analyzer](#6-cisco-ai-defense-analyzer) | Yes | Enhanced | Optional Analyzer | Refactored initialization; integrated with analyzer factory and scan policy |
| 7 | [Trigger Analyzer](#7-trigger-analyzer) | Yes | Yes | Optional Analyzer | No changes |
| 8 | [Cross-Skill Scanner](#8-cross-skill-scanner) | Yes | Yes | Optional Analyzer | No changes |
| 9 | [Pipeline Analyzer](#9-pipeline-analyzer) | No | **New** | Core Analyzer | Shell pipeline taint analysis detecting `curl\|sh`, trusted installer domains, benign vs. dangerous pipe classification |
| 10 | [Bytecode Analyzer](#10-bytecode-analyzer) | No | **New** | Core Analyzer | Detects `.pyc` without source, bytecode version mismatches, header integrity validation |
| 11 | [Scan Policy System](#11-scan-policy-system) | No | **New** | Policy Engine | Full YAML policy engine with 12+ config sections; deep-merge on top of built-in defaults |
| 12 | [Policy Presets (strict / balanced / permissive)](#12-policy-presets) | No | **New** | Policy Engine | Three ready-to-use presets covering compliance audits through rapid prototyping |
| 13 | [Policy TUI (Interactive Configurator)](#13-policy-tui-interactive-configurator) | No | **New** | CLI / UX | Textual-based terminal wizard for building custom scan policies interactively |
| 14 | [Command Safety Engine](#14-command-safety-engine) | No | **New** | Detection | Tiered command classification (safe/caution/risky/dangerous) with GTFOBins pattern detection |
| 15 | [Magika File-Type Detection](#15-magika-file-type-detection) | No | **New** | File Handling | AI-powered content-type detection (200+ types, ~99% accuracy) replacing extension-only heuristics |
| 16 | [Content Extractor (ZIP/TAR/DOCX/XLSX)](#16-content-extractor-ziptardocxxlsx) | No | **New** | File Handling | Safe archive extraction with zip-bomb, path-traversal, and file-limit protections |
| 17 | [Analyzability Scoring](#17-analyzability-scoring) | No | **New** | Reporting | 0-100 scan confidence score based on source-vs-binary ratio, SKILL.md quality, and file limits |
| 18 | [Analyzer Factory](#18-analyzer-factory) | No | **New** | Architecture | Centralized `build_core_analyzers()` / `build_analyzers()` replacing scattered init logic |
| 19 | [Policy-Driven Knob System](#19-policy-driven-knob-system) | No | **New** | Policy Engine | All tunable parameters live in named policy sections (file_limits, analysis_thresholds, pipeline, file_classification, etc.) — no per-rule property layer |
| 20 | [Policy Benchmark System](#20-policy-benchmark-system) | No | **New** | Evals | Cross-policy comparison on ~119-skill corpus with 10 policy variants; MD + JSON output |
| 21 | [Eval-Skills Benchmark](#21-eval-skills-benchmark) | Yes | Enhanced | Evals | Runners moved to `evals/runners/`; added `__init__.py`; updated imports and paths |
| 22 | [Taxonomy Enforcement (check-taxonomy)](#22-taxonomy-enforcement-check-taxonomy) | No | **New** | CI / Governance | Pre-commit hook validating `ThreatCategory` enum stays in sync with Cisco AITech taxonomy |
| 23 | [Makefile Build System](#23-makefile-build-system) | No | **New** | Developer Tooling | `make benchmark`, `make test`, `make lint`, `make clean` with auto-tagged checkpoint output |
| 24 | [CLI (scan, scan-all, list-analyzers, etc.)](#24-cli) | Yes | Enhanced | CLI | Added `generate-policy` and `configure-policy` commands; new `--policy` flag; major refactor (~1094 lines) |
| 25 | [REST API Server](#25-rest-api-server) | Yes | Enhanced | API | Router refactored with updated Pydantic models; `api_server.py` simplified (--616 lines); policy support added |
| 26 | [Pre-Commit Hook](#26-pre-commit-hook) | Yes | Enhanced | CI Integration | Added scan-policy support and improved `.skill_scannerrc` configuration handling |
| 27 | [SARIF Reporter](#27-sarif-reporter) | Yes | Yes | Reporting | No changes |
| 28 | [Multiple Output Formats](#28-multiple-output-formats) | Yes | Yes | Reporting | No changes |
| 29 | [Cisco AITech Threat Taxonomy](#29-cisco-aitech-threat-taxonomy) | Yes | Enhanced | Taxonomy | Taxonomy validation enforced via `check-taxonomy` pre-commit hook; updated threat mappings for new analyzers |
| 30 | [YARA Rule Library (13 rule files)](#30-yara-rule-library) | Yes | Enhanced | Detection | Migrated from `yara-python` to `yara-x` (Rust-based); tightened patterns; refactored mode config |
| 31 | [Static Analysis Subsystem (CFG, Taint, Dataflow)](#31-static-analysis-subsystem) | Yes | Yes | Core Engine | No changes |
| 32 | [LLM Provider Abstraction (LiteLLM)](#32-llm-provider-abstraction) | Yes | Yes | Integration | No changes |
| 33 | [Pre-Commit Config (.pre-commit-config.yaml)](#33-pre-commit-config) | Yes | Enhanced | CI / Quality | Added `gitleaks` and `check-taxonomy` hooks; updated `detect-private-key` exclusions; bumped hook versions |
| 34 | [Documentation Suite](#34-documentation-suite) | Yes | Enhanced | Documentation | Added `docs/scan-policy.md` (691 lines); updated architecture, quickstart, and threat-taxonomy docs |
| 35 | [GitHub Actions CI/CD](#35-github-actions-cicd) | Yes | Yes | CI/CD | No changes |
| 36 | [Example Scripts](#36-example-scripts) | Yes | Yes | Documentation | Minor import path updates |
| 37 | [Gitleaks Integration](#37-gitleaks-integration) | No | **New** | CI / Security | `.gitleaksignore` + pre-commit hook for secret scanning with known-safe pattern whitelisting |

**Legend:** Yes = present and unchanged, Enhanced = present on main but improved on local, **New** = only exists on the local branch, `local` = `feat/scan-policy-and-analyzers`.

---

## Detailed Feature Descriptions

---

### 1. Static Pattern Analyzer (YAML + YARA)

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/static.py`, `skill_scanner/data/packs/core/signatures/`, `skill_scanner/data/packs/core/yara/*.yara` |
| **Branch** | `main`: Yes — `local`: Enhanced |
| **Requires** | Nothing (runs offline, no API keys) |

**What it is:**
The primary detection engine. It scans every file in a skill directory using two complementary pattern systems:

- **YAML signature rules** — regex-based patterns defined in `data/packs/core/signatures/`, grouped by category (prompt injection, command injection, hardcoded secrets, etc.). Each rule specifies `id`, `category`, `severity`, `patterns`, and optional `file_types`.
- **YARA rules** — compiled rules in `skill_scanner/data/packs/core/yara/` for binary and text matching. Covers 13 threat categories including prompt injection, credential harvesting, unicode steganography, and tool-chaining abuse.

The static analyzer also performs:
- **Manifest analysis** — checks SKILL.md frontmatter for suspicious fields.
- **Instruction analysis** — scans SKILL.md body for prompt-injection patterns.
- **Code analysis** — scans all referenced script/code files.
- **Consistency checks** — validates that manifested files actually exist.
- **File inventory** — identifies hidden files, unexpected binaries, etc.

**What changed on the local branch:**
- Integrated with the new scan policy system (rule scoping, disabled rules, severity overrides, file classification).
- Enhanced hidden-file detection with policy-driven benign dotfile lists.
- Integrated Magika file-type detection for smarter file classification.
- Expanded and tightened YAML signature patterns (+78 lines of rule changes).
- YARA scanner migrated from `yara-python` to `yara-x` for better performance and security.

**How to use:**

```bash
# Static analysis is always enabled by default
skill-scanner scan ./my-skill

# List all available rules
skill-scanner validate-rules
```

---

### 2. LLM Semantic Analyzer

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/llm_analyzer.py`, `llm_prompt_builder.py`, `llm_request_handler.py`, `llm_response_parser.py`, `llm_provider_config.py` |
| **Branch** | `main`: Yes — `local`: Enhanced |
| **Requires** | `SKILL_SCANNER_LLM_API_KEY` and `SKILL_SCANNER_LLM_MODEL` env vars |

**What it is:**
Uses a large language model to perform semantic threat analysis that pattern matching cannot catch. The LLM reads the full SKILL.md content and all referenced scripts, then produces structured findings with threat categories, severity levels, and explanations.

**Why it exists:**
Pattern-based detection misses novel attack vectors, obfuscated payloads, and context-dependent threats. The LLM understands intent and can identify social-engineering patterns, subtle data exfiltration, and logical bombs that static rules would miss.

**What changed on the local branch:**
- Prompt builder updated to include scan-policy context.
- Request handler improved with better error handling.
- Integration with the analyzer factory for cleaner initialization.

**How to use:**

```bash
export SKILL_SCANNER_LLM_API_KEY="your-api-key"
export SKILL_SCANNER_LLM_MODEL="anthropic/claude-sonnet-4-20250514"

skill-scanner scan --use-llm ./my-skill
```

Supported providers via LiteLLM: Anthropic, OpenAI, AWS Bedrock, Google Vertex AI, Azure OpenAI.

---

### 3. Meta-Analyzer (FP Filtering)

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/meta_analyzer.py` |
| **Branch** | `main`: Yes — `local`: Enhanced |
| **Requires** | LLM API key + at least 2 other analyzers to have run |

**What it is:**
A second-pass LLM analyzer that reviews all findings from previous analyzers and performs false-positive filtering and prioritization. It retains filtered findings with metadata explaining why they were downgraded rather than silently removing them.

**Why it exists:**
Static + LLM analyzers can produce overlapping or noisy findings. The meta-analyzer acts as a "senior reviewer" that consolidates, deduplicates, and adds confidence scores.

**What changed on the local branch:**
- Better integration with the analyzer factory.
- Enhanced finding retention with richer metadata.

**How to use:**

```bash
skill-scanner scan --use-llm --enable-meta ./my-skill
```

---

### 4. Behavioral / Dataflow Analyzer

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/behavioral_analyzer.py`, `skill_scanner/core/analyzers/behavioral/` (alignment LLM, orchestrator, prompt builder, response validator, threat classifier) |
| **Branch** | `main`: Yes — `local`: Yes |
| **Requires** | Nothing for AST analysis; optional LLM for alignment checks |

**What it is:**
Performs Python AST-based dataflow analysis to detect data exfiltration patterns. Traces data from sensitive sources (file reads, environment variables, credentials) through transformations to sensitive sinks (HTTP requests, subprocess calls, file writes to external paths).

The behavioral sub-modules include:
- **Orchestrator** — coordinates the analysis pipeline.
- **Threat classifier** — categorizes detected dataflows by threat type.
- **Alignment LLM** — optional LLM pass to check if code behavior aligns with stated skill purpose.

**How to use:**

```bash
skill-scanner scan --use-behavioral ./my-skill
```

---

### 5. VirusTotal Analyzer

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/virustotal_analyzer.py` |
| **Branch** | `main`: Yes — `local`: Enhanced |
| **Requires** | `VIRUSTOTAL_API_KEY` env var |

**What it is:**
Computes SHA-256 hashes of binary files in a skill and looks them up via the VirusTotal API (`https://www.virustotal.com/api/v3`). Optionally uploads unknown files for dynamic analysis.

**Why it exists:**
Compiled binaries, packed executables, and obfuscated scripts cannot be analyzed by pattern matching alone. VirusTotal provides crowd-sourced antivirus verdicts from 70+ engines.

**What changed on the local branch:**
- Post-processing integrated with scan policy for VirusTotal validation behavior.
- Better handling of API rate limits and errors.

**How to use:**

```bash
export VIRUSTOTAL_API_KEY="your-vt-key"

# Hash lookup only (default)
skill-scanner scan --use-virustotal ./my-skill

# Also upload unknown files for analysis
skill-scanner scan --use-virustotal --vt-upload-files ./my-skill
```

---

### 6. Cisco AI Defense Analyzer

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/aidefense_analyzer.py` |
| **Branch** | `main`: Yes — `local`: Enhanced |
| **Requires** | `AI_DEFENSE_API_KEY` and `AI_DEFENSE_API_URL` env vars |

**What it is:**
Sends skill content to Cisco's AI Defense cloud service for enterprise-grade threat analysis. Returns findings mapped to the Cisco AITech taxonomy.

**Why it exists:**
Provides an additional layer of detection backed by Cisco's threat intelligence, complementing the local static and LLM analyzers.

**How to use:**

```bash
export AI_DEFENSE_API_KEY="your-key"
export AI_DEFENSE_API_URL="https://your-instance.example.com"

skill-scanner scan --use-aidefense ./my-skill
```

---

### 7. Trigger Analyzer

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/trigger_analyzer.py` |
| **Branch** | `main`: Yes — `local`: Yes |
| **Requires** | Nothing |

**What it is:**
Analyzes skill descriptions for overly generic trigger patterns that could cause the skill to activate too broadly (trigger hijacking). Uses Jaccard similarity to compare a skill's trigger surface against known patterns.

**Why it exists:**
A malicious skill with an overly broad description (e.g., "helps with any coding task") could intercept requests meant for other skills, enabling prompt-injection attacks.

**How to use:**

```bash
skill-scanner scan --use-trigger ./my-skill
```

---

### 8. Cross-Skill Scanner

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/cross_skill_scanner.py` |
| **Branch** | `main`: Yes — `local`: Yes |
| **Requires** | Multiple skill directories |

**What it is:**
When scanning multiple skills (via `scan-all`), this analyzer detects cross-skill attack patterns where individually benign skills could be malicious in combination (e.g., one skill reads secrets, another exfiltrates data).

**How to use:**

```bash
skill-scanner scan-all --check-overlap ./skills-directory/
```

---

### 9. Pipeline Analyzer

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/pipeline_analyzer.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Nothing |

**What it is:**
A new analyzer that performs taint analysis on shell command pipelines. It detects dangerous patterns like `curl | sh`, `wget | bash`, and piped command chains that download and execute remote code. It distinguishes between:

- **Dangerous pipes** — `curl URL | sh`, `wget -O- | bash`, etc.
- **Benign pipes** — `grep | sort`, `cat file | wc -l`, etc.
- **Trusted installer domains** — configurable via scan policy (e.g., `get.docker.com`, `install.python-poetry.org`).

**Why it exists:**
Shell pipeline attacks are a common supply-chain vector in developer tools. Skills that install dependencies or run setup scripts often use piped commands. The pipeline analyzer ensures these are from trusted sources and don't pipe untrusted remote content directly to a shell interpreter.

**How to use:**

```bash
# Enabled automatically as a core analyzer
skill-scanner scan ./my-skill

# Configure trusted domains via policy
skill-scanner scan --policy my_policy.yaml ./my-skill
```

---

### 10. Bytecode Analyzer

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/bytecode_analyzer.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Nothing |

**What it is:**
Detects and analyzes Python bytecode files (`.pyc`) in skill packages. Checks for:

- Presence of `.pyc` files without corresponding `.py` source (pre-compiled, potentially hiding malicious code).
- Bytecode version mismatches (compiled on a different Python version).
- Integrity validation of bytecode headers.

**Why it exists:**
Attackers can distribute pre-compiled Python bytecode that doesn't have readable source code, making it impossible for other analyzers to inspect. This analyzer flags such files and validates their integrity.

**How to use:**

```bash
# Enabled automatically as a core analyzer
skill-scanner scan ./my-skill
```

---

### 11. Scan Policy System

| | |
|---|---|
| **Files** | `skill_scanner/core/scan_policy.py`, `skill_scanner/data/default_policy.yaml`, `strict_policy.yaml`, `permissive_policy.yaml` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Nothing (defaults are built-in) |

**What it is:**
A comprehensive policy engine that lets organizations customize every aspect of scan behavior through a single YAML configuration file. Policy sections include:

| Policy Section | Controls |
|---|---|
| `hidden_files` | Which dotfiles are benign vs. suspicious |
| `pipeline` | Trusted installer domains, dangerous pipe patterns |
| `rule_scoping` | Which rules apply to which file types |
| `credentials` | Known-benign credential variable names |
| `file_classification` | File type categories and risk levels |
| `file_limits` | Max file size, max files per skill |
| `analysis_thresholds` | Min confidence scores, analyzability cutoffs |
| `command_safety` | Command risk tiers (safe/caution/risky/dangerous) |
| `severity_overrides` | Bump or lower severity for specific rules |
| `disabled_rules` | Completely disable specific rule IDs |
| `analyzers` | Enable/disable and configure individual analyzers |

**Why it exists:**
Different organizations have different security postures. A startup building internal tools has different tolerance thresholds than a financial institution. The policy system lets teams codify their security bar, share it across projects, and version-control it.

**How policies work:**
1. The `balanced` preset ships as the default (loaded from `data/default_policy.yaml`).
2. Custom policies merge on top of defaults — you only override what you need.
3. Lists replace entirely (to let you narrow scope). Scalars override directly.

**How to use:**

```bash
# Scan with a built-in preset
skill-scanner scan --policy strict ./my-skill
skill-scanner scan --policy permissive ./my-skill

# Generate a policy file, customize it, then use it
skill-scanner generate-policy --preset balanced -o my_policy.yaml
# ... edit my_policy.yaml ...
skill-scanner scan --policy my_policy.yaml ./my-skill
```

---

### 12. Policy Presets

| | |
|---|---|
| **Files** | `skill_scanner/data/default_policy.yaml` (balanced), `strict_policy.yaml`, `permissive_policy.yaml` |
| **Branch** | `main`: No — `local`: **New** |

**What it is:**
Three built-in policy presets covering common use cases:

| Preset | Philosophy | Use When |
|---|---|---|
| **`strict`** | Maximum detection, minimal tolerance. Every dotfile is suspicious, all credential patterns fire, low thresholds. | Compliance audits, security reviews, untrusted skill sources |
| **`balanced`** | Sensible defaults. Common dotfiles (`.gitignore`, `.env.example`) are benign, standard installer domains are trusted. | Day-to-day scanning, CI pipelines, most teams |
| **`permissive`** | Minimal noise. Broad benign lists, higher thresholds, more trusted domains. | Internal tooling, trusted skill authors, rapid prototyping |

**How to use:**

```bash
skill-scanner scan --policy strict ./my-skill
skill-scanner scan --policy balanced ./my-skill    # default
skill-scanner scan --policy permissive ./my-skill

# Generate a preset to a file for customization
skill-scanner generate-policy --preset strict -o strict_custom.yaml
```

---

### 13. Policy TUI (Interactive Configurator)

| | |
|---|---|
| **Files** | `skill_scanner/cli/policy_tui.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | `textual>=1.0.0` (included in dependencies) |

**What it is:**
A terminal user interface (TUI) built with the Textual framework that provides an interactive wizard for building custom scan policies. Users can toggle settings, adjust thresholds, enable/disable rules, and preview the resulting YAML — all without manually editing policy files.

**Why it exists:**
Scan policies have dozens of configurable options. The TUI makes it accessible to security engineers who want to customize behavior without memorizing YAML schema details.

**How to use:**

```bash
skill-scanner configure-policy -o my_policy.yaml
```

---

### 14. Command Safety Engine

| | |
|---|---|
| **Files** | `skill_scanner/core/command_safety.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Nothing |

**What it is:**
A tiered command classification system that categorizes shell commands into risk levels:

| Tier | Risk Level | Examples |
|---|---|---|
| **Safe** | No risk | `echo`, `cat`, `ls`, `pwd`, `date` |
| **Caution** | Low risk | `pip install`, `npm install`, `git clone` |
| **Risky** | Medium risk | `curl`, `wget`, `ssh`, `docker run` |
| **Dangerous** | High risk | `rm -rf`, `mkfs`, `dd`, `chmod 777`, GTFOBins patterns |

The engine includes special handling for **GTFOBins patterns** — commands from the GTFOBins database that can be used for privilege escalation, file read/write, or reverse shells (e.g., `python -c 'import os; os.system("/bin/sh")'`).

**Why it exists:**
Skills frequently execute shell commands. The command safety engine provides a standardized risk assessment that the static analyzer and pipeline analyzer use to flag dangerous operations.

**How to use:**
Integrated automatically into the static and pipeline analyzers. Configurable via the `command_safety` section of scan policies.

---

### 15. Magika File-Type Detection

| | |
|---|---|
| **Files** | `skill_scanner/core/file_magic.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | `magika>=0.6.0` (included in dependencies) |

**What it is:**
Google's Magika library provides AI-powered file-type detection with ~99% accuracy across 200+ content types. The skill scanner uses it as the primary file classification engine, with fallback to extension-based detection when Magika is unavailable.

**Why it exists:**
Attackers can disguise malicious files with wrong extensions (e.g., a `.txt` file that's actually a compiled binary). Content-based detection catches these mismatches and enables smarter rule scoping (applying the right rules to the right file types).

**How to use:**
Integrated automatically. No configuration needed. The file type detection feeds into the static analyzer's rule scoping and the content extractor.

---

### 16. Content Extractor (ZIP/TAR/DOCX/XLSX)

| | |
|---|---|
| **Files** | `skill_scanner/core/extractors/content_extractor.py`, `skill_scanner/core/extractors/__init__.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Nothing (uses Python stdlib) |

**What it is:**
Safely extracts and scans content from archive and document files:

- **Archives:** ZIP, TAR, TAR.GZ, TAR.BZ2
- **Documents:** DOCX (Word), XLSX (Excel)

Includes protection against:
- **Zip bombs** — detects excessive compression ratios.
- **Path traversal** — blocks `../` escape attempts in archive paths.
- **File limits** — enforces maximum extracted file size and count (configurable via policy).

**Why it exists:**
Skills may bundle dependencies, datasets, or configuration in archives. Malicious archives could contain hidden payloads, zip bombs, or path-traversal attacks. The extractor safely handles these while making archived content available to other analyzers.

**How to use:**
Integrated automatically. Archives found in skill directories are extracted to a temporary location and scanned.

---

### 17. Analyzability Scoring

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzability.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Nothing |

**What it is:**
Computes a 0–100 analyzability score for each skill based on:

- Percentage of files that are source code (readable/scannable) vs. binary.
- Whether SKILL.md exists and has structured frontmatter.
- Number of files within analysis limits.
- Presence of obfuscated or minified content.

**Why it exists:**
Not all skills are equally analyzable. A skill with only binary files and no documentation gives the scanner very little to work with. The analyzability score communicates scan confidence to the user: "We found 2 issues, but could only analyze 30% of this skill."

**How to use:**
Included automatically in scan results. Thresholds are configurable via the `analysis_thresholds` section of scan policies.

---

### 18. Analyzer Factory

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzer_factory.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Nothing |

**What it is:**
A centralized factory module that builds and configures all analyzers based on the current scan policy and CLI flags. Provides two functions:

- `build_core_analyzers()` — returns the always-on analyzers (static, pipeline, bytecode).
- `build_analyzers()` — returns all enabled analyzers including optional ones (LLM, behavioral, VirusTotal, AI Defense, meta, trigger).

**Why it exists:**
Previously, analyzer construction was scattered across the CLI and scanner modules. The factory consolidates initialization logic, making it easier to add new analyzers and ensuring consistent configuration from both the CLI and the programmatic API.

**How to use:**
Used internally by the scanner engine. Accessible programmatically:

```python
from skill_scanner.core.analyzer_factory import build_analyzers

analyzers = build_analyzers(config=config, policy=policy)
```

---

### 19. Policy-Driven Knob System

| | |
|---|---|
| **Files** | `skill_scanner/core/scan_policy.py`, `skill_scanner/data/default_policy.yaml`, policy preset files |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Nothing (defaults are built-in) |

**What it is:**
All tunable parameters are exposed through named policy sections. There is no separate per-rule property layer. Fine-grained control is achieved by editing the appropriate section:

- **file_limits** — max file count, max file size, max reference depth, name/description length thresholds
- **analysis_thresholds** — zero-width character thresholds, analyzability risk cutoffs
- **pipeline** — trusted installer domains, benign pipe patterns, doc path indicators
- **file_classification** — inert extensions, structured extensions, archive and code extensions
- **severity_overrides** — change any rule's severity without disabling it

**Why it exists:**
Organizations need to tune scan behavior to match their security posture. Placing all knobs in well-defined policy sections keeps configuration discoverable and avoids the complexity of per-rule property overrides.

**How to use:**

```yaml
# In your policy YAML — tune thresholds and scoping via named sections
file_limits:
  max_file_count: 200
  max_file_size_bytes: 10485760

analysis_thresholds:
  zerowidth_threshold_with_decode: 100
  zerowidth_threshold_alone: 500
```

---

### 20. Policy Benchmark System

| | |
|---|---|
| **Files** | `evals/runners/policy_benchmark.py`, `evals/policies/*.yaml` (10 policy variants) |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Corpus of skills in `.local_benchmark/corpus/` |

**What it is:**
A benchmarking framework that compares scan results across different policy configurations on a large corpus of real-world skills (~119 skills). It produces:

- Per-policy finding counts and severity distributions.
- Cross-policy comparison tables (which policy finds what).
- Markdown and JSON reports with timestamps and git commit tags.

**Included policy variants for benchmarking:**

| # | Policy File | Description |
|---|---|---|
| 01 | `baseline_no_policy.yaml` | No policy (scanner defaults) |
| 02 | `strict_preset.yaml` | Strict preset |
| 03 | `permissive_preset.yaml` | Permissive preset |
| 04 | `compliance_audit.yaml` | Compliance-focused settings |
| 05 | `ci_pipeline.yaml` | CI/CD optimized |
| 06 | `internal_tooling.yaml` | Internal tools (relaxed) |
| 07 | `no_pipeline_analysis.yaml` | Pipeline analyzer disabled |
| 08 | `yara_wide_open.yaml` | All YARA rules enabled |
| 09 | `cred_heavy.yaml` | Heavy credential detection |
| 10 | `max_sensitivity.yaml` | Everything at maximum |

**Why it exists:**
When tuning scan policies, you need to understand the impact of changes across a representative skill corpus. The benchmark system prevents regressions and helps teams choose the right policy preset.

**How to use:**

```bash
# Run full policy benchmark (~9 min)
make benchmark-corpus

# Single policy
uv run python evals/runners/policy_benchmark.py \
  --policies evals/policies/04_compliance_audit.yaml

# Custom corpus
uv run python evals/runners/policy_benchmark.py \
  --corpus /path/to/skills
```

---

### 21. Eval-Skills Benchmark

| | |
|---|---|
| **Files** | `evals/runners/benchmark_runner.py`, `evals/runners/eval_runner.py`, `evals/runners/update_expected_findings.py`, `evals/skills/` |
| **Branch** | `main`: Yes — `local`: Enhanced (moved to `evals/runners/`) |
| **Requires** | Nothing for static; LLM API key for LLM evals |

**What it is:**
A curated evaluation framework that tests scanner accuracy against skills with known ground truth. Each eval skill has an `_expected.json` file specifying expected findings (category + severity). The benchmark computes:

| Metric | Formula | Meaning |
|---|---|---|
| Precision | TP / (TP + FP) | Of all findings, how many were correct |
| Recall | TP / (TP + FN) | Of all expected threats, how many found |
| F1 | 2 * P * R / (P + R) | Balanced precision/recall |
| Accuracy | (TP + TN) / Total | Overall correctness |

**Eval skill categories:**
`backdoor`, `behavioral-analysis`, `command-injection`, `data-exfiltration`, `obfuscation`, `path-traversal`, `prompt-injection`, `resource-exhaustion`, `safe-skills`, `sql-injection`

**What changed on the local branch:**
- Runner scripts moved from `evals/` to `evals/runners/` for better organization.
- Added `__init__.py` for proper Python packaging.
- Updated imports and paths throughout.

**How to use:**

```bash
# Fast static-only benchmark (~30s)
make benchmark-eval

# Detailed per-skill evaluation
uv run python evals/runners/eval_runner.py --test-skills-dir evals/skills

# With LLM
uv run python evals/runners/eval_runner.py --test-skills-dir evals/skills --use-llm

# Update ground truth after rule changes
uv run python evals/runners/update_expected_findings.py \
  --test-skills-dir evals/skills --update
```

---

### 22. Taxonomy Enforcement (check-taxonomy)

| | |
|---|---|
| **Files** | `scripts/check_taxonomy.py` |
| **Branch** | `main`: No — `local`: **New** |
| **Requires** | Runs as a pre-commit hook |

**What it is:**
A validation script that ensures the `ThreatCategory` Python enum stays in sync with the official Cisco AI taxonomy. It:

1. Parses the `ThreatCategory` enum from source.
2. Compares members against the `ALLOWED_CATEGORIES` list.
3. Fails the pre-commit hook if any category is added/removed without updating both places.

**Why it exists:**
The Cisco AITech taxonomy is the canonical threat classification system used across all Cisco AI security products. Any drift between the scanner's threat categories and the official taxonomy would cause inconsistent reporting and broken integrations.

**How to use:**
Runs automatically as a pre-commit hook. Can also be run manually:

```bash
python scripts/check_taxonomy.py
```

---

### 23. Makefile Build System

| | |
|---|---|
| **Files** | `Makefile` |
| **Branch** | `main`: No — `local`: **New** |

**What it is:**
A Makefile providing standardized development commands:

| Target | Command | Description |
|---|---|---|
| `make help` | — | Show all available targets |
| `make benchmark` | Both below | Full benchmark suite |
| `make benchmark-eval` | `uv run python evals/runners/benchmark_runner.py` | Eval-skills benchmark (~30s) |
| `make benchmark-corpus` | `uv run python evals/runners/policy_benchmark.py` | Policy benchmark (~9 min) |
| `make test` | `uv run pytest tests/ -x -q` | Run test suite |
| `make lint` | `uv run ruff check . --fix && uv run ruff format .` | Lint and format |
| `make clean` | `find . -type d -name __pycache__ ...` | Clean caches |

Benchmark outputs are automatically tagged with `TIMESTAMP_COMMIT` and saved to `.local_benchmark/checkpoints/`.

**Why it exists:**
Provides a single, memorable entry point for all common development tasks. Ensures consistency across team members and CI environments.

---

### 24. CLI

| | |
|---|---|
| **Files** | `skill_scanner/cli/cli.py` |
| **Entry Point** | `skill-scanner` |
| **Branch** | `main`: Yes — `local`: Enhanced |

**What it is:**
The primary command-line interface built with Click. Provides these commands:

| Command | Purpose |
|---|---|
| `scan` | Scan a single skill directory |
| `scan-all` | Scan multiple skills (with `--recursive`, `--check-overlap`) |
| `list-analyzers` | List all available analyzers with descriptions |
| `validate-rules` | Validate YAML rule signatures |
| `generate-policy` | Generate a policy YAML file from a preset |
| `configure-policy` | Launch the interactive TUI configurator |

**Key flags:**

| Flag | Description |
|---|---|
| `--format` | Output format: `summary`, `json`, `markdown`, `table`, `sarif` |
| `--output` | Write results to file |
| `--fail-on-findings` | Exit non-zero if findings exist (for CI) |
| `--policy` | Path to policy YAML or preset name (`strict`, `balanced`, `permissive`) |
| `--use-llm` | Enable LLM semantic analysis |
| `--use-behavioral` | Enable behavioral/dataflow analysis |
| `--use-virustotal` | Enable VirusTotal hash lookup |
| `--use-aidefense` | Enable Cisco AI Defense |
| `--enable-meta` | Enable meta-analyzer FP filtering |
| `--use-trigger` | Enable trigger specificity analysis |
| `--custom-rules` | Path to additional YAML rule files |

**What changed on the local branch:**
- Added `generate-policy` and `configure-policy` commands.
- Added `--policy` flag to `scan` and `scan-all`.
- Significant refactoring and cleanup (~1094 lines changed).
- `list-analyzers` now includes the new analyzers (pipeline, bytecode).

---

### 25. REST API Server

| | |
|---|---|
| **Files** | `skill_scanner/api/api.py`, `router.py`, `api_server.py`, `api_cli.py` |
| **Entry Point** | `skill-scanner-api` |
| **Branch** | `main`: Yes — `local`: Enhanced |

**What it is:**
A FastAPI-based REST API that exposes scan functionality over HTTP. Endpoints include:

- `POST /scan` — scan a skill (upload or path).
- `GET /health` — health check.
- `GET /analyzers` — list available analyzers.

The server binds to `localhost` by default and warns if exposed publicly.

**What changed on the local branch:**
- Router refactored with updated Pydantic models.
- API server significantly simplified (–616 lines from `api_server.py`).
- Policy support added to API endpoints.

**How to use:**

```bash
skill-scanner-api --host 127.0.0.1 --port 8000
```

---

### 26. Pre-Commit Hook

| | |
|---|---|
| **Files** | `skill_scanner/hooks/pre_commit.py` |
| **Entry Point** | `skill-scanner-pre-commit` |
| **Branch** | `main`: Yes — `local`: Enhanced |

**What it is:**
A pre-commit hook that automatically scans skill files before they are committed. Configurable via `.skill_scannerrc` in the repository root.

**What changed on the local branch:**
- Added scan policy support to the pre-commit hook.
- Improved configuration handling.

**How to use:**
Add to `.pre-commit-config.yaml`:

```yaml
- repo: https://github.com/cisco-ai-defense/skill-scanner
  rev: v1.0.0
  hooks:
    - id: skill-scanner
```

---

### 27. SARIF Reporter

| | |
|---|---|
| **Files** | `skill_scanner/core/reporters/sarif_reporter.py` |
| **Branch** | `main`: Yes — `local`: Yes |

**What it is:**
Generates SARIF (Static Analysis Results Interchange Format) output compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-compatible tools. Each finding maps to a SARIF `result` with location, severity, and rule metadata.

**How to use:**

```bash
skill-scanner scan --format sarif --output results.sarif ./my-skill
```

---

### 28. Multiple Output Formats

| | |
|---|---|
| **Files** | `skill_scanner/core/reporters/` (json, markdown, table, sarif) |
| **Branch** | `main`: Yes — `local`: Yes |

**What it is:**
Five output formats for different consumption scenarios:

| Format | Best For |
|---|---|
| `summary` | Quick terminal review (default) |
| `json` | Programmatic consumption, CI pipelines |
| `markdown` | Documentation, PR comments, reports |
| `table` | Terminal review with more detail |
| `sarif` | GitHub Code Scanning, IDE integration |

---

### 29. Cisco AITech Threat Taxonomy

| | |
|---|---|
| **Files** | `skill_scanner/threats/threats.py`, `skill_scanner/threats/cisco_ai_taxonomy.py` |
| **Branch** | `main`: Yes — `local`: Enhanced |

**What it is:**
Every finding is mapped to the Cisco AI Security Framework's AITech taxonomy codes. The `ThreatMapping` class translates between internal categories (from LLM, static, and YARA analyzers) and standardized AITech codes.

**Why it exists:**
Standardized taxonomy enables consistent reporting across Cisco's AI security product suite and allows findings to be correlated across tools.

**What changed on the local branch:**
- Taxonomy validation enforced via the `check-taxonomy` pre-commit hook.
- Updated threat mappings for new analyzer categories.

---

### 30. YARA Rule Library

| | |
|---|---|
| **Files** | `skill_scanner/data/packs/core/yara/*.yara` (13 rule files) |
| **Branch** | `main`: Yes — `local`: Enhanced |

**What it is:**
Thirteen compiled YARA rule files covering:

| Rule File | Threat Category |
|---|---|
| `autonomy_abuse_generic.yara` | Agent autonomy abuse |
| `capability_inflation_generic.yara` | Privilege escalation via capability inflation |
| `code_execution_generic.yara` | Arbitrary code execution |
| `coercive_injection_generic.yara` | Coercive prompt injection |
| `command_injection_generic.yara` | OS command injection |
| `credential_harvesting_generic.yara` | Credential theft |
| `indirect_prompt_injection_generic.yara` | Indirect prompt injection |
| `prompt_injection_generic.yara` | Direct prompt injection |
| `prompt_injection_unicode_steganography.yara` | Unicode steganography |
| `script_injection_generic.yara` | Script injection (XSS, etc.) |
| `sql_injection_generic.yara` | SQL injection |
| `system_manipulation_generic.yara` | System file/config manipulation |
| `tool_chaining_abuse_generic.yara` | Tool chaining attacks |

**What changed on the local branch:**
- Migrated from `yara-python` to `yara-x` (Rust-based, faster, more secure).
- YARA mode configuration (`yara_modes.py`) refactored.
- Pattern tightening across rule files.

---

### 31. Static Analysis Subsystem (CFG, Taint, Dataflow)

| | |
|---|---|
| **Files** | `skill_scanner/core/static_analysis/` — `parser/python_parser.py`, `cfg/builder.py`, `dataflow/forward_analysis.py`, `taint/tracker.py`, `context_extractor.py`, `semantic/name_resolver.py`, `semantic/type_analyzer.py`, `interprocedural/call_graph_analyzer.py`, `interprocedural/cross_file_analyzer.py` |
| **Branch** | `main`: Yes — `local`: Yes |

**What it is:**
A full Python static analysis framework providing:

- **AST Parser** — parses Python source into an analyzable AST.
- **CFG Builder** — constructs control-flow graphs from AST.
- **Forward Dataflow Analysis** — propagates data-flow facts through the CFG.
- **Taint Tracker** — tracks tainted data from sources to sinks.
- **Name Resolver** — resolves variable and function names across scopes.
- **Type Analyzer** — infers types for better taint tracking.
- **Call Graph Analyzer** — builds interprocedural call graphs.
- **Cross-File Analyzer** — tracks dataflow across multiple files.

**Why it exists:**
Deep code analysis that goes beyond pattern matching. Can detect data exfiltration where a secret is read, transformed through multiple functions, and sent over HTTP — something no regex or YARA rule could catch.

---

### 32. LLM Provider Abstraction

| | |
|---|---|
| **Files** | `skill_scanner/core/analyzers/llm_provider_config.py` |
| **Branch** | `main`: Yes — `local`: Yes |

**What it is:**
Unified LLM provider configuration using LiteLLM for seamless switching between:

| Provider | Extra Required |
|---|---|
| Anthropic (Claude) | None (default) |
| OpenAI (GPT) | None |
| AWS Bedrock | `pip install cisco-ai-skill-scanner[bedrock]` |
| Google Vertex AI | `pip install cisco-ai-skill-scanner[vertex]` |
| Azure OpenAI | `pip install cisco-ai-skill-scanner[azure]` |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     Entry Points                             │
│  skill-scanner (CLI)  │  skill-scanner-api  │  pre-commit   │
└───────────┬───────────┴──────────┬──────────┴───────┬───────┘
            │                      │                  │
            ▼                      ▼                  ▼
┌─────────────────────────────────────────────────────────────┐
│                    Scan Policy Engine                 [NEW]  │
│  Presets: strict │ balanced │ permissive │ custom YAML       │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Analyzer Factory                   [NEW]  │
│  build_core_analyzers() │ build_analyzers()                  │
└───────────────────────────┬─────────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            ▼               ▼               ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│    Core       │  │   Optional    │  │  Integration  │
│  Analyzers    │  │  Analyzers    │  │  Analyzers    │
├──────────────┤  ├──────────────┤  ├──────────────┤
│ Static(YAML+ │  │ LLM Semantic │  │ VirusTotal   │
│  YARA)       │  │ Behavioral   │  │ AI Defense   │
│ Pipeline[NEW]│  │ Meta (FP)    │  │              │
│ Bytecode[NEW]│  │ Trigger      │  │              │
│              │  │ Cross-Skill  │  │              │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┼─────────────────┘
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Supporting Systems                         │
│  File Magic [NEW] │ Content Extractor [NEW] │ Command Safety │
│  Analyzability [NEW] │ Threat Taxonomy │ Static Analysis     │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Reporters                               │
│  Summary │ JSON │ Markdown │ Table │ SARIF                   │
└─────────────────────────────────────────────────────────────┘
```

---

## Environment Variables Reference

| Variable | Used By | Required | Description |
|---|---|---|---|
| `SKILL_SCANNER_LLM_API_KEY` | LLM Analyzer | For `--use-llm` | API key for the LLM provider |
| `SKILL_SCANNER_LLM_MODEL` | LLM Analyzer | For `--use-llm` | Model identifier (e.g., `anthropic/claude-sonnet-4-20250514`) |
| `SKILL_SCANNER_META_LLM_API_KEY` | Meta Analyzer | Optional | Separate key for meta-analyzer (falls back to LLM key) |
| `SKILL_SCANNER_META_LLM_MODEL` | Meta Analyzer | Optional | Separate model for meta-analyzer |
| `VIRUSTOTAL_API_KEY` | VirusTotal | For `--use-virustotal` | VirusTotal API key |
| `AI_DEFENSE_API_KEY` | AI Defense | For `--use-aidefense` | Cisco AI Defense API key |
| `AI_DEFENSE_API_URL` | AI Defense | For `--use-aidefense` | Cisco AI Defense endpoint URL |

---
