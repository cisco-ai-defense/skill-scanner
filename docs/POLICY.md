# Policy Configuration Guide

## Overview

Scan policies control all tuning knobs, detection thresholds, and rule enablement in Skill Scanner. A policy specifies which file types are benign, which rules fire on which files, which installer URLs are trusted, severity overrides, and more. Every setting has a sensible default; custom policies merge on top of defaults so you only specify what you want to change.

## Presets

Three built-in presets provide different security postures:

| Preset | Use case |
|--------|----------|
| **balanced** (default) | Good balance of detection and false-positive rate. Broad benign allowlists, demotion in docs, known installer domains trusted. |
| **strict** | Lowest thresholds, most sensitive. Scans all files (no inert extension skip), no known installer demotions, narrow allowlists. Best for untrusted/external skills and compliance audits. |
| **permissive** | Highest thresholds, fewer findings, broader whitelists. Best for trusted internal skills or high-FP workflows. |

## Using Policies

```bash
skill-scanner scan --policy balanced ./my-skill
skill-scanner scan --policy strict ./my-skill
skill-scanner scan --policy /path/to/custom.yaml ./my-skill
skill-scanner generate-policy -o my_org_policy.yaml
skill-scanner configure-policy  # Interactive TUI
```

Use `--preset strict|balanced|permissive` with `generate-policy` to base a new file on a specific preset.

## Section Reference

### file_limits

Numeric thresholds for file inventory and manifest checks.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| max_file_count | int | 100 | EXCESSIVE_FILE_COUNT |
| max_file_size_bytes | int | 5242880 (5 MB) | OVERSIZED_FILE |
| max_reference_depth | int | 5 | LAZY_LOAD_DEEP_NESTING |
| max_name_length | int | 64 | MANIFEST_INVALID_NAME |
| max_description_length | int | 1024 | MANIFEST_DESCRIPTION_TOO_LONG |
| min_description_length | int | 20 | SOCIAL_ENG_VAGUE_DESCRIPTION |

### analysis_thresholds

Numeric thresholds for YARA and analyzability scoring.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| zerowidth_threshold_with_decode | int | 50 | Unicode steganography (with decode step) |
| zerowidth_threshold_alone | int | 200 | Unicode steganography (without decode) |
| analyzability_low_risk | int | 90 | LOW_ANALYZABILITY (score >= this = LOW risk) |
| analyzability_medium_risk | int | 70 | LOW_ANALYZABILITY (score >= this = MEDIUM risk) |
| min_dangerous_lines | int | 5 | HOMOGLYPH_ATTACK |
| min_confidence_pct | int | 80 | FILE_MAGIC_MISMATCH |
| exception_handler_context_lines | int | 20 | RESOURCE_ABUSE_INFINITE_LOOP |
| short_match_max_chars | int | 2 | Unicode steganography (short match filter) |
| cyrillic_cjk_min_chars | int | 10 | Unicode steganography (CJK suppression) |

### pipeline

Pipeline taint and tool-chaining analysis behaviour.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| known_installer_domains | set | various | URLs demoted to LOW when curl\|sh targets them |
| benign_pipe_targets | list | regex patterns | Benign pipe chains (e.g. `cat \| grep`) |
| doc_path_indicators | set | `references`, `docs`, etc. | Path segments marking documentation |
| demote_in_docs | bool | true | Demote findings in doc paths |
| demote_instructional | bool | true | Demote instructional patterns (e.g. SKILL.md) |
| check_known_installers | bool | true | Demote known installer URLs |
| exfil_hints | list | `send`, `upload`, etc. | Hint words for exfiltration detection |
| api_doc_tokens | list | `@app.`, `app.`, etc. | Tokens suppressing tool-chaining FP |

### file_classification

How file extensions are classified for analysis routing.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| inert_extensions | set | images, fonts, etc. | Skip binary checks on these |
| structured_extensions | set | svg, pdf, etc. | Not flagged as unknown binary |
| archive_extensions | set | zip, tar, etc. | Flagged as archives |
| code_extensions | set | py, sh, js, etc. | Code file detection |
| skip_inert_extensions | bool | true | Skip checks on inert files |

### Other sections (brief)

| Section | Purpose |
|---------|---------|
| **hidden_files** | `benign_dotfiles`, `benign_dotdirs` – dotfiles/dotdirs not flagged as HIDDEN_DATA_* |
| **rule_scoping** | Which rules apply to which file types (`skillmd_and_scripts_only`, `skip_in_docs`, `code_only`, `doc_path_indicators`, `doc_filename_patterns`) |
| **credentials** | `known_test_values`, `placeholder_markers` – suppress credential findings for known test/placeholder values |
| **system_cleanup** | `safe_rm_targets` – paths considered safe for `rm` patterns |
| **command_safety** | Tiered command classification: `safe_commands`, `caution_commands`, `risky_commands`, `dangerous_commands`, `dangerous_arg_patterns` |
| **sensitive_files** | `patterns` – regex for sensitive file paths that upgrade pipeline taint |
| **analyzers** | `static`, `bytecode`, `pipeline` – enable/disable analysis passes |
| **severity_overrides** | Raise or lower rule severities |
| **disabled_rules** | Completely suppress rule IDs |

## Disabling Rules

```yaml
disabled_rules:
  - LAZY_LOAD_DEEP_NESTING
  - ARCHIVE_FILE_DETECTED
```

## Severity Overrides

```yaml
severity_overrides:
  - rule_id: BINARY_FILE_DETECTED
    severity: MEDIUM
    reason: "Our policy treats unknown binaries as medium risk"
```

## Common Customizations

### 1. Raising file limits for large projects

```yaml
file_limits:
  max_file_count: 500
  max_file_size_bytes: 20971520  # 20 MB
```

### 2. Adding custom benign dotfiles

```yaml
hidden_files:
  benign_dotfiles:
    - ".bazelrc"
    - ".bazelversion"
    - ".terraform.lock.hcl"
```

### 3. Tuning detection thresholds

```yaml
analysis_thresholds:
  zerowidth_threshold_with_decode: 30   # Stricter (lower = more sensitive)
  zerowidth_threshold_alone: 150
  analyzability_low_risk: 95
  analyzability_medium_risk: 75
```

### 4. Disabling noisy rules

```yaml
disabled_rules:
  - LAZY_LOAD_DEEP_NESTING
  - ARCHIVE_FILE_DETECTED
  - MANIFEST_DESCRIPTION_TOO_LONG
```
