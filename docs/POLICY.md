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

### hidden_files

Dotfiles and dotdirs not in these lists trigger HIDDEN_DATA_FILE / HIDDEN_DATA_DIR findings.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| benign_dotfiles | set | 35 entries (version control, linting, etc.) | HIDDEN_DATA_FILE |
| benign_dotdirs | set | 22 entries (.github, .vscode, etc.) | HIDDEN_DATA_DIR |

### rule_scoping

Restrict which rules fire on which file types. Reduces noise in doc-heavy skills.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| skillmd_and_scripts_only | list | `coercive_injection_generic`, `autonomy_abuse_generic` | Rules limited to SKILL.md + scripts |
| skip_in_docs | list | 5 rules | Rules skipped in documentation directories |
| code_only | list | `prompt_injection_unicode_steganography`, `sql_injection_generic` | Rules only on code files |
| doc_path_indicators | set | `references`, `docs`, `examples`, etc. | Directory names marking "documentation" context |
| doc_filename_patterns | list | regex patterns | Filename patterns marking educational/example content |
| dedupe_reference_aliases | bool | true | De-dupes duplicate script references in SKILL.md parsing |
| dedupe_duplicate_findings | bool | true | De-dupes duplicate findings emitted across script/reference passes |
| asset_prompt_injection_skip_in_docs | bool | true | Suppresses ASSET_PROMPT_INJECTION findings in doc-style paths |

### credentials

Suppress well-known test credentials and placeholders.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| known_test_values | set | Stripe test keys, JWT.io example, common placeholders | Exact-match suppression of credential findings |
| placeholder_markers | set | `your-`, `example`, `placeholder`, etc. | Substring match suppression of credential findings |

### system_cleanup

Targets that are considered safe for destructive cleanup operations.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| safe_rm_targets | set | `dist`, `build`, `tmp`, `node_modules`, etc. | DANGEROUS_CLEANUP finding suppression |

### command_safety

Tiered command classification for code execution findings.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| safe_commands | set | read-only utilities (cat, ls, grep, etc.) | Commands always considered safe |
| caution_commands | set | cp, mv, find, git, npm, pip, etc. | Commands that need context to evaluate |
| risky_commands | set | rm, docker, ssh, kubectl, etc. | Commands flagged at MEDIUM severity |
| dangerous_commands | set | curl, wget, eval, exec, sudo, etc. | Commands flagged at HIGH/CRITICAL severity |
| dangerous_arg_patterns | list[regex] | 8 patterns (inline code exec, shell spawning, etc.) | Regex patterns that immediately classify a command as DANGEROUS |

### sensitive_files

Regex patterns matching sensitive file paths. When a pipeline reads a matching file, the taint is upgraded to SENSITIVE_DATA.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| patterns | list[regex] | `/etc/passwd`, `~/.ssh`, `.env`, `.pem`, etc. | Pipeline taint upgrade to SENSITIVE_DATA |

### analyzers

Enable or disable built-in analysis passes.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| static | bool | true | Enable/disable YAML+YARA pattern analyzer |
| bytecode | bool | true | Enable/disable .pyc bytecode analyzer |
| pipeline | bool | true | Enable/disable shell pipeline taint analyzer |

### finding_output

Controls final output normalization, dedupe behavior, and traceability metadata.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| dedupe_exact_findings | bool | true | Removes exact duplicates from overlapping analyzers |
| dedupe_same_issue_per_location | bool | true | Collapses same issue at same file/line/snippet/category across analyzers |
| same_issue_preferred_analyzers | list[str] | `["meta_analyzer", "llm_analyzer", ...]` | Chooses which analyzer's details survive same-issue collapse |
| same_issue_collapse_within_analyzer | bool | true | If true, also collapses same-issue findings from one analyzer |
| annotate_same_path_rule_cooccurrence | bool | true | Adds `same_path_other_rule_ids` metadata for findings on the same path |
| attach_policy_fingerprint | bool | true | Adds policy name/version/fingerprint metadata to each finding |

### severity_overrides

Raise or lower any rule's severity.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| severity_overrides | list[{rule_id, severity, reason}] | `[]` | Override finding severity per rule |

### disabled_rules

Completely suppress specific rule IDs.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| disabled_rules | list[str] | `[]` | Remove matching findings from results |

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
