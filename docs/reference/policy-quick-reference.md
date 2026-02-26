# Policy Quick Reference

## Overview

Scan policies control all tuning knobs, detection thresholds, and rule enablement in Skill Scanner. Every setting has a sensible default; custom policies merge on top so you only specify what you want to change.

This page is a compact reference. For full walkthroughs, see [Custom Policy Configuration](../user-guide/custom-policy-configuration.md).

## Presets

| Preset | Use case |
|--------|----------|
| **balanced** (default) | Good balance of detection and false-positive rate. Broad benign allowlists, demotion in docs, known installer domains trusted. |
| **strict** | Lowest thresholds, most sensitive. Scans all files (no inert extension skip), no known installer demotions, narrow allowlists. Best for untrusted/external skills and compliance audits. |
| **permissive** | Highest thresholds, fewer findings, broader whitelists. Best for trusted internal skills or high-FP workflows. |

```bash
skill-scanner scan --policy balanced ./my-skill
skill-scanner scan --policy strict ./my-skill
skill-scanner scan --policy /path/to/custom.yaml ./my-skill
skill-scanner generate-policy -o my_org_policy.yaml
skill-scanner configure-policy  # Interactive TUI
```

Use `--preset strict|balanced|permissive` with `generate-policy` to base a new file on a specific preset.

## Most Common Tweaks

Copy-paste these into your policy YAML. You only need the sections you want to change.

### CI strict mode

```yaml
# Strict scanning for CI pipelines
analyzers:
  static: true
  bytecode: true
  pipeline: true
disabled_rules: []
```

### Raise file limits for large projects

```yaml
file_limits:
  max_file_count: 500
  max_file_size_bytes: 20971520  # 20 MB
```

### Disable noisy rules

```yaml
disabled_rules:
  - LAZY_LOAD_DEEP_NESTING
  - ARCHIVE_FILE_DETECTED
  - MANIFEST_DESCRIPTION_TOO_LONG
```

### Override a rule severity

```yaml
severity_overrides:
  - rule_id: BINARY_FILE_DETECTED
    severity: MEDIUM
    reason: "Our policy treats unknown binaries as medium risk"
```

### Add custom benign dotfiles

```yaml
hidden_files:
  benign_dotfiles:
    - ".bazelrc"
    - ".bazelversion"
    - ".terraform.lock.hcl"
```

### Tune LLM context budgets

```yaml
llm_analysis:
  max_instruction_body_chars: 40000   # double default
  max_code_file_chars: 30000
  max_total_prompt_chars: 200000
  meta_budget_multiplier: 2.0
```

### Tighten detection thresholds

```yaml
analysis_thresholds:
  zerowidth_threshold_with_decode: 30   # stricter (lower = more sensitive)
  zerowidth_threshold_alone: 150
  analyzability_low_risk: 95
  analyzability_medium_risk: 75
```

## Section Reference

Each section below documents every field, its type, default, and what it affects. Click to expand.

<details>
<summary><strong>file_limits</strong> — Numeric thresholds for file inventory and manifest checks</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| max_file_count | int | 100 | EXCESSIVE_FILE_COUNT |
| max_file_size_bytes | int | 5242880 (5 MB) | OVERSIZED_FILE |
| max_reference_depth | int | 5 | LAZY_LOAD_DEEP_NESTING |
| max_name_length | int | 64 | MANIFEST_INVALID_NAME |
| max_description_length | int | 1024 | MANIFEST_DESCRIPTION_TOO_LONG |
| min_description_length | int | 20 | SOCIAL_ENG_VAGUE_DESCRIPTION |

</details>

<details>
<summary><strong>analysis_thresholds</strong> — Numeric thresholds for YARA and analyzability scoring</summary>

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
| homoglyph_filter_math_context | bool | true | Suppress scientific/math contexts in HOMOGLYPH_ATTACK |
| homoglyph_math_aliases | list[str] | `["COMMON", "GREEK"]` | Allowed confusable alias groups in math contexts |

</details>

<details>
<summary><strong>pipeline</strong> — Pipeline taint and tool-chaining analysis behaviour</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| known_installer_domains | set | various | URLs demoted to LOW when curl\|sh targets them |
| benign_pipe_targets | list | regex patterns | Benign pipe chains (e.g. `cat \| grep`) |
| doc_path_indicators | set | `references`, `docs`, etc. | Path segments marking documentation |
| demote_in_docs | bool | true | Demote findings in doc paths |
| demote_instructional | bool | true | Demote instructional patterns (e.g. SKILL.md) |
| check_known_installers | bool | true | Demote known installer URLs |
| dedupe_equivalent_pipelines | bool | true | Collapse equivalent pipeline detections from overlapping extraction passes |
| compound_fetch_require_download_intent | bool | true | Require explicit download intent for fetch+execute detection |
| compound_fetch_filter_api_requests | bool | true | Suppress API-request false positives in fetch+execute heuristics |
| compound_fetch_filter_shell_wrapped_fetch | bool | true | Suppress shell-wrapped fetch false positives |
| compound_fetch_exec_prefixes | list | wrapper commands | Allowed wrappers before execution sinks (for example `sudo`) |
| compound_fetch_exec_commands | list | execution sinks | Commands treated as execution sinks in fetch+execute detection |
| exfil_hints | list | `send`, `upload`, etc. | Hint words for exfiltration detection |
| api_doc_tokens | list | `@app.`, `app.`, etc. | Tokens suppressing tool-chaining FP |

</details>

<details>
<summary><strong>file_classification</strong> — How file extensions are classified for analysis routing</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| inert_extensions | set | images, fonts, etc. | Skip binary checks on these |
| structured_extensions | set | svg, pdf, etc. | Not flagged as unknown binary |
| archive_extensions | set | zip, tar, etc. | Flagged as archives |
| code_extensions | set | py, sh, js, etc. | Code file detection |
| skip_inert_extensions | bool | true | Skip checks on inert files |
| allow_script_shebang_text_extensions | bool | true | Allow shebang headers for script-like text/code files |
| script_shebang_extensions | set | script extensions | Extensions treated as valid shebang script targets |

</details>

<details>
<summary><strong>hidden_files</strong> — Dotfile/dotdir allowlists</summary>

Dotfiles and dotdirs not in these lists trigger HIDDEN_DATA_FILE / HIDDEN_DATA_DIR findings.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| benign_dotfiles | set | preset-defined allowlist | HIDDEN_DATA_FILE |
| benign_dotdirs | set | preset-defined allowlist | HIDDEN_DATA_DIR |

</details>

<details>
<summary><strong>rule_scoping</strong> — Restrict which rules fire on which file types</summary>

Reduces noise in doc-heavy skills.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| skillmd_and_scripts_only | list | preset-defined set | Rules limited to SKILL.md + scripts |
| skip_in_docs | list | preset-defined set | Rules skipped in documentation directories |
| code_only | list | `prompt_injection_unicode_steganography`, `sql_injection_generic` | Rules only on code files |
| doc_path_indicators | set | `references`, `docs`, `examples`, etc. | Directory names marking "documentation" context |
| doc_filename_patterns | list | regex patterns | Filename patterns marking educational/example content |
| dedupe_reference_aliases | bool | true | De-dupes duplicate script references in SKILL.md parsing |
| dedupe_duplicate_findings | bool | true | De-dupes duplicate findings emitted across script/reference passes |
| asset_prompt_injection_skip_in_docs | bool | true | Suppresses ASSET_PROMPT_INJECTION findings in doc-style paths |

</details>

<details>
<summary><strong>credentials</strong> — Suppress well-known test credentials and placeholders</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| known_test_values | set | Stripe test keys, JWT.io example, common placeholders | Exact-match suppression of credential findings |
| placeholder_markers | set | `your-`, `example`, `placeholder`, etc. | Substring match suppression of credential findings |

</details>

<details>
<summary><strong>system_cleanup</strong> — Safe destructive cleanup targets</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| safe_rm_targets | set | `dist`, `build`, `tmp`, `node_modules`, etc. | DANGEROUS_CLEANUP finding suppression |

</details>

<details>
<summary><strong>command_safety</strong> — Tiered command classification for code execution findings</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| safe_commands | set | read-only utilities (cat, ls, grep, etc.) | Commands always considered safe |
| caution_commands | set | cp, mv, find, git, npm, pip, etc. | Commands that need context to evaluate |
| risky_commands | set | rm, docker, ssh, kubectl, etc. | Commands flagged at MEDIUM severity |
| dangerous_commands | set | curl, wget, eval, exec, sudo, etc. | Commands flagged at HIGH/CRITICAL severity |
| dangerous_arg_patterns | list[regex] | 8 patterns (inline code exec, shell spawning, etc.) | Regex patterns that immediately classify a command as DANGEROUS |

</details>

<details>
<summary><strong>sensitive_files</strong> — Regex patterns matching sensitive file paths</summary>

When a pipeline reads a matching file, the taint is upgraded to SENSITIVE_DATA.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| patterns | list[regex] | `/etc/passwd`, `~/.ssh`, `.env`, `.pem`, etc. | Pipeline taint upgrade to SENSITIVE_DATA |

</details>

<details>
<summary><strong>llm_analysis</strong> — LLM context budget thresholds</summary>

Controls LLM context budget thresholds for LLM and meta analyzers. Content within budget is sent in full; content exceeding the budget is skipped entirely and an `LLM_CONTEXT_BUDGET_EXCEEDED` INFO finding is emitted.

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| max_instruction_body_chars | int | 20000 | Maximum character length for a single instruction body sent to the LLM |
| max_code_file_chars | int | 15000 | Maximum character length for a single code file sent to the LLM |
| max_referenced_file_chars | int | 10000 | Maximum character length for a single referenced file sent to the LLM |
| max_total_prompt_chars | int | 100000 | Maximum total characters across the entire LLM prompt |
| meta_budget_multiplier | float | 3.0 | Multiplier applied to all limits above for the meta analyzer (e.g. 3x = 60K instruction, 45K/file, 300K total) |

</details>

<details>
<summary><strong>analyzers</strong> — Enable or disable built-in analysis passes</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| static | bool | true | Enable/disable YAML+YARA pattern analyzer |
| bytecode | bool | true | Enable/disable .pyc bytecode analyzer |
| pipeline | bool | true | Enable/disable shell pipeline taint analyzer |

</details>

<details>
<summary><strong>finding_output</strong> — Output normalization, dedupe behavior, and traceability metadata</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| dedupe_exact_findings | bool | true | Removes exact duplicates from overlapping analyzers |
| dedupe_same_issue_per_location | bool | true | Collapses same issue at same file/line/snippet/category across analyzers |
| same_issue_preferred_analyzers | list[str] | `["meta_analyzer", "llm_analyzer", ...]` | Chooses which analyzer's details survive same-issue collapse |
| same_issue_collapse_within_analyzer | bool | true | If true, also collapses same-issue findings from one analyzer |
| annotate_same_path_rule_cooccurrence | bool | true | Adds `same_path_other_rule_ids` metadata for findings on the same path |
| attach_policy_fingerprint | bool | true | Adds policy name/version/fingerprint metadata to each finding |

</details>

<details>
<summary><strong>severity_overrides</strong> — Raise or lower any rule's severity</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| severity_overrides | list[{rule_id, severity, reason}] | `[]` | Override finding severity per rule |

```yaml
severity_overrides:
  - rule_id: BINARY_FILE_DETECTED
    severity: MEDIUM
    reason: "Our policy treats unknown binaries as medium risk"
```

</details>

<details>
<summary><strong>disabled_rules</strong> — Completely suppress specific rule IDs</summary>

| Field | Type | Default | Affects |
|-------|------|---------|---------|
| disabled_rules | list[str] | `[]` | Remove matching findings from results |

```yaml
disabled_rules:
  - LAZY_LOAD_DEEP_NESTING
  - ARCHIVE_FILE_DETECTED
```

</details>
