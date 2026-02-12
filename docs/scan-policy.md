# Scan Policy Guide

Every organisation has a different security bar. A **scan policy** captures what counts as benign, which rules fire on which file types, which installer URLs are trusted, numeric thresholds, and more — all in a single YAML file.

---

## Table of Contents

- [Quick Start](#quick-start)
- [How Policies Work](#how-policies-work)
- [Built-in Presets](#built-in-presets)
- [Preset Comparison](#preset-comparison)
- [Writing a Custom Policy](#writing-a-custom-policy)
- [Rule Governance Conventions](#rule-governance-conventions)
- [Policy Reference](#policy-reference)
  - [Metadata](#metadata)
  - [hidden_files](#hidden_files)
  - [pipeline](#pipeline)
  - [rule_scoping](#rule_scoping)
  - [credentials](#credentials)
  - [system_cleanup](#system_cleanup)
  - [file_classification](#file_classification)
  - [file_limits](#file_limits)
  - [analysis_thresholds](#analysis_thresholds)
  - [sensitive_files](#sensitive_files)
  - [command_safety](#command_safety)
  - [analyzers](#analyzers)
  - [severity_overrides](#severity_overrides)
  - [disabled_rules](#disabled_rules)
- [Interactive Configurator (TUI)](#interactive-configurator-tui)
- [Migration from Legacy Flags](#migration-from-legacy-flags)
- [Examples](#examples)

---

## Quick Start

```bash
# Scan with a built-in preset
skill-scanner scan --policy strict ./my-skill
skill-scanner scan --policy permissive ./my-skill

# Generate a policy file from a preset, then customise it
skill-scanner generate-policy --preset balanced -o my_policy.yaml
# ... edit my_policy.yaml ...
skill-scanner scan --policy my_policy.yaml ./my-skill

# Use the interactive configurator
skill-scanner configure-policy -o my_policy.yaml
```

---

## How Policies Work

1. **Defaults ship with the package** — the `balanced` preset (stored in `data/default_policy.yaml`) is used when no `--policy` flag is provided.
2. **Custom policies merge on top of defaults** — you only need to include the sections you want to override. Omitted sections inherit from the defaults.
3. **Lists replace entirely** — when you override a list (e.g. `benign_dotfiles`), your list *replaces* the default, rather than appending. This lets you narrow or expand without repeating the entire default.
4. **Scalar values override** — numeric thresholds, strings, and booleans are simple replacements.

```
┌────────────────────┐      ┌────────────────────┐
│  default_policy    │      │  your_policy.yaml  │
│  (built-in)        │ ──▶  │  (overrides only)  │
└────────────────────┘      └────────────────────┘
         │                           │
         └─────── deep merge ────────┘
                     │
              ┌──────▼──────┐
              │  Effective   │
              │  Policy      │
              └─────────────┘
```

---

## Built-in Presets

| Preset | Description | Use when |
|--------|-------------|----------|
| **strict** | Narrow allowlists, no suppressions, lower thresholds | Auditing untrusted / external skills, compliance |
| **balanced** | Sensible defaults, moderate filtering | CI/CD pipelines, everyday scanning |
| **permissive** | Broad allowlists, aggressive suppression | Trusted internal skills, dev-time scanning |

Use a preset by name:

```bash
skill-scanner scan --policy strict ./skill-dir
```

Or generate a file from a preset to customise:

```bash
skill-scanner generate-policy --preset strict -o strict_custom.yaml
```

---

## Preset Comparison

The table below highlights the key differences between the three presets. Values not shown inherit from `balanced`.

| Setting | Strict | Balanced (default) | Permissive |
|---------|--------|--------------------|------------|
| **Benign dotfiles** | 6 (git + editor + docker) | 35 (standard dev toolchain) | 83 (+ Bazel, Rust, Swift, etc.) |
| **Benign dotdirs** | 3 (.github, .circleci, .gitlab) | 18 (+ .vscode, .cache, etc.) | 30 (+ .yarn, .terraform, etc.) |
| **Known installer domains** | 0 (none trusted) | 16 (Rust, nvm, Docker, etc.) | 26 (+ Helm, k3s, Linkerd, etc.) |
| **Benign pipe patterns** | 2 (ps\|grep, grep\|grep -v) | 7 (+ cat\|sort, curl\|jq, etc.) | 12 (+ docker\|grep, kubectl\|jq, etc.) |
| **Rule scoping: SKILL.md-only rules** | none (fire everywhere) | coercive_injection, autonomy_abuse | + capability_inflation, indirect_prompt_injection |
| **Rule scoping: skip in docs** | 3 rules | 3 rules | 5 rules (+ command_injection, credential_harvesting) |
| **Rule scoping: code-only rules** | sql_injection only | steg + sql_injection | steg + sql_injection |
| **Rule scoping: doc path dirs** | 2 (references, docs) | 10 (+ examples, fixtures, test, etc.) | 19 (+ tests, spec, samples, patterns, etc.) |
| **Test credentials suppressed** | 0 (none) | 7 (Stripe test, JWT.io, placeholders) | 15 (+ AWS EXAMPLE, changeme, etc.) |
| **Inert extensions** | 15 (default) | 15 (fonts, images, pyc) | 25 (+ mp3, mp4, wav, etc.) |
| **Archive extensions** | 18 (default) | 18 (zip, tar, jar, docx, etc.) | 23 (+ whl, egg, deb, rpm, etc.) |
| **Code extensions** | 8 (default) | 8 (py, sh, rb, js, ts, php, etc.) | 17 (+ go, rs, java, swift, etc.) |
| **Max file count** | 50 | 100 | 500 |
| **Max file size** | 2 MB | 5 MB | 20 MB |
| **Max reference depth** | 3 | 5 | 10 |
| **Max name length** | 48 | 64 | 128 |
| **Max description length** | 512 | 1024 | 4096 |
| **Min description length** | 30 | 20 | 10 |
| **Zero-width threshold (with decode)** | 20 | 50 | 100 |
| **Zero-width threshold (alone)** | 100 | 200 | 500 |
| **Analyzability LOW risk** | 95% | 90% | 80% |
| **Analyzability MEDIUM risk** | 80% | 70% | 50% |
| **Sensitive file patterns** | 5 (+ sudoers, .kube, .jks) | 5 (passwd, .ssh, .env, etc.) | 4 (narrower — passwd, .ssh only) |
| **Severity overrides** | 3 (BINARY→MEDIUM, HIDDEN→MEDIUM, PYCACHE→MEDIUM) | none | 2 (ARCHIVE→LOW, PACKAGE_INSTALL→LOW) |
| **Disabled rules** | none | none | 4 (deep nesting, invalid name, capability_inflation, indirect_prompt_injection) |

---

## Writing a Custom Policy

### Minimal Override

You only need to include the sections you want to change. For example, to add your internal installer domain and raise the file count limit:

```yaml
# my_org_policy.yaml
policy_name: acme-corp
policy_version: "1.0"

pipeline:
  known_installer_domains:
    - "sh.rustup.rs"
    - "install.internal.acme.com"   # Our internal installer

file_limits:
  max_file_count: 200
```

Everything else inherits from the `balanced` defaults.

### Starting from a Preset

If your org is more security-conscious, start from `strict` and relax only what you need:

```bash
skill-scanner generate-policy --preset strict -o acme_policy.yaml
```

Then edit the generated file to add your trusted domains, extra benign dotfiles, etc.

### Tips

- **Lists replace, don't append.** If you override `known_installer_domains`, include *all* domains you want — the default list is discarded.
- **Use `severity_overrides` to tune, not disable.** Instead of disabling a noisy rule, consider demoting it to `LOW` or `INFO`.
- **Use `disabled_rules` sparingly.** Disabled rules produce zero findings, which means zero visibility.
- **Version your policies.** Use `policy_version` and commit policies to your repo so changes are tracked.
- **Keep ownership clean.** Use policy YAML for allowlists/thresholds/scoping, keep YARA/signatures for detection logic, and avoid duplicating the same decision in multiple layers.

### Rule Governance Conventions

- **ID conventions:** Keep signature IDs in `SCREAMING_SNAKE_CASE` (e.g. `DATA_EXFIL_HTTP_POST`) and YARA findings as `YARA_<rule_name>` (e.g. `YARA_code_execution_generic`).
- **Severity strategy:** Use detector defaults for baseline severity; apply org-specific risk posture via `severity_overrides`.
- **Scoping strategy:** Use `rule_scoping` for context-aware enablement (docs/code/SKILL.md), not `disabled_rules`.
- **Suppression strategy:** Put known placeholders and safe cleanup paths in policy (`credentials`, `system_cleanup`) instead of hardcoding in analyzers.

---

## Policy Reference

### Metadata

```yaml
policy_name: my-org              # Display name for reports
policy_version: "1.0"            # Semantic version for tracking changes
preset_base: strict              # Which preset this derives from (strict / balanced / permissive)
```

`preset_base` controls which YARA post-filtering behaviour is used (credential placeholder filtering, generic HTTP verb suppression, etc.). It is set automatically by built-in presets and preserved when you rename `policy_name`. If your custom policy was generated from a preset, the correct `preset_base` is already embedded — you only need to change it if you want different YARA filtering than the preset you started from.

### hidden_files

Controls which dotfiles and dot-directories are treated as benign (not flagged as hidden data).

```yaml
hidden_files:
  benign_dotfiles:          # List of filenames (e.g. ".gitignore")
    - ".gitignore"
    - ".myCustomConfig"

  benign_dotdirs:           # List of directory names (e.g. ".github")
    - ".github"
    - ".myToolDir"
```

**Impact:** Files/dirs not in these lists trigger `HIDDEN_DATA_FILE` or `HIDDEN_DATA_DIR` findings.

### pipeline

Controls the pipeline taint analysis engine.

```yaml
pipeline:
  known_installer_domains:   # Domains where curl|sh is demoted to LOW
    - "sh.rustup.rs"
    - "install.mycompany.com"

  benign_pipe_targets:       # Regex patterns for safe pipe chains (full pipeline matched)
    - 'ps\s.*\|\s*grep'
    - 'mycommand\s.*\|\s*jq'

  doc_path_indicators:       # Path segments marking documentation context
    - "references"
    - "docs"
```

**Impact:**
- `known_installer_domains`: Matching `curl|sh` patterns are flagged at LOW instead of HIGH.
- `benign_pipe_targets`: Matching pipe chains are suppressed entirely.
- `doc_path_indicators`: Findings in doc paths get reduced severity.

### rule_scoping

Controls which rule sets (YARA and other analyzers) fire on which file categories.

```yaml
rule_scoping:
  skillmd_and_scripts_only:  # Rules that ONLY fire on SKILL.md + scripts
    - "coercive_injection_generic"
    - "autonomy_abuse_generic"

  skip_in_docs:              # Rules skipped for files in documentation dirs
    - "code_execution_generic"

  code_only:                 # Rules that only fire on code files (.py, .sh, etc.)
    - "prompt_injection_unicode_steganography"

  doc_path_indicators:       # Directory names marking "documentation" for rule scoping
    - "references"
    - "test"

  doc_filename_patterns:     # Regex for educational/example filenames
    - 'tutorial|guide|howto'
```

**Impact:** Controls which rules fire on which files, reducing false positives from educational or documentation content.

### credentials

Controls which well-known test credentials are automatically suppressed.

```yaml
credentials:
  known_test_values:         # Exact strings that suppress HARDCODED_SECRETS findings
    - "sk_test_4eC39HqLyjWDarjtT1zdp7dc"   # Stripe test key
    - 'password="password"'                  # Common placeholder
  placeholder_markers:       # Substrings used by placeholder-filter logic
    - "example"
    - "changeme"
    - "<your"
```

**Impact:**
- `known_test_values`: Findings whose snippet contains any of these exact strings are suppressed.
- `placeholder_markers`: Placeholder-like marker substrings are suppressed in credential-harvesting post-filters.

### system_cleanup

Controls which cleanup targets are considered safe when `rm -r`/`rm -rf` patterns are detected.

```yaml
system_cleanup:
  safe_rm_targets:
    - "dist"
    - "build"
    - "node_modules"
    - ".cache"
```

**Impact:** Reduces false positives for common build-artifact cleanup while still flagging destructive deletion outside approved targets.

### file_classification

Controls how file extensions are routed for analysis.

```yaml
file_classification:
  inert_extensions:          # Skip binary check entirely (images, fonts, etc.)
    - ".png"
    - ".ttf"
    - ".pyc"

  structured_extensions:     # Not flagged as unknown binary (SVG, PDF)
    - ".svg"
    - ".pdf"

  archive_extensions:        # Flagged as ARCHIVE_FILE_DETECTED
    - ".zip"
    - ".tar.gz"
    - ".docx"

  code_extensions:           # Considered executable for hidden-file checks
    - ".py"
    - ".sh"
    - ".js"
```

**Impact:**
- `inert_extensions`: Files with these extensions are silently skipped during binary analysis.
- `structured_extensions`: Files are noted but not flagged as unknown binaries.
- `archive_extensions`: Files trigger `ARCHIVE_FILE_DETECTED` at MEDIUM severity (unless overridden).
- `code_extensions`: Hidden files with these extensions trigger `HIDDEN_CODE_FILE` (higher severity) instead of `HIDDEN_DATA_FILE`.

### file_limits

Numeric thresholds for file inventory checks.

```yaml
file_limits:
  max_file_count: 100           # Above this → EXCESSIVE_FILE_COUNT
  max_file_size_bytes: 5242880  # 5 MB — above this → OVERSIZED_FILE
  max_reference_depth: 5        # Max recursion for reference resolution
  max_name_length: 64           # Skill name character limit
  max_description_length: 1024  # Skill description character limit
  min_description_length: 20    # Below this → vague description warning
```

**Impact:** Controls when inventory-related rules fire. Larger orgs or monorepo skills may need higher limits.

### analysis_thresholds

Numeric thresholds for YARA and analyzability scoring.

```yaml
analysis_thresholds:
  zerowidth_threshold_with_decode: 50   # Zero-width chars when decode context present
  zerowidth_threshold_alone: 200        # Zero-width chars without decode context
  analyzability_low_risk: 90            # Score >= this → LOW risk
  analyzability_medium_risk: 70         # Score >= this → MEDIUM risk
```

**Impact:**
- `zerowidth_*`: Controls when the Unicode steganography detector fires. Lower values are more sensitive (stricter).
- `analyzability_*`: Controls the risk-level classification based on how much of the skill can be statically analyzed. Higher values are harder to achieve (stricter).

### sensitive_files

Regex patterns for file paths that upgrade taint in pipeline analysis.

```yaml
sensitive_files:
  patterns:                          # Regex patterns (matched against command args)
    - '/etc/(?:passwd|shadow|hosts)'
    - '~?/\.(?:ssh|aws|gnupg)'
    - '\.(?:env|pem|key|crt)'
    - '(?:credentials|secrets?)'
    - '\$(?:HOME|USER|AWS_)'
```

**Impact:** When a pipeline command references a file matching these patterns, the taint is upgraded to `SENSITIVE_DATA`, which elevates the finding severity.

### command_safety

Controls which commands belong to each safety tier.  The scanner uses a tiered
evaluation to decide whether a `code_execution_generic` YARA finding should be
suppressed (safe/caution) or kept (risky/dangerous).

```yaml
command_safety:
  safe_commands:       # Read-only, informational, no side effects
    - "cat"
    - "ls"
    - "grep"
    - "echo"
    - "git"

  caution_commands:    # Generally safe but context-dependent
    - "cp"
    - "mv"
    - "sed"
    - "make"

  risky_commands:      # Can modify system or exfiltrate data
    - "rm"
    - "ssh"
    - "docker"

  dangerous_commands:  # Direct code execution, network exfiltration
    - "curl"
    - "wget"
    - "eval"
    - "bash"
    - "sudo"
```

**Impact:** An org that uses `docker` and `kubectl` routinely can move them to
`caution_commands` to suppress YARA code-execution findings for those commands.
Empty lists fall back to the built-in defaults.

### analyzers

Enable or disable entire analysis passes.

```yaml
analyzers:
  static: true    # Static pattern analysis (YARA, regex, manifest checks)
  bytecode: true  # Python bytecode integrity checks
  pipeline: true  # Shell pipeline taint analysis
```

**Impact:** Set `pipeline: false` to skip pipeline analysis entirely (useful if your skills never contain shell scripts).  Disabling an analyzer removes all its findings from the scan results.

### severity_overrides

Per-rule severity overrides — raise or lower any rule's severity without disabling it.

```yaml
severity_overrides:
  - rule_id: BINARY_FILE_DETECTED
    severity: MEDIUM
    reason: "Our policy treats unknown binaries as medium risk"

  - rule_id: ARCHIVE_FILE_DETECTED
    severity: LOW
    reason: "Archives are expected in our skill packages"
```

**Valid severities:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`

**Impact:** Changes the reported severity for matching rules. Useful for tuning signal-to-noise ratio without losing visibility.

### disabled_rules

Completely suppress specific rule IDs — they produce zero findings.

```yaml
disabled_rules:
  - LAZY_LOAD_DEEP_NESTING
  - MANIFEST_INVALID_NAME
  - capability_inflation_generic    # YARA rule names work too
```

**Impact:** Disabled rules are never evaluated. Use sparingly — prefer `severity_overrides` to demote rather than silence.

**Important:** Do not list a rule in both `disabled_rules` and `rule_scoping`. If a rule is disabled, scoping entries for that rule are ignored.

---

## Interactive Configurator (TUI)

The built-in TUI walks you through each policy section interactively:

```bash
skill-scanner configure-policy -o my_policy.yaml
```

The configurator:

1. Lets you pick a starting preset (strict / balanced / permissive)
2. Names your policy
3. Walks through each section — you choose which to customise
4. Shows a summary for review
5. Saves to a YAML file

For each section, you can add/remove individual items from lists, adjust numeric thresholds, and manage severity overrides. All tunable knobs are configurable via these named policy sections — there is no separate advanced or per-rule override layer.

---

## Migration from Legacy Flags

The policy system replaces several older CLI flags. These flags still work but are **deprecated** and will be removed in a future release:

| Old flag | Policy equivalent |
|----------|-------------------|
| `--yara-mode strict` | `--policy strict` (preset) or custom `analysis_thresholds` + `rule_scoping` |
| `--yara-mode permissive` | `--policy permissive` (preset) |
| `--disable-rule RULE_ID` | `disabled_rules: [RULE_ID]` in policy YAML |

When both `--policy` and a legacy flag are provided, the policy takes precedence.

---

## Examples

### Example 1: CI/CD Pipeline — Fail on HIGH+

Use `balanced` defaults but promote archive and binary findings:

```yaml
policy_name: ci-pipeline
severity_overrides:
  - rule_id: ARCHIVE_FILE_DETECTED
    severity: HIGH
    reason: "CI should catch archives"
  - rule_id: BINARY_FILE_DETECTED
    severity: HIGH
    reason: "CI should catch unknown binaries"
```

### Example 2: Internal Tooling Org

Trust internal installers, allow large packages, suppress noisy rules:

```yaml
policy_name: internal-tools
pipeline:
  known_installer_domains:
    - "install.internal.example.com"
    - "sh.rustup.rs"
    - "get.docker.com"

file_limits:
  max_file_count: 300
  max_file_size_bytes: 10485760  # 10 MB

disabled_rules:
  - EXCESSIVE_FILE_COUNT
  - MANIFEST_INVALID_NAME
```

### Example 3: Compliance Audit

Maximum strictness — everything flagged, nothing suppressed:

```yaml
policy_name: compliance-audit
pipeline:
  known_installer_domains: []
  benign_pipe_targets: []

credentials:
  known_test_values: []

file_limits:
  max_file_count: 25
  max_file_size_bytes: 1048576  # 1 MB

analysis_thresholds:
  zerowidth_threshold_with_decode: 10
  zerowidth_threshold_alone: 50
  analyzability_low_risk: 98
  analyzability_medium_risk: 90

severity_overrides:
  - rule_id: BINARY_FILE_DETECTED
    severity: HIGH
    reason: "Audit requires all binaries flagged"
  - rule_id: ARCHIVE_FILE_DETECTED
    severity: HIGH
    reason: "Audit requires all archives flagged"
  - rule_id: HIDDEN_DATA_FILE
    severity: MEDIUM
    reason: "Audit requires all hidden files flagged"
```

### Example 4: Adding a Custom Language

If your org uses Lua/R/Julia scripts in skills:

```yaml
policy_name: polyglot-org
file_classification:
  code_extensions:
    - ".py"
    - ".sh"
    - ".bash"
    - ".rb"
    - ".pl"
    - ".js"
    - ".ts"
    - ".php"
    - ".lua"
    - ".r"
    - ".jl"
```

> **Remember:** lists replace entirely, so include all extensions you want — not just the new ones.
