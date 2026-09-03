# Static Analyzer

> [!TIP]
> **TL;DR**
>
> The static analyzer runs an ordered, deterministic pipeline covering YAML
> signatures, bounded contextual Python rules, YARA-X, binary and document
> inspection, Unicode concealment, dependency pinning, allowed-tools
> enforcement, and final finding refinement. It is an always-on core analyzer
> and requires no external services.

The static analyzer is the primary deterministic detection engine. It combines YAML signature matching, YARA-X rule scanning, Python-based checks, and file inventory analysis to detect security threats without requiring external services.

<small>Source: [`skill_scanner/core/analyzers/static.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/analyzers/static.py)</small>

## Analysis Flow

The `analyze()` method performs scanning and post-processing in the following
order. Manifest and consistency checks require a complete manifest; YARA runs
only when its scanner is enabled and available.

```mermaid
flowchart TD
    S01["Manifest validation"] --> S02["Instruction signatures"]
    S02 --> S03["Active dynamic execution"]
    S03 --> S04["Hidden HTML instructions"]
    S04 --> S05["Remote acquire + execute"]
    S05 --> S06["Active semantic directives"]
    S06 --> S07["Unicode smuggling"]
    S07 --> S08["Script/code signatures"]
    S08 --> S09["Dynamic sensitive-file access"]
    S09 --> S10["Consistency + allowed tools"]
    S10 --> S11["Dependency pinning"]
    S11 --> S12["Config-file URLs"]
    S12 --> S13["Referenced files"]
    S13 --> S14["Binary files"]
    S14 --> S15["Hidden files"]
    S15 --> S16["ASCII smuggling"]
    S16 --> S17["Unicode-obfuscated instructions"]
    S17 --> S18["File inventory"]
    S18 --> S19["PDF documents"]
    S19 --> S20["Office documents"]
    S20 --> S21["Homoglyphs"]
    S21 --> S22["YARA-X"]
    S22 --> S23["Asset signatures"]
    S23 --> S24["Disabled-rule filter"]
    S24 --> S25["Test-credential filter"]
    S25 --> S26["Deduplication"]
    S26 --> S27["Unreferenced-script context"]
    S27 --> S28["Core-signature refinement"]
```

Each pass targets a different aspect of the skill package:

| Stage | Method | What it checks |
|---|---|---|
| Manifest | `_check_manifest()` | Skill name, description, frontmatter integrity |
| Instruction body | `_scan_instruction_body()` | SKILL.md content against signature rules |
| Active dynamic execution | `check_active_dynamic_execution()` | Bounded active-context `eval`/`exec` and reviewed process-launch APIs |
| Hidden HTML | `check_active_hidden_html()` | Active concealed instructions in HTML comments/elements |
| Remote acquire/execute | `check_active_remote_execution()` | Active remote payload acquisition joined to execution |
| Semantic directives | `check_active_semantic_directives()` | Mandatory helper execution, persistence, and sensitive-data exfiltration instructions |
| Unicode smuggling | `check_unicode_smuggling()` | Active Unicode tag-character smuggling |
| Script scanning | `_scan_scripts()` | Python/bash/other scripts against signatures |
| Dynamic sensitive access | `_check_dynamic_sensitive_file_access()` | Dynamic glob/enumeration of credential and configuration paths |
| Consistency | `_check_consistency()` | Mismatch between manifest claims and behavior, including allowed-tools enforcement |
| Dependency pinning | `_check_dependency_pinning()` | Unpinned dependencies in `requirements*.txt`, `pyproject.toml`, `setup.cfg`, `setup.py`, `Pipfile`, and manifest metadata |
| Config file URLs | `_scan_config_files()` | URLs in config/settings/TOML files classified via the shared `url_classifier` |
| Referenced files | `_scan_referenced_files()` | Files mentioned in SKILL.md instructions |
| Binary files | `_check_binary_files()` | Extension/magic mismatch, archive detection, unknown binaries |
| Hidden files | `_check_hidden_files()` | Dotfiles, `__pycache__`, policy-allowed exceptions |
| ASCII smuggling | `_check_ascii_smuggling()` | Unicode tag blocks that conceal ASCII payloads |
| Unicode-obfuscated instructions | `_check_unicode_obfuscated_instructions()` | Bounded normalization of active obfuscated instruction text |
| File inventory | `_check_file_inventory()` | Package anomalies (file count, types, sizes) |
| PDF documents | `_check_pdf_documents()` | Structural analysis via pdfid for suspicious elements |
| Office documents | `_check_office_documents()` | VBA macros and suspicious OLE indicators |
| Homoglyphs | `_check_homoglyph_attacks()` | Unicode homoglyph attacks in code files |
| YARA | `_yara_scan()` | YARA-X rule matches across all eligible files |
| Asset files | `_scan_asset_files()` | Non-script assets against signature rules |
| Disabled-rule filter | `_is_rule_enabled()` | Removes findings disabled by CLI, YARA mode, or policy |
| Test-credential filter | `_is_known_test_credential()` | Removes configured test/placeholder credential findings |
| Deduplication | `_dedupe_findings()` | Collapses overlapping findings when policy enables it |
| Context annotation | `_annotate_unreferenced_script_context()` | Adds unreferenced executable context to existing findings |
| Signature refinement | `refine_core_signature_findings()` | Applies bounded package-local dataflow and file-role refinement to broad core signature candidates |

## Rule Sources

### YAML Signatures

<small>Source: [`skill_scanner/data/packs/core/signatures/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/skill_scanner/data/packs/core/signatures/)</small>

Loaded by `RuleLoader` ([`skill_scanner/core/rules/patterns.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/rules/patterns.py)), each `SecurityRule` includes:

- `id` -- unique rule identifier
- `category` -- maps to `ThreatCategory` enum
- `severity` -- maps to `Severity` enum
- `patterns` -- list of regex patterns (compiled at load time)
- `exclude_patterns` -- optional patterns that suppress matches
- `file_types` -- optional file type scope (e.g., python-only rules)
- `description` and `remediation` -- human-readable context

Signature files cover: command injection, data exfiltration, hardcoded secrets, obfuscation, privilege escalation, and more.

### YARA Rules

<small>Source: [`skill_scanner/data/packs/core/yara/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/skill_scanner/data/packs/core/yara/)</small>

Scanned by `YaraScanner` ([`skill_scanner/core/rules/yara_scanner.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/rules/yara_scanner.py)). YARA rules detect complex multi-pattern threats that are difficult to express as individual regex signatures, such as tool chaining, system manipulation, and prompt injection.

### Python-Based Checks

<small>Sources: [`skill_scanner/data/packs/core/python/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/skill_scanner/data/packs/core/python/) and [`skill_scanner/core/rules/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/skill_scanner/core/rules/)</small>

Programmatic checks are declared in `pack.yaml` and implemented in reusable
pack modules, bounded contextual rule helpers, and analyzer-owned passes. They
handle logic that requires more than regex matching, such as trigger quality,
manifest validation, allowed-tools enforcement, active instruction context,
and analyzability scoring. The closed-world manifest inventory now explicitly
accepts these four added Python/static rule IDs:

- `ACTIVE_REMOTE_ACQUIRE_EXECUTE`
- `MANDATORY_AUTOMATIC_HELPER_EXECUTION`
- `ACTIVE_OS_PERSISTENCE_DIRECTIVE`
- `ACTIVE_SENSITIVE_EXFILTRATION`

### Pack Manifest

<small>Source: [`skill_scanner/data/packs/core/pack.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/pack.yaml)</small>

The pack manifest registers all rule sources and metadata for the core detection pack.

## Detection Coverage

- Prompt injection
- Command/code injection
- Data exfiltration
- Obfuscation (encoding tricks, steganography patterns)
- Hardcoded credentials and secrets
- Archive/binary risks
- Tool mismatch and manifest consistency
- Supply-chain risk from unpinned dependencies
- Suspicious/tunnel URLs in configuration files
- Hidden file and dotfile risks
- Document-embedded threats (PDF, Office macros)
- Unicode homoglyph attacks
- File inventory anomalies

## Policy-Aware Behavior

Static analysis behavior is shaped by several policy sections:

- **Rule scoping** (`rule_scoping`) -- file and path inclusion, documentation-path demotion/suppression
- **Docs demotion** -- findings in doc paths can be suppressed or severity-demoted
- **File classification** -- inert/structured/archive extension lists control binary check behavior
- **Severity overrides** -- promote or demote specific rules
- **Disabled rules** -- skip individual rule IDs entirely
- **Credential policy** -- known test values are filtered from hardcoded secret findings
- **Deduplication** -- overlapping findings from multiple scan passes are collapsed when enabled

## Custom Rules

- Validate custom signature sets with `skill-scanner validate-rules`
- Supply additional YARA rules at runtime with `--custom-rules` (applies to YARA scanning only, not YAML signatures)

## Related Pages

- [Writing Custom Rules](writing-custom-rules.md)
- [Custom Policy Configuration](../../user-guide/custom-policy-configuration.md)
- [Binary Handling](../binary-handling.md)
