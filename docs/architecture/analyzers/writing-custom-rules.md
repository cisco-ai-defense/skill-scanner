# Rule Authoring Guide

## Overview

skill-scanner supports three rule types:

1. **Signature rules** — regex-based pattern matching
2. **YARA rules** — binary/pattern matching for complex detection
3. **Python rules** — programmatic logic for nuanced checks

Every rule must be registered in [`pack.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/pack.yaml). The pack manifest is the single source of truth for rule metadata; the rule registry audit in tests will fail if a rule exists in the codebase but has no pack entry.

---

## Authoring Workflow (Checklist)

1. Pick the rule type (`signature`, `yara`, `python`) based on detection complexity.
2. Implement the rule in the correct directory under [`skill_scanner/data/packs/core/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/skill_scanner/data/packs/core/).
3. Add or update the [`pack.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/pack.yaml) entry (`source`, `description`, `severity`, and `knobs.enabled`).
4. Wire policy knobs in [`scan_policy.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/scan_policy.py) and [`default_policy.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/default_policy.yaml) if your rule introduces new tunables.
5. Add tests that prove true positives and expected suppression behavior.
6. Run validation before opening a PR:
   - `skill-scanner validate-rules`
   - `uv run pytest tests/test_rule_registry.py tests/test_static_policy_integration.py -q`

---

## Signature Rules

**Location:** [`skill_scanner/data/packs/core/signatures/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/skill_scanner/data/packs/core/signatures/)

One YAML file per category (e.g., [`command_injection.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/signatures/command_injection.yaml), [`prompt_injection.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/signatures/prompt_injection.yaml)). Each rule is a list item with these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique uppercase identifier (e.g., `COMMAND_INJECTION_EVAL`) |
| `patterns` | Yes | List of regex strings; any match triggers the rule |
| `severity` | Yes | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `category` | Yes | Threat category (e.g., `command_injection`, `prompt_injection`) |
| `description` | Yes | Human-readable description |
| `exclude_patterns` | No | Regexes that suppress a match when present |
| `file_types` | No | Restrict rule to `python`, `bash`, `markdown`, etc. If omitted, applies to all |
| `remediation` | No | Guidance for fixing the issue |

**Example** (from [`signatures/command_injection.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/signatures/command_injection.yaml)):

```yaml
- id: COMMAND_INJECTION_EVAL
  category: command_injection
  severity: CRITICAL
  patterns:
    - "\\beval\\s*\\("
    - "\\bexec\\s*\\("
    - "\\b__import__\\s*\\("
    - "(?<!re\\.)\\bcompile\\s*\\("
  file_types: [python]
  description: "Dangerous code execution functions that can execute arbitrary code"
  remediation: "Avoid eval(), exec(), and compile(). Use safer alternatives like ast.literal_eval()"
```

---

## YARA Rules

**Location:** [`skill_scanner/data/packs/core/yara/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/skill_scanner/data/packs/core/yara/)

Standard `.yara` syntax. Rule names become rule IDs with a `YARA_` prefix (e.g., `rule command_injection_generic` becomes `YARA_command_injection_generic`).

**Required `meta:` fields:**

| Meta key | Purpose |
|----------|---------|
| `description` | Human-readable description (used in findings) |
| `classification` | Often `"harmful"` — used for threat mapping |
| `threat_type` | Maps to threat category (e.g., `INJECTION ATTACK`, `PROMPT INJECTION`) |

Severity and category are derived from `threat_type` at runtime. The pack.yaml entry documents the rule and may include knob defaults.

**Example structure** (from [`yara/command_injection_generic.yara`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/yara/command_injection_generic.yara)):

```yara
rule command_injection_generic {

    meta:
        author = "Cisco"
        description = "Detects command injection patterns in agent skills"
        classification = "harmful"
        threat_type = "INJECTION ATTACK"

    strings:
        $dangerous_system_cmds = /\b(shutdown|reboot|halt|poweroff)\s+(-[fh]|now|0)\b/
        $reverse_shell_bash = /\bbash\s+-i\s+>&?\s*\/dev\/tcp\//i
        $safe_cleanup = /(rm\s+-rf\s+(\/var\/lib\/apt|\/tmp\/|node_modules)...)/

    condition:
        not $safe_cleanup and
        ($dangerous_system_cmds or $reverse_shell_bash or ...)
}
```

---

## Python Rules

**Location:** [`skill_scanner/data/packs/core/python/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/skill_scanner/data/packs/core/python/)

Each module defines one or more `check_*` functions. The analyzer imports and invokes these; findings are aggregated by the analyzer.

**Function signature:**

```python
def check_<aspect>(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    """Analyze the skill for specific anomalies. Returns findings."""
    findings: list[Finding] = []

    # Access policy sections
    max_count = policy.file_limits.max_file_count
    min_lines = policy.analysis_thresholds.min_dangerous_lines

    # Skip if rule is disabled
    if "MY_RULE_ID" in policy.disabled_rules:
        return findings

    # Emit findings
    findings.append(
        Finding(
            id=generate_finding_id("RULE_ID", context),
            rule_id="RULE_ID",
            category=ThreatCategory.POLICY_VIOLATION,
            severity=Severity.HIGH,
            title="Short title",
            description="Detailed description",
            file_path=skill_file.relative_path,
            remediation="How to fix",
            analyzer="static",  # or "pipeline", "scanner", etc.
        )
    )
    return findings
```

**Policy access:** Use policy sections directly:

- `policy.file_limits.max_file_count`, `policy.file_limits.max_file_size_bytes`
- `policy.analysis_thresholds.min_dangerous_lines`, `policy.analysis_thresholds.min_confidence_pct`
- `policy.pipeline.*` (for taint, installer allowlists, and compound fetch/execute knobs)
- `policy.file_classification.*`, `policy.hidden_files.*`, `policy.rule_scoping.*`
- `policy.credentials.*`, `policy.system_cleanup.*`, `policy.command_safety.*`
- `policy.finding_output.*` for dedupe and finding metadata behavior
- `policy.disabled_rules` — check before emitting to respect rule disabling

**Example** (from [`python/file_inventory_checks.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/python/file_inventory_checks.py)):

```python
def check_file_inventory(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    findings: list[Finding] = []
    max_file_count = policy.file_limits.max_file_count

    if len(skill.files) > max_file_count:
        findings.append(
            Finding(
                id=generate_finding_id("EXCESSIVE_FILE_COUNT", str(len(skill.files))),
                rule_id="EXCESSIVE_FILE_COUNT",
                category=ThreatCategory.POLICY_VIOLATION,
                severity=Severity.LOW,
                title="Skill package contains many files",
                description=f"Skill package contains {len(skill.files)} files.",
                file_path=".",
                remediation="Review file inventory and remove unnecessary files.",
                analyzer="static",
            )
        )
    return findings
```

---

## Registering in pack.yaml

Every rule must have an entry in [`skill_scanner/data/packs/core/pack.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/pack.yaml).

**Required fields:**

- `source`: `signature`, `yara`, or `python`
- `category`: Threat category (for signature/YARA; Python usually inherits from Finding)
- `severity`: Default severity
- `description`: One-line description
- `knobs.enabled`: `true` (default)

**Optional fields:**

- `knobs`: Documentation-only defaults (e.g., `max_file_count: 100`)
- `analyzer`: For Python rules — `static`, `pipeline`, `scanner`, `content_extractor`, `behavioral`
- `file_types`: For scoping

**Example entries:**

```yaml
# Signature rule
COMMAND_INJECTION_EVAL:
  source: signature
  category: command_injection
  severity: CRITICAL
  knobs:
    enabled: true
  description: "Dangerous code execution functions"

# YARA rule (rule name + YARA_ prefix = ID)
YARA_command_injection_generic:
  source: yara
  knobs:
    enabled: true
  description: "Command injection patterns"

# Python rule
EXCESSIVE_FILE_COUNT:
  source: python
  analyzer: static
  knobs:
    enabled: true
    max_file_count: 100
  description: "Skill package contains too many files"
```

---

## Policy Knobs

Tunable parameters live in policy YAML sections, not in pack.yaml. The `knobs` in pack.yaml are **documentation only**; they describe default or typical values but are not enforced.

To add a tunable threshold for your rule:

1. Add the field to the appropriate policy dataclass in [`scan_policy.py`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/core/scan_policy.py) (e.g., `FileLimitsPolicy`, `AnalysisThresholdsPolicy`).
2. Wire it in `_from_dict` and `_to_dict`.
3. Add it to the default policy YAML ([`default_policy.yaml`](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/default_policy.yaml)).
4. Use it in your Python check: `policy.file_limits.my_new_threshold`.

**Available sections:**

| Section | Purpose |
|---------|---------|
| `file_limits` | `max_file_count`, `max_file_size_bytes`, `max_reference_depth`, `min_description_length`, etc. |
| `analysis_thresholds` | `min_dangerous_lines`, `min_confidence_pct`, `zerowidth_threshold_*`, etc. |
| `pipeline` | `demote_in_docs`, `demote_instructional`, `benign_pipe_targets`, fetch/execute tuning knobs |
| `rule_scoping` | Rule scope by file context (`skillmd_and_scripts_only`, `skip_in_docs`, `code_only`) |
| `file_classification` | `inert_extensions`, `archive_extensions`, `code_extensions`, shebang compatibility knobs |
| `hidden_files` | `benign_dotfiles`, `benign_dotdirs` |
| `credentials` | Test values/placeholders to suppress in hardcoded-secret filtering |
| `system_cleanup` | Safe cleanup targets for destructive command heuristics |
| `command_safety` | Safe/caution/risky/dangerous command tiers and dangerous arg patterns |
| `finding_output` | Dedupe strategy and policy-fingerprint attachment |
| `disabled_rules` | Rule IDs to suppress entirely |

---

## Testing

1. **Validate rule loading and schema:** `skill-scanner validate-rules`
2. **Run targeted rule/policy regression tests:** `uv run pytest tests/test_rule_registry.py tests/test_static_policy_integration.py -q`
3. **Run the full suite before merge:** `make test`
4. **Add unit tests for new behavior:** Add coverage in [`tests/`](https://github.com/cisco-ai-defense/skill-scanner/tree/main/tests) (for example, `tests/test_new_detections.py` or analyzer-specific test modules).

---

## Directory Structure

```
skill_scanner/data/packs/core/
├── [pack.yaml](https://github.com/cisco-ai-defense/skill-scanner/blob/main/skill_scanner/data/packs/core/pack.yaml)              # Manifest – declares all rules + metadata
├── signatures/            # Regex-based rules
│   ├── command_injection.yaml
│   ├── data_exfiltration.yaml
│   ├── hardcoded_secrets.yaml
│   ├── obfuscation.yaml
│   ├── prompt_injection.yaml
│   ├── resource_abuse.yaml
│   ├── social_engineering.yaml
│   ├── supply_chain.yaml
│   └── unauthorized_tool_use.yaml
├── yara/                  # YARA binary/text pattern rules
│   ├── command_injection_generic.yara
│   ├── prompt_injection_generic.yara
│   ├── embedded_binary_detection.yara
│   └── ...
└── python/                # Programmatic checks
    ├── __init__.py
    ├── _helpers.py
    ├── allowed_tools_checks.py
    ├── analyzability_checks.py
    ├── archive_checks.py
    ├── asset_checks.py
    ├── binary_file_checks.py
    ├── bytecode_checks.py
    ├── consistency_checks.py
    ├── external_tool_checks.py
    ├── file_inventory_checks.py
    ├── hidden_file_checks.py
    ├── manifest_checks.py
    └── trigger_checks.py
```

## Related Pages

- [Static Analyzer](/architecture/analyzers/static-analyzer) -- How custom rules are loaded and matched
- [Threat Taxonomy](/architecture/threat-taxonomy) -- Threat categories and severity levels for rule authoring
- [Custom Policy Configuration](/user-guide/custom-policy-configuration) -- Policy knobs that affect rule behavior
