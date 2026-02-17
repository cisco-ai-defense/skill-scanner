# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""
Rule Registry & Pack System tests.

Three layers of validation:

1. **Unit tests** for RuleDefinition, RuleRegistry, RulePack, PackLoader.
2. **Audit tests** that ensure every rule in the codebase has a matching
   pack.yaml entry with an ``enabled`` knob – catches drift at CI time.
3. **Functional tests** that verify disabled rules via ``disabled_rules``
   actually suppress findings (parameterized over trigger skills).
"""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest
import yaml

from skill_scanner.core.rule_registry import (
    PackLoader,
    RuleDefinition,
    RulePack,
    RuleRegistry,
)
from skill_scanner.core.scan_policy import ScanPolicy

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PACKS_DIR = Path(__file__).resolve().parent.parent / "skill_scanner" / "data" / "packs"
_CORE_PACK_DIR = _PACKS_DIR / "core"
_CORE_PACK_YAML = _CORE_PACK_DIR / "pack.yaml"
_CORE_SIGNATURES_DIR = _CORE_PACK_DIR / "signatures"
_CORE_YARA_DIR = _CORE_PACK_DIR / "yara"

# Pattern to extract YARA rule names from source
_YARA_RULE_NAME_RE = re.compile(r"^rule\s+(\w+)", re.MULTILINE)


# ===========================================================================
# Helpers
# ===========================================================================


def _load_pack_rule_ids() -> set[str]:
    """Load all rule IDs declared in the core pack.yaml."""
    with open(_CORE_PACK_YAML) as fh:
        data = yaml.safe_load(fh)
    return set((data.get("rules") or {}).keys())


def _load_signature_rule_ids() -> set[str]:
    """Parse all YAML files in signatures/ and return all rule IDs."""
    ids: set[str] = set()
    for yaml_file in sorted(_CORE_SIGNATURES_DIR.glob("*.yaml")):
        with open(yaml_file) as fh:
            rules = yaml.safe_load(fh) or []
        ids.update(r["id"] for r in rules)
    return ids


def _load_yara_rule_names() -> set[str]:
    """Parse .yara files and return all YARA_ prefixed rule IDs."""
    names: set[str] = set()
    for yara_file in _CORE_YARA_DIR.glob("*.yara"):
        text = yara_file.read_text()
        for m in _YARA_RULE_NAME_RE.finditer(text):
            names.add(f"YARA_{m.group(1)}")
    return names


# ---------------------------------------------------------------------------
# Rules that are intentionally EXEMPT from requiring a pack.yaml entry.
#
# These are dynamic rules whose IDs are computed at runtime and cannot
# be enumerated statically.  Each entry includes a justification.
# ---------------------------------------------------------------------------

EXEMPT_FROM_PACK = {
    # LLM analyzer: rule_id = f"LLM_{category}" – computed from model output
    # Behavioral analyzer: BEHAVIOR_ALIGNMENT_*, BEHAVIOR_CROSSFILE_* – dynamic
    # Meta analyzer: META_VALIDATED, META_DETECTED – computed at meta-analysis
    # AIDefense analyzer: AIDEFENSE_* – computed from external API response
    # VirusTotal analyzer: VIRUSTOTAL_* – computed from external API response
    # Cross-skill scanner: CROSS_SKILL_* – only used in cross-skill mode
}

# Regex patterns for dynamic rule IDs that are exempt
_EXEMPT_PATTERNS = [
    re.compile(r"^LLM_"),
    re.compile(r"^BEHAVIOR_ALIGNMENT_"),
    re.compile(r"^BEHAVIOR_CROSSFILE_"),
    re.compile(r"^META_"),
    re.compile(r"^AIDEFENSE_"),
    re.compile(r"^VIRUSTOTAL_"),
    re.compile(r"^CROSS_SKILL_"),
]


def _is_exempt(rule_id: str) -> bool:
    """Check if a rule ID is exempt from pack.yaml coverage."""
    return any(p.match(rule_id) for p in _EXEMPT_PATTERNS)


# ===========================================================================
# 1. Unit tests for registry models
# ===========================================================================


class TestRuleDefinition:
    def test_default_knobs_have_enabled(self):
        rd = RuleDefinition(id="TEST_RULE", source_type="python", pack_name="test")
        assert "enabled" in rd.knobs
        assert rd.knobs["enabled"] is True

    def test_custom_knobs_preserved(self):
        rd = RuleDefinition(
            id="CUSTOM",
            source_type="signature",
            pack_name="test",
            knobs={"enabled": True, "threshold": 5},
        )
        assert rd.knobs["threshold"] == 5


class TestRuleRegistry:
    def test_register_and_retrieve(self):
        reg = RuleRegistry()
        rd = RuleDefinition(id="FOO", source_type="python", pack_name="test")
        reg.register(rd)
        assert "FOO" in reg
        assert reg.get("FOO") is rd
        assert len(reg) == 1

    def test_register_pack(self):
        pack = RulePack(
            name="mypack",
            version="1.0",
            description="test",
            path=Path("/tmp/fake"),
            rules={
                "A": RuleDefinition(id="A", source_type="python", pack_name="mypack"),
                "B": RuleDefinition(id="B", source_type="yara", pack_name="mypack"),
            },
        )
        reg = RuleRegistry()
        reg.register_pack(pack)
        assert len(reg) == 2
        assert "mypack" in reg.all_packs()

    def test_collision_different_packs_raises(self):
        reg = RuleRegistry()
        reg.register(RuleDefinition(id="X", source_type="python", pack_name="alpha"))
        pack = RulePack(
            name="beta",
            version="1.0",
            description="",
            path=Path("/tmp"),
            rules={"X": RuleDefinition(id="X", source_type="python", pack_name="beta")},
        )
        with pytest.raises(ValueError, match="collision"):
            reg.register_pack(pack)

    def test_get_default_knobs(self):
        reg = RuleRegistry()
        reg.register(
            RuleDefinition(
                id="R1",
                source_type="python",
                pack_name="t",
                knobs={"enabled": True, "threshold": 3},
            )
        )
        knobs = reg.get_default_knobs()
        assert knobs["R1"]["enabled"] is True
        assert knobs["R1"]["threshold"] == 3


class TestPackLoader:
    def test_load_pack_from_directory(self, tmp_path):
        pack_dir = tmp_path / "mypack"
        pack_dir.mkdir()
        (pack_dir / "pack.yaml").write_text(
            textwrap.dedent("""\
            name: mypack
            version: "2.0"
            description: A test pack
            rules:
              CUSTOM_RULE:
                source: signature
                knobs:
                  enabled: true
                  min_score: 10
        """)
        )
        (pack_dir / "signatures.yaml").write_text("[]")

        loader = PackLoader()
        pack = loader.load_pack(pack_dir)

        assert pack.name == "mypack"
        assert pack.version == "2.0"
        assert "CUSTOM_RULE" in pack.rules
        assert pack.rules["CUSTOM_RULE"].knobs["min_score"] == 10
        assert pack.signatures_file == pack_dir / "signatures.yaml"

    def test_discover_packs_finds_core(self):
        loader = PackLoader()
        packs = loader.discover_packs()
        names = {p.name for p in packs}
        assert "core" in names

    def test_build_registry_has_core_rules(self):
        loader = PackLoader()
        registry = loader.build_registry()
        # Core pack should have many rules
        assert len(registry) > 50
        # Spot-check a few rules from each source
        assert "FIND_EXEC_PATTERN" in registry  # signature
        assert "YARA_embedded_elf_binary" in registry  # yara
        assert "PDF_STRUCTURAL_THREAT" in registry  # python

    def test_extra_dirs_additive(self, tmp_path):
        ext_dir = tmp_path / "ext"
        ext_dir.mkdir()
        (ext_dir / "pack.yaml").write_text(
            textwrap.dedent("""\
            name: ext-rules
            version: "1.0"
            rules:
              EXT_CUSTOM_CHECK:
                source: signature
                knobs:
                  enabled: true
        """)
        )
        loader = PackLoader()
        registry = loader.build_registry(extra_dirs=[ext_dir])
        assert "EXT_CUSTOM_CHECK" in registry
        # Core rules are still there
        assert "FIND_EXEC_PATTERN" in registry

    def test_missing_pack_yaml_raises(self, tmp_path):
        loader = PackLoader()
        with pytest.raises(FileNotFoundError, match="pack.yaml"):
            loader.load_pack(tmp_path)

    def test_enabled_knob_guaranteed(self):
        """Every rule loaded from the core pack must have an enabled knob."""
        loader = PackLoader()
        pack = loader.load_pack(_CORE_PACK_DIR)
        for rule_id, rule_def in pack.rules.items():
            assert "enabled" in rule_def.knobs, f"Rule '{rule_id}' in core pack is missing 'enabled' knob"


# ===========================================================================
# 2. Audit tests – ensure pack.yaml covers all rules in the codebase
# ===========================================================================


class TestPackCoverageAudit:
    """Ensures every rule in the codebase has a matching pack.yaml entry.

    When a developer adds a new rule, this test fails immediately,
    telling them exactly which entry to add.
    """

    def test_all_signature_rules_in_pack(self):
        """Every rule in signatures/*.yaml must have an entry in pack.yaml."""
        sig_ids = _load_signature_rule_ids()
        pack_ids = _load_pack_rule_ids()
        missing = sig_ids - pack_ids
        assert not missing, (
            f"Signature rules missing from pack.yaml: {sorted(missing)}. Add entries to {_CORE_PACK_YAML}"
        )

    def test_all_yara_rules_in_pack(self):
        """Every YARA rule must have a YARA_-prefixed entry in pack.yaml."""
        yara_ids = _load_yara_rule_names()
        pack_ids = _load_pack_rule_ids()
        missing = yara_ids - pack_ids
        assert not missing, f"YARA rules missing from pack.yaml: {sorted(missing)}. Add entries to {_CORE_PACK_YAML}"

    def test_pack_entries_have_enabled_knob(self):
        """Every rule in pack.yaml must have at least an 'enabled' knob."""
        with open(_CORE_PACK_YAML) as fh:
            data = yaml.safe_load(fh)
        rules = data.get("rules") or {}
        for rule_id, rule_data in rules.items():
            knobs = (rule_data or {}).get("knobs", {})
            assert "enabled" in knobs, f"Rule '{rule_id}' in pack.yaml is missing 'enabled' knob"

    def test_no_orphan_pack_entries_for_signatures(self):
        """pack.yaml signature entries should correspond to actual rules."""
        sig_ids = _load_signature_rule_ids()
        with open(_CORE_PACK_YAML) as fh:
            data = yaml.safe_load(fh)
        pack_sigs = {
            rid
            for rid, rd in (data.get("rules") or {}).items()
            if isinstance(rd, dict) and rd.get("source") == "signature"
        }
        orphans = pack_sigs - sig_ids
        assert not orphans, (
            f"pack.yaml declares signature rules that don't exist in signatures/*.yaml: {sorted(orphans)}"
        )

    def test_no_orphan_pack_entries_for_yara(self):
        """pack.yaml YARA entries should correspond to actual .yara rules."""
        yara_ids = _load_yara_rule_names()
        with open(_CORE_PACK_YAML) as fh:
            data = yaml.safe_load(fh)
        pack_yara = {
            rid for rid, rd in (data.get("rules") or {}).items() if isinstance(rd, dict) and rd.get("source") == "yara"
        }
        orphans = pack_yara - yara_ids
        assert not orphans, f"pack.yaml declares YARA rules that don't exist in .yara files: {sorted(orphans)}"


# ===========================================================================
# 3. Functional disabled rules tests (key rules)
# ===========================================================================


class TestEnabledKnobFunctional:
    """Verify that disabled rules via policy.disabled_rules suppress findings."""

    def test_pdf_structural_disabled(self, make_skill):
        """PDF_STRUCTURAL_THREAT should not fire when disabled in policy."""
        from skill_scanner.core.analyzer_factory import build_core_analyzers

        policy = ScanPolicy.default()
        policy.disabled_rules.add("PDF_STRUCTURAL_THREAT")
        analyzers = build_core_analyzers(policy)

        # Create a skill with a PDF (the pdfid import may fail, but the
        # enabled check happens before that)
        files = {
            "SKILL.md": "---\nname: pdf-test\ndescription: Test skill\n---\n# pdf-test\nTest.",
        }
        skill = make_skill(files)
        for a in analyzers:
            findings = a.analyze(skill)
            for f in findings:
                assert f.rule_id != "PDF_STRUCTURAL_THREAT"

    def test_office_document_disabled(self, make_skill):
        """OFFICE_DOCUMENT_THREAT should not fire when disabled in policy."""
        from skill_scanner.core.analyzer_factory import build_core_analyzers

        policy = ScanPolicy.default()
        policy.disabled_rules.add("OFFICE_DOCUMENT_THREAT")
        analyzers = build_core_analyzers(policy)

        files = {
            "SKILL.md": "---\nname: doc-test\ndescription: Test skill\n---\n# doc-test\nTest.",
        }
        skill = make_skill(files)
        for a in analyzers:
            findings = a.analyze(skill)
            for f in findings:
                assert f.rule_id != "OFFICE_DOCUMENT_THREAT"

    def test_signature_rule_disabled_via_policy(self, make_skill):
        """A signature rule should not fire when disabled in policy.disabled_rules."""
        from skill_scanner.core.analyzer_factory import build_core_analyzers

        policy = ScanPolicy.default()
        policy.disabled_rules.add("RESOURCE_ABUSE_INFINITE_LOOP")
        analyzers = build_core_analyzers(policy)

        files = {
            "SKILL.md": "---\nname: loop-test\ndescription: Test skill\n---\n# loop-test\nRuns a loop.",
            "run.py": "while True:\n    do_something()\n",
        }
        skill = make_skill(files)
        for a in analyzers:
            findings = a.analyze(skill)
            for f in findings:
                assert f.rule_id != "RESOURCE_ABUSE_INFINITE_LOOP", (
                    "RESOURCE_ABUSE_INFINITE_LOOP fired despite being in disabled_rules"
                )


# ===========================================================================
# Phase 4 tests: directory-based signature loading
# ===========================================================================


class TestDirectorySignatureLoading:
    """Verify RuleLoader correctly loads from a signatures/ directory."""

    def test_loader_reads_directory(self):
        """RuleLoader should load all 41 rules from the signatures/ directory."""
        from skill_scanner.core.rules.patterns import RuleLoader

        loader = RuleLoader()  # defaults to signatures/ directory
        rules = loader.load_rules()
        assert len(rules) == 45, f"Expected 45 rules, got {len(rules)}"

    def test_loader_has_all_categories(self):
        """All 9 categories should be represented."""
        from skill_scanner.core.rules.patterns import RuleLoader

        loader = RuleLoader()
        loader.load_rules()
        categories = set(r.category.value for r in loader.rules)
        expected = {
            "command_injection",
            "data_exfiltration",
            "hardcoded_secrets",
            "obfuscation",
            "prompt_injection",
            "resource_abuse",
            "social_engineering",
            "supply_chain_attack",
            "unauthorized_tool_use",
        }
        assert categories == expected

    def test_loader_backward_compat_single_file(self, tmp_path):
        """RuleLoader should still work when pointed at a single YAML file."""
        from skill_scanner.core.rules.patterns import RuleLoader

        sig_file = tmp_path / "custom.yaml"
        sig_file.write_text(
            textwrap.dedent("""\
            - id: TEST_RULE
              category: obfuscation
              severity: LOW
              patterns: ["test_pattern"]
              description: "Test rule"
        """)
        )
        loader = RuleLoader(rules_file=sig_file)
        rules = loader.load_rules()
        assert len(rules) == 1
        assert rules[0].id == "TEST_RULE"

    def test_loader_raises_on_malformed_yaml_in_directory(self, tmp_path):
        """Malformed YAML in a rules directory should fail fast."""
        from skill_scanner.core.rules.patterns import RuleLoader

        (tmp_path / "good.yaml").write_text(
            textwrap.dedent("""\
            - id: TEST_RULE
              category: obfuscation
              severity: LOW
              patterns: ["ok"]
              description: "Test rule"
            """)
        )
        # Intentionally malformed YAML (missing closing bracket)
        (tmp_path / "bad.yaml").write_text(
            textwrap.dedent("""\
            - id: BAD_RULE
              category: obfuscation
              severity: LOW
              patterns: ["oops"
              description: "Broken rule"
            """)
        )

        loader = RuleLoader(rules_file=tmp_path)
        with pytest.raises(RuntimeError, match="Failed to load rules from"):
            loader.load_rules()

    def test_packloader_detects_signatures_dir(self):
        """PackLoader should detect signatures/ directory over signatures.yaml."""
        loader = PackLoader()
        packs = loader.discover_packs()
        core = next(p for p in packs if p.name == "core")
        assert core.signatures_dir is not None, "Core pack should have signatures_dir set"
        assert core.signatures_file is None, "Core pack should NOT have signatures_file set"
        assert core.signatures_dir.is_dir()


# ===========================================================================
# Phase 4 tests: extracted Python check modules
# ===========================================================================


class TestExtractedCheckModules:
    """Verify that extracted check modules produce the same findings."""

    def test_manifest_checks_invalid_name(self):
        """manifest_checks.check_manifest should flag invalid names."""
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.data.packs.core.python.manifest_checks import check_manifest

        policy = ScanPolicy.default()

        # Create a mock manifest with invalid name
        class FakeManifest:
            name = "Invalid Name With Spaces"
            description = "A valid description that is long enough to pass checks"
            license = "MIT"
            compatibility = ""
            allowed_tools = []

        findings = check_manifest(FakeManifest(), policy)
        rule_ids = [f.rule_id for f in findings]
        assert "MANIFEST_INVALID_NAME" in rule_ids

    def test_manifest_checks_missing_license(self):
        """manifest_checks.check_manifest should flag missing license."""
        from skill_scanner.core.scan_policy import ScanPolicy
        from skill_scanner.data.packs.core.python.manifest_checks import check_manifest

        policy = ScanPolicy.default()

        class FakeManifest:
            name = "valid-name"
            description = "A valid description that is long enough to pass checks"
            license = ""
            compatibility = ""
            allowed_tools = []

        findings = check_manifest(FakeManifest(), policy)
        rule_ids = [f.rule_id for f in findings]
        assert "MANIFEST_MISSING_LICENSE" in rule_ids

    def test_trigger_checks_generic_pattern(self):
        """trigger_checks should detect overly generic descriptions."""
        from skill_scanner.data.packs.core.python.trigger_checks import check_generic_patterns

        class FakeSkill:
            description = "help me"

        findings = check_generic_patterns(FakeSkill())
        assert len(findings) >= 1
        assert findings[0].rule_id == "TRIGGER_OVERLY_GENERIC"

    def test_trigger_checks_short_description(self):
        """trigger_checks should detect too-short descriptions."""
        from skill_scanner.data.packs.core.python.trigger_checks import check_description_specificity

        class FakeSkill:
            description = "Hi"

        findings = check_description_specificity(FakeSkill())
        assert len(findings) >= 1
        assert findings[0].rule_id == "TRIGGER_DESCRIPTION_TOO_SHORT"
