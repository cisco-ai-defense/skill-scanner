# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""
Tests for multi-pack signature rule loading.

Covers the ``--rule-packs`` feature: extra_rules_dirs in RuleLoader,
pack discovery/resolution helpers, analyzer factory forwarding,
and CLI argument wiring.
"""

from __future__ import annotations

import argparse
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.rules.patterns import RuleLoader, SecurityRule
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.data import list_available_packs, resolve_rule_packs

# ===========================================================================
# Helpers
# ===========================================================================

_VALID_RULE_FLAT = textwrap.dedent("""\
    - id: FLAT_RULE_1
      category: obfuscation
      severity: LOW
      patterns: ["test_flat"]
      description: "A flat-list rule"
""")

_VALID_RULE_WRAPPED = textwrap.dedent("""\
    signatures:
      - id: WRAPPED_RULE_1
        category: command_injection
        severity: HIGH
        patterns: ["test_wrapped"]
        description: "A signatures-wrapped rule"
      - id: WRAPPED_RULE_2
        category: data_exfiltration
        severity: MEDIUM
        patterns: ["test_wrapped_2"]
        description: "Another wrapped rule"
""")

_RULE_UNKNOWN_CATEGORY = textwrap.dedent("""\
    - id: UNKNOWN_CAT_RULE
      category: totally_made_up_category
      severity: LOW
      patterns: ["something"]
      description: "Rule with non-taxonomy category"
""")


def _write_yaml(directory: Path, filename: str, content: str) -> Path:
    fp = directory / filename
    fp.write_text(content, encoding="utf-8")
    return fp


# ===========================================================================
# 1. RuleLoader – _extract_rules_list
# ===========================================================================


class TestExtractRulesList:
    """Verify _extract_rules_list handles both flat and wrapped YAML."""

    def test_flat_list_returned_as_is(self):
        data = [{"id": "R1"}, {"id": "R2"}]
        result = RuleLoader._extract_rules_list(data, Path("test.yaml"))
        assert result == data

    def test_dict_with_signatures_key_unwrapped(self):
        inner = [{"id": "R1"}]
        data = {"signatures": inner}
        result = RuleLoader._extract_rules_list(data, Path("test.yaml"))
        assert result == inner

    def test_dict_without_signatures_key_raises(self):
        data = {"rules": [{"id": "R1"}]}
        with pytest.raises(RuntimeError, match="signatures"):
            RuleLoader._extract_rules_list(data, Path("test.yaml"))

    def test_non_list_non_dict_raises(self):
        with pytest.raises(RuntimeError):
            RuleLoader._extract_rules_list("not valid", Path("test.yaml"))

    def test_none_data_raises_with_empty_message(self):
        with pytest.raises(RuntimeError, match="file is empty"):
            RuleLoader._extract_rules_list(None, Path("empty.yaml"))

    def test_empty_yaml_file_raises(self, tmp_path):
        empty = tmp_path / "empty.yaml"
        empty.write_text("", encoding="utf-8")
        loader = RuleLoader(rules_file=empty)
        with pytest.raises(RuntimeError, match="file is empty"):
            loader.load_rules()


# ===========================================================================
# 2. RuleLoader – extra_rules_dirs
# ===========================================================================


class TestRuleLoaderExtraDirs:
    """Verify RuleLoader loads from extra_rules_dirs alongside primary."""

    def test_extra_dir_rules_appended(self, tmp_path):
        primary = tmp_path / "primary"
        primary.mkdir()
        _write_yaml(primary, "core.yaml", _VALID_RULE_FLAT)

        extra = tmp_path / "extra"
        extra.mkdir()
        _write_yaml(extra, "ext.yaml", _VALID_RULE_WRAPPED)

        loader = RuleLoader(rules_file=primary, extra_rules_dirs=[extra])
        rules = loader.load_rules()

        ids = {r.id for r in rules}
        assert "FLAT_RULE_1" in ids
        assert "WRAPPED_RULE_1" in ids
        assert "WRAPPED_RULE_2" in ids
        assert len(rules) == 3

    def test_extra_dir_nonexistent_is_skipped(self, tmp_path):
        primary = tmp_path / "primary"
        primary.mkdir()
        _write_yaml(primary, "core.yaml", _VALID_RULE_FLAT)

        loader = RuleLoader(
            rules_file=primary,
            extra_rules_dirs=[tmp_path / "does_not_exist"],
        )
        rules = loader.load_rules()
        assert len(rules) == 1
        assert rules[0].id == "FLAT_RULE_1"

    def test_multiple_extra_dirs(self, tmp_path):
        primary = tmp_path / "primary"
        primary.mkdir()
        _write_yaml(primary, "core.yaml", _VALID_RULE_FLAT)

        extra_a = tmp_path / "extra_a"
        extra_a.mkdir()
        _write_yaml(
            extra_a,
            "a.yaml",
            textwrap.dedent("""\
                - id: EXTRA_A
                  category: malware
                  severity: CRITICAL
                  patterns: ["extra_a"]
                  description: "From pack A"
            """),
        )

        extra_b = tmp_path / "extra_b"
        extra_b.mkdir()
        _write_yaml(
            extra_b,
            "b.yaml",
            textwrap.dedent("""\
                signatures:
                  - id: EXTRA_B
                    category: prompt_injection
                    severity: HIGH
                    patterns: ["extra_b"]
                    description: "From pack B (wrapped)"
            """),
        )

        loader = RuleLoader(
            rules_file=primary,
            extra_rules_dirs=[extra_a, extra_b],
        )
        rules = loader.load_rules()
        ids = {r.id for r in rules}
        assert ids == {"FLAT_RULE_1", "EXTRA_A", "EXTRA_B"}

    def test_no_extra_dirs_loads_primary_only(self, tmp_path):
        primary = tmp_path / "primary"
        primary.mkdir()
        _write_yaml(primary, "core.yaml", _VALID_RULE_FLAT)

        loader = RuleLoader(rules_file=primary)
        rules = loader.load_rules()
        assert len(rules) == 1

    def test_default_loads_core_signatures(self):
        loader = RuleLoader()
        rules = loader.load_rules()
        assert len(rules) >= 40


# ===========================================================================
# 3. SecurityRule – unknown category fallback
# ===========================================================================


class TestUnknownCategoryFallback:
    """Unknown categories from external packs should not crash the loader."""

    def test_unknown_category_falls_back_to_policy_violation(self, tmp_path):
        _write_yaml(tmp_path, "unknown.yaml", _RULE_UNKNOWN_CATEGORY)

        loader = RuleLoader(rules_file=tmp_path)
        rules = loader.load_rules()

        assert len(rules) == 1
        assert rules[0].id == "UNKNOWN_CAT_RULE"
        assert rules[0].category == ThreatCategory.POLICY_VIOLATION

    def test_known_category_not_affected(self):
        rule = SecurityRule(
            {
                "id": "TEST",
                "category": "obfuscation",
                "severity": "LOW",
                "patterns": ["x"],
                "description": "test",
            }
        )
        assert rule.category == ThreatCategory.OBFUSCATION

    def test_unknown_severity_falls_back_to_high(self, tmp_path):
        _write_yaml(
            tmp_path,
            "weird_sev.yaml",
            textwrap.dedent("""\
                - id: WEIRD_SEV_RULE
                  category: obfuscation
                  severity: SUSPICIOUS
                  patterns: ["something"]
                  description: "Rule with non-standard severity"
            """),
        )
        loader = RuleLoader(rules_file=tmp_path)
        rules = loader.load_rules()
        assert len(rules) == 1
        assert rules[0].id == "WEIRD_SEV_RULE"
        assert rules[0].severity == Severity.HIGH

    def test_known_severity_not_affected(self):
        rule = SecurityRule(
            {
                "id": "TEST",
                "category": "obfuscation",
                "severity": "MEDIUM",
                "patterns": ["x"],
                "description": "test",
            }
        )
        assert rule.severity == Severity.MEDIUM


# ===========================================================================
# 4. data helpers – list_available_packs / resolve_rule_packs
# ===========================================================================


class TestPackDiscovery:
    """Tests for pack discovery and resolution helpers."""

    def test_list_available_packs_excludes_core(self):
        packs = list_available_packs()
        assert "core" not in packs

    def test_list_available_packs_returns_strings(self):
        packs = list_available_packs()
        assert all(isinstance(p, str) for p in packs)

    def test_resolve_unknown_pack_raises(self):
        with pytest.raises(ValueError, match="Unknown rule pack"):
            resolve_rule_packs(["definitely_not_a_real_pack"])

    def test_resolve_returns_paths(self, tmp_path):
        fake_packs = tmp_path / "packs"
        fake_packs.mkdir()
        core = fake_packs / "core"
        core.mkdir()
        ext = fake_packs / "ext"
        ext.mkdir()
        sigs = ext / "signatures"
        sigs.mkdir()

        with patch("skill_scanner.data._PACKS_DIR", fake_packs):
            packs = list_available_packs()
            assert "ext" in packs

            dirs = resolve_rule_packs(["ext"])
            assert len(dirs) == 1
            assert dirs[0] == sigs

    def test_resolve_pack_without_signatures_raises(self, tmp_path):
        fake_packs = tmp_path / "packs"
        fake_packs.mkdir()
        core = fake_packs / "core"
        core.mkdir()
        ext = fake_packs / "nosigs"
        ext.mkdir()
        (ext / "pack.yaml").write_text("name: nosigs\n")

        with patch("skill_scanner.data._PACKS_DIR", fake_packs):
            packs = list_available_packs()
            assert "nosigs" in packs

            with pytest.raises(ValueError, match="no signatures/ directory"):
                resolve_rule_packs(["nosigs"])


# ===========================================================================
# 5. Analyzer factory – extra_rules_dirs forwarding
# ===========================================================================


class TestAnalyzerFactoryExtraRules:
    """Verify extra_rules_dirs is forwarded to StaticAnalyzer via the factory."""

    def test_extra_rules_dirs_forwarded_to_static(self, tmp_path):
        from skill_scanner.core.analyzer_factory import build_core_analyzers

        extra = tmp_path / "extra"
        extra.mkdir()
        _write_yaml(extra, "ext.yaml", _VALID_RULE_FLAT)

        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy, extra_rules_dirs=[extra])

        static = [a for a in analyzers if a.get_name() == "static_analyzer"]
        assert len(static) == 1
        assert hasattr(static[0], "rule_loader")
        assert extra in static[0].rule_loader.extra_rules_dirs

    def test_no_extra_rules_dirs_by_default(self):
        from skill_scanner.core.analyzer_factory import build_core_analyzers

        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy)

        static = [a for a in analyzers if a.get_name() == "static_analyzer"]
        assert len(static) == 1
        assert static[0].rule_loader.extra_rules_dirs == []

    def test_build_analyzers_forwards_extra_rules(self, tmp_path):
        from skill_scanner.core.analyzer_factory import build_analyzers

        extra = tmp_path / "extra"
        extra.mkdir()
        _write_yaml(extra, "ext.yaml", _VALID_RULE_FLAT)

        policy = ScanPolicy.default()
        analyzers = build_analyzers(policy, extra_rules_dirs=[extra])

        static = [a for a in analyzers if a.get_name() == "static_analyzer"]
        assert len(static) == 1
        assert extra in static[0].rule_loader.extra_rules_dirs


# ===========================================================================
# 6. CLI – --rule-packs flag
# ===========================================================================


class TestCLIRulePacks:
    """Verify the --rule-packs CLI argument is registered and functional."""

    def test_rule_packs_flag_registered_on_scan(self):
        from skill_scanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp/test", "--rule-packs", "atr"])
        assert args.rule_packs == ["atr"]

    def test_rule_packs_flag_accepts_multiple(self):
        from skill_scanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp/test", "--rule-packs", "atr", "extra"])
        assert args.rule_packs == ["atr", "extra"]

    def test_rule_packs_flag_registered_on_scan_all(self):
        from skill_scanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan-all", "/tmp/test", "--rule-packs", "atr"])
        assert args.rule_packs == ["atr"]

    def test_rule_packs_default_is_none(self):
        from skill_scanner.cli.cli import build_parser

        parser = build_parser()
        args = parser.parse_args(["scan", "/tmp/test"])
        assert args.rule_packs is None

    def test_rule_packs_list_handler(self, capsys):
        from skill_scanner.cli.cli import _handle_rule_packs_list

        args = argparse.Namespace(rule_packs=["list"])
        result = _handle_rule_packs_list(args)
        assert result is True
        captured = capsys.readouterr()
        assert "pack" in captured.out.lower()

    def test_rule_packs_list_handler_returns_false_when_not_list(self):
        from skill_scanner.cli.cli import _handle_rule_packs_list

        args = argparse.Namespace(rule_packs=["atr"])
        result = _handle_rule_packs_list(args)
        assert result is False

    def test_rule_packs_list_handler_returns_false_when_none(self):
        from skill_scanner.cli.cli import _handle_rule_packs_list

        args = argparse.Namespace(rule_packs=None)
        result = _handle_rule_packs_list(args)
        assert result is False
