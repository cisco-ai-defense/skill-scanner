# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Integration tests for StaticAnalyzer + ScanPolicy.

Covers:
- YARA mode derivation from policy.preset_base
- Binary scan + file classification integration
- Disabled-rules merging (CLI + YARA mode + policy)
"""

from pathlib import Path

import pytest

from skill_scanner.config.yara_modes import YaraMode, YaraModeConfig
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, Skill, SkillFile, SkillManifest
from skill_scanner.core.scan_policy import ScanPolicy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_skill(skill_dir: Path, files: list[SkillFile]) -> Skill:
    """Create a minimal Skill object."""
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        skill_md.write_text("---\nname: test-skill\ndescription: Test skill\n---\n\n# Test\nDoes things.\n")
    return Skill(
        directory=skill_dir,
        manifest=SkillManifest(name="test-skill", description="Test skill"),
        skill_md_path=skill_md,
        instruction_body="# Test\nDoes things.",
        files=files,
    )


def _sf(path: Path, rel: str, ftype: str = "other") -> SkillFile:
    return SkillFile(
        path=path,
        relative_path=rel,
        file_type=ftype,
        size_bytes=path.stat().st_size if path.exists() else 0,
    )


# ===================================================================
# YARA mode derivation from policy.preset_base
# ===================================================================


class TestYaraModeDerivation:
    """Verify that StaticAnalyzer derives the YARA mode from the policy's
    ``preset_base`` field when no explicit ``yara_mode`` is passed."""

    def test_strict_policy_yields_strict_yara(self):
        policy = ScanPolicy.from_preset("strict")
        analyzer = StaticAnalyzer(policy=policy)
        assert analyzer.yara_mode.mode == YaraMode.STRICT

    def test_balanced_policy_yields_balanced_yara(self):
        policy = ScanPolicy.from_preset("balanced")
        analyzer = StaticAnalyzer(policy=policy)
        assert analyzer.yara_mode.mode == YaraMode.BALANCED

    def test_permissive_policy_yields_permissive_yara(self):
        policy = ScanPolicy.from_preset("permissive")
        analyzer = StaticAnalyzer(policy=policy)
        assert analyzer.yara_mode.mode == YaraMode.PERMISSIVE

    def test_custom_name_preserves_preset_base_yara_mode(self):
        """Renaming ``policy_name`` should NOT change the YARA mode.

        The mode is derived from ``preset_base``, which is stable.
        """
        policy = ScanPolicy.from_preset("strict")
        policy.policy_name = "acme-corp-strict"
        assert policy.preset_base == "strict"  # stable

        analyzer = StaticAnalyzer(policy=policy)
        assert analyzer.yara_mode.mode == YaraMode.STRICT

    def test_explicit_yara_mode_overrides_policy_preset(self):
        """Passing an explicit yara_mode should override the policy derivation."""
        policy = ScanPolicy.from_preset("strict")
        analyzer = StaticAnalyzer(
            policy=policy,
            yara_mode="permissive",
        )
        assert analyzer.yara_mode.mode == YaraMode.PERMISSIVE

    def test_explicit_yara_mode_config_overrides_policy_preset(self):
        """Passing a YaraModeConfig instance should override the policy derivation."""
        policy = ScanPolicy.from_preset("permissive")
        mode_cfg = YaraModeConfig.strict()
        analyzer = StaticAnalyzer(
            policy=policy,
            yara_mode=mode_cfg,
        )
        assert analyzer.yara_mode.mode == YaraMode.STRICT


# ===================================================================
# Disabled rules merging
# ===================================================================


class TestDisabledRulesMerging:
    """Verify disabled_rules from CLI, YARA mode, and policy are all merged."""

    def test_policy_disabled_rules_merged(self):
        """Rules disabled in the policy should appear in analyzer.disabled_rules."""
        policy = ScanPolicy.default()
        policy.disabled_rules = {"MY_CUSTOM_RULE", "ANOTHER_RULE"}
        analyzer = StaticAnalyzer(policy=policy)

        assert "MY_CUSTOM_RULE" in analyzer.disabled_rules
        assert "ANOTHER_RULE" in analyzer.disabled_rules

    def test_cli_disabled_rules_merged(self):
        """Rules disabled via the constructor parameter should appear too."""
        policy = ScanPolicy.default()
        analyzer = StaticAnalyzer(
            policy=policy,
            disabled_rules={"CLI_DISABLED"},
        )
        assert "CLI_DISABLED" in analyzer.disabled_rules

    def test_all_sources_merged(self):
        """CLI + policy + YARA mode disabled rules should all be present."""
        policy = ScanPolicy.default()
        policy.disabled_rules = {"POLICY_RULE"}
        analyzer = StaticAnalyzer(
            policy=policy,
            disabled_rules={"CLI_RULE"},
        )
        # Both sources should be merged
        assert "POLICY_RULE" in analyzer.disabled_rules
        assert "CLI_RULE" in analyzer.disabled_rules
        # YARA mode may add its own (depends on mode); just check no crash
        assert isinstance(analyzer.disabled_rules, set)


# ===================================================================
# Binary scan + file classification
# ===================================================================


class TestFileClassificationIntegration:
    """Verify that the StaticAnalyzer respects file_classification from the policy
    when determining what to flag as binary/archive/inert."""

    def test_inert_extension_not_flagged_as_binary(self, tmp_path):
        """Files with inert extensions (e.g. .png) should not produce
        BINARY_FILE_DETECTED findings."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        png = skill_dir / "logo.png"
        png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

        skill = _make_skill(skill_dir, [_sf(png, "logo.png", "binary")])

        policy = ScanPolicy.default()
        assert ".png" in policy.file_classification.inert_extensions

        analyzer = StaticAnalyzer(policy=policy)
        findings = analyzer.analyze(skill)

        binary_findings = [f for f in findings if f.rule_id == "BINARY_FILE_DETECTED"]
        assert len(binary_findings) == 0

    def test_archive_extension_flagged(self, tmp_path):
        """Files with archive extensions (e.g. .zip) should produce
        ARCHIVE_FILE_DETECTED findings."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        zipfile = skill_dir / "payload.zip"
        # Write minimal valid ZIP file header
        zipfile.write_bytes(b"PK\x05\x06" + b"\x00" * 18)

        skill = _make_skill(skill_dir, [_sf(zipfile, "payload.zip", "binary")])

        policy = ScanPolicy.default()
        assert ".zip" in policy.file_classification.archive_extensions

        analyzer = StaticAnalyzer(policy=policy)
        findings = analyzer.analyze(skill)

        archive_findings = [f for f in findings if f.rule_id == "ARCHIVE_FILE_DETECTED"]
        assert len(archive_findings) >= 1

    def test_unknown_binary_flagged(self, tmp_path):
        """A binary file with an unrecognised extension should trigger
        BINARY_FILE_DETECTED."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        blob = skill_dir / "mystery.dat"
        blob.write_bytes(b"\x00\x01\x02\x03" * 100)

        skill = _make_skill(skill_dir, [_sf(blob, "mystery.dat", "binary")])

        policy = ScanPolicy.default()
        analyzer = StaticAnalyzer(policy=policy)
        findings = analyzer.analyze(skill)

        binary_findings = [f for f in findings if f.rule_id == "BINARY_FILE_DETECTED"]
        assert len(binary_findings) >= 1


class TestStaticAnalyzerPolicyStorage:
    """Basic sanity: the analyzer stores and uses its policy."""

    def test_stores_policy(self):
        policy = ScanPolicy.from_preset("strict")
        analyzer = StaticAnalyzer(policy=policy)
        assert analyzer.policy is policy

    def test_default_policy_when_none(self):
        analyzer = StaticAnalyzer()
        assert analyzer.policy is not None
        assert analyzer.policy.policy_name is not None
