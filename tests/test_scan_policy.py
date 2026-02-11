# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ScanPolicy system."""

import textwrap
from pathlib import Path

import pytest

from skill_scanner.core.scan_policy import ScanPolicy


class TestScanPolicyDefaults:
    """Test that the default policy loads and contains expected values."""

    def test_default_policy_loads(self):
        policy = ScanPolicy.default()
        assert policy.policy_name == "default"
        assert policy.policy_version == "1.0"

    def test_default_has_benign_dotfiles(self):
        policy = ScanPolicy.default()
        assert ".gitignore" in policy.hidden_files.benign_dotfiles
        assert ".editorconfig" in policy.hidden_files.benign_dotfiles
        assert ".npmrc" in policy.hidden_files.benign_dotfiles

    def test_default_has_benign_dotdirs(self):
        policy = ScanPolicy.default()
        assert ".github" in policy.hidden_files.benign_dotdirs
        assert ".vscode" in policy.hidden_files.benign_dotdirs
        assert ".vitepress" in policy.hidden_files.benign_dotdirs

    def test_default_has_known_installers(self):
        policy = ScanPolicy.default()
        assert "sh.rustup.rs" in policy.pipeline.known_installer_domains
        assert "brew.sh" in policy.pipeline.known_installer_domains
        assert "get.docker.com" in policy.pipeline.known_installer_domains

    def test_default_has_benign_pipes(self):
        policy = ScanPolicy.default()
        assert len(policy.pipeline.benign_pipe_targets) > 0
        # Should compile without error
        compiled = policy._compiled_benign_pipes
        assert len(compiled) > 0

    def test_default_has_rule_scoping(self):
        policy = ScanPolicy.default()
        assert "coercive_injection_generic" in policy.rule_scoping.skillmd_and_scripts_only
        assert "code_execution_generic" in policy.rule_scoping.skip_in_docs
        assert "prompt_injection_unicode_steganography" in policy.rule_scoping.code_only

    def test_default_has_test_creds(self):
        policy = ScanPolicy.default()
        assert "sk_test_4eC39HqLyjWDarjtT1zdp7dc" in policy.credentials.known_test_values

    def test_default_has_placeholder_markers(self):
        policy = ScanPolicy.default()
        assert "example" in policy.credentials.placeholder_markers
        assert "<your" in policy.credentials.placeholder_markers

    def test_default_has_safe_cleanup_targets(self):
        policy = ScanPolicy.default()
        assert "dist" in policy.system_cleanup.safe_rm_targets
        assert "node_modules" in policy.system_cleanup.safe_rm_targets

    def test_default_has_no_disabled_rules(self):
        policy = ScanPolicy.default()
        assert len(policy.disabled_rules) == 0

    def test_default_has_no_severity_overrides(self):
        policy = ScanPolicy.default()
        assert len(policy.severity_overrides) == 0


class TestScanPolicyCustomisation:
    """Test org-specific policy overrides."""

    def test_override_replaces_lists(self, tmp_path):
        """An org that only considers .gitignore benign."""
        policy_file = tmp_path / "strict.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            policy_name: strict-corp
            hidden_files:
              benign_dotfiles:
                - ".gitignore"
              benign_dotdirs:
                - ".github"
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)
        assert policy.policy_name == "strict-corp"
        # Only the overridden values
        assert policy.hidden_files.benign_dotfiles == {".gitignore"}
        assert policy.hidden_files.benign_dotdirs == {".github"}
        # Other sections still have defaults
        assert "sh.rustup.rs" in policy.pipeline.known_installer_domains

    def test_add_custom_installer_domains(self, tmp_path):
        """An org that trusts their own internal installer."""
        policy_file = tmp_path / "custom.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            pipeline:
              known_installer_domains:
                - "install.internal.corp.com"
                - "sh.rustup.rs"
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)
        assert "install.internal.corp.com" in policy.pipeline.known_installer_domains
        assert "sh.rustup.rs" in policy.pipeline.known_installer_domains
        # Note: the override replaces the full list, so brew.sh is NOT here
        assert "brew.sh" not in policy.pipeline.known_installer_domains

    def test_disable_rules(self, tmp_path):
        """An org that disables noisy rules."""
        policy_file = tmp_path / "quiet.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            disabled_rules:
              - LAZY_LOAD_DEEP_NESTING
              - ARCHIVE_FILE_DETECTED
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)
        assert "LAZY_LOAD_DEEP_NESTING" in policy.disabled_rules
        assert "ARCHIVE_FILE_DETECTED" in policy.disabled_rules

    def test_severity_overrides(self, tmp_path):
        """An org that promotes BINARY_FILE_DETECTED back to MEDIUM."""
        policy_file = tmp_path / "strict.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            severity_overrides:
              - rule_id: BINARY_FILE_DETECTED
                severity: MEDIUM
                reason: "Our policy treats unknown binaries as medium risk"
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)
        assert policy.get_severity_override("BINARY_FILE_DETECTED") == "MEDIUM"
        assert policy.get_severity_override("NONEXISTENT") is None

    def test_empty_policy_gets_all_defaults(self, tmp_path):
        """An empty override file should result in all defaults."""
        policy_file = tmp_path / "empty.yaml"
        policy_file.write_text("# empty policy\n")
        policy = ScanPolicy.from_yaml(policy_file)
        default = ScanPolicy.default()
        assert policy.hidden_files.benign_dotfiles == default.hidden_files.benign_dotfiles
        assert policy.pipeline.known_installer_domains == default.pipeline.known_installer_domains


class TestScanPolicyRoundTrip:
    """Test dump and reload."""

    def test_to_yaml_roundtrip(self, tmp_path):
        """Dump and reload should produce identical policy."""
        original = ScanPolicy.default()
        out_path = tmp_path / "roundtrip.yaml"
        original.to_yaml(out_path)

        reloaded = ScanPolicy.from_yaml(out_path)
        assert reloaded.hidden_files.benign_dotfiles == original.hidden_files.benign_dotfiles
        assert reloaded.hidden_files.benign_dotdirs == original.hidden_files.benign_dotdirs
        assert reloaded.pipeline.known_installer_domains == original.pipeline.known_installer_domains
        assert reloaded.rule_scoping.skillmd_and_scripts_only == original.rule_scoping.skillmd_and_scripts_only
        assert reloaded.credentials.known_test_values == original.credentials.known_test_values

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            ScanPolicy.from_yaml("/nonexistent/policy.yaml")


class TestScanPolicyPresets:
    """Test that presets load and differ from each other."""

    def test_strict_preset_loads(self):
        policy = ScanPolicy.from_preset("strict")
        assert policy.policy_name == "strict"

    def test_balanced_preset_loads(self):
        policy = ScanPolicy.from_preset("balanced")
        assert policy.policy_name == "default"

    def test_permissive_preset_loads(self):
        policy = ScanPolicy.from_preset("permissive")
        assert policy.policy_name == "permissive"

    def test_unknown_preset_raises(self):
        with pytest.raises(ValueError, match="Unknown preset"):
            ScanPolicy.from_preset("nonexistent")

    def test_strict_has_fewer_benign_dotfiles(self):
        strict = ScanPolicy.from_preset("strict")
        balanced = ScanPolicy.from_preset("balanced")
        assert len(strict.hidden_files.benign_dotfiles) < len(balanced.hidden_files.benign_dotfiles)

    def test_strict_has_no_known_installers(self):
        strict = ScanPolicy.from_preset("strict")
        assert len(strict.pipeline.known_installer_domains) == 0

    def test_strict_has_no_test_creds(self):
        strict = ScanPolicy.from_preset("strict")
        assert len(strict.credentials.known_test_values) == 0
        assert len(strict.credentials.placeholder_markers) == 0

    def test_strict_has_severity_promotions(self):
        strict = ScanPolicy.from_preset("strict")
        assert strict.get_severity_override("BINARY_FILE_DETECTED") == "MEDIUM"

    def test_permissive_has_more_benign_dotfiles(self):
        permissive = ScanPolicy.from_preset("permissive")
        balanced = ScanPolicy.from_preset("balanced")
        assert len(permissive.hidden_files.benign_dotfiles) > len(balanced.hidden_files.benign_dotfiles)

    def test_permissive_has_more_installers(self):
        permissive = ScanPolicy.from_preset("permissive")
        balanced = ScanPolicy.from_preset("balanced")
        assert len(permissive.pipeline.known_installer_domains) > len(balanced.pipeline.known_installer_domains)

    def test_permissive_has_disabled_rules(self):
        permissive = ScanPolicy.from_preset("permissive")
        assert "LAZY_LOAD_DEEP_NESTING" in permissive.disabled_rules
        assert "capability_inflation_generic" not in permissive.rule_scoping.skillmd_and_scripts_only

    def test_permissive_has_severity_demotions(self):
        permissive = ScanPolicy.from_preset("permissive")
        assert permissive.get_severity_override("ARCHIVE_FILE_DETECTED") == "LOW"

    def test_preset_names_returns_all_three(self):
        names = ScanPolicy.preset_names()
        assert "strict" in names
        assert "balanced" in names
        assert "permissive" in names

    def test_strict_broadens_rule_scoping(self):
        strict = ScanPolicy.from_preset("strict")
        # In strict mode, coercive/autonomy fire on all files (not just SKILL.md+scripts)
        assert len(strict.rule_scoping.skillmd_and_scripts_only) == 0

    def test_permissive_narrows_rules_more(self):
        permissive = ScanPolicy.from_preset("permissive")
        balanced = ScanPolicy.from_preset("balanced")
        # Permissive skips more rules in docs
        assert len(permissive.rule_scoping.skip_in_docs) >= len(balanced.rule_scoping.skip_in_docs)
        # Permissive has more doc path indicators
        assert len(permissive.rule_scoping.doc_path_indicators) >= len(balanced.rule_scoping.doc_path_indicators)


class TestRuleProperties:
    """Test the extensible rule_properties system."""

    def test_default_policy_has_empty_rule_properties(self):
        policy = ScanPolicy.default()
        assert policy.rule_properties == {}

    def test_get_rule_property_returns_default_when_absent(self):
        policy = ScanPolicy.default()
        assert policy.get_rule_property("NONEXISTENT_RULE", "key", default=42) == 42

    def test_get_rule_property_returns_value_when_present(self):
        policy = ScanPolicy.default()
        policy.rule_properties["MY_RULE"] = {"threshold": 100, "enabled": True}
        assert policy.get_rule_property("MY_RULE", "threshold") == 100
        assert policy.get_rule_property("MY_RULE", "enabled") is True
        assert policy.get_rule_property("MY_RULE", "missing", default="fallback") == "fallback"

    def test_get_rule_property_int_coerces(self):
        policy = ScanPolicy.default()
        policy.rule_properties["MY_RULE"] = {"threshold": "200"}
        assert policy.get_rule_property_int("MY_RULE", "threshold", default=50) == 200

    def test_get_rule_property_int_falls_back_on_bad_value(self):
        policy = ScanPolicy.default()
        policy.rule_properties["MY_RULE"] = {"threshold": "not-a-number"}
        assert policy.get_rule_property_int("MY_RULE", "threshold", default=50) == 50

    def test_get_rule_property_bool_coerces(self):
        policy = ScanPolicy.default()
        policy.rule_properties["MY_RULE"] = {"flag": "true", "other": "false"}
        assert policy.get_rule_property_bool("MY_RULE", "flag", default=False) is True
        assert policy.get_rule_property_bool("MY_RULE", "other", default=True) is False

    def test_rule_properties_parsed_from_yaml(self, tmp_path):
        policy_file = tmp_path / "custom.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            rule_properties:
              EXCESSIVE_FILE_COUNT:
                max_file_count: 250
              PIPELINE_TAINT_FLOW:
                severity: LOW
                demote_instructional: false
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)
        assert policy.get_rule_property_int("EXCESSIVE_FILE_COUNT", "max_file_count", 100) == 250
        assert policy.get_rule_property("PIPELINE_TAINT_FLOW", "severity") == "LOW"
        assert policy.get_rule_property_bool("PIPELINE_TAINT_FLOW", "demote_instructional", True) is False

    def test_rule_properties_roundtrip(self, tmp_path):
        policy = ScanPolicy.default()
        policy.rule_properties = {
            "EXCESSIVE_FILE_COUNT": {"max_file_count": 500},
            "MY_CUSTOM_RULE": {"severity": "HIGH", "custom_flag": True},
        }
        out = tmp_path / "rt.yaml"
        policy.to_yaml(out)

        reloaded = ScanPolicy.from_yaml(out)
        assert reloaded.get_rule_property_int("EXCESSIVE_FILE_COUNT", "max_file_count", 100) == 500
        assert reloaded.get_rule_property("MY_CUSTOM_RULE", "severity") == "HIGH"
        assert reloaded.get_rule_property_bool("MY_CUSTOM_RULE", "custom_flag", False) is True

    def test_empty_rule_properties_in_yaml(self, tmp_path):
        """An empty rule_properties section should not break anything."""
        policy_file = tmp_path / "empty_rp.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            rule_properties: {}
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)
        assert policy.rule_properties == {}

    def test_invalid_rule_properties_entry_ignored(self, tmp_path):
        """Non-dict entries under rule_properties should be skipped."""
        policy_file = tmp_path / "bad_rp.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            rule_properties:
              VALID_RULE:
                severity: HIGH
              BAD_RULE: "just a string"
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)
        assert "VALID_RULE" in policy.rule_properties
        assert "BAD_RULE" not in policy.rule_properties

    def test_rule_properties_severity_applied_by_scanner(self, tmp_path):
        """rule_properties severity should be applied when no legacy override exists."""
        from skill_scanner.core.models import Finding, Severity, ThreatCategory

        policy = ScanPolicy.default()
        policy.rule_properties["SOME_RULE"] = {"severity": "LOW"}

        finding = Finding(
            id="test",
            rule_id="SOME_RULE",
            category=ThreatCategory.POLICY_VIOLATION,
            severity=Severity.HIGH,
            title="Test",
            description="Test finding",
            analyzer="test",
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner.__new__(SkillScanner)
        scanner.policy = policy
        scanner._apply_severity_overrides([finding])

        assert finding.severity == Severity.LOW

    def test_legacy_severity_overrides_take_precedence(self, tmp_path):
        """Legacy severity_overrides should win over rule_properties.severity."""
        from skill_scanner.core.models import Finding, Severity, ThreatCategory
        from skill_scanner.core.scan_policy import SeverityOverride

        policy = ScanPolicy.default()
        policy.severity_overrides = [SeverityOverride(rule_id="SOME_RULE", severity="CRITICAL")]
        policy.rule_properties["SOME_RULE"] = {"severity": "LOW"}

        finding = Finding(
            id="test",
            rule_id="SOME_RULE",
            category=ThreatCategory.POLICY_VIOLATION,
            severity=Severity.HIGH,
            title="Test",
            description="Test finding",
            analyzer="test",
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner.__new__(SkillScanner)
        scanner.policy = policy
        scanner._apply_severity_overrides([finding])

        assert finding.severity == Severity.CRITICAL


class TestRulePropertiesEditorParsing:
    """Test the TUI editor's text-to-props parsing."""

    def test_empty_text(self):
        from skill_scanner.cli.policy_tui import RulePropertiesEditorScreen

        assert RulePropertiesEditorScreen._text_to_props("") == {}
        assert RulePropertiesEditorScreen._text_to_props("   \n\n") == {}

    def test_single_rule(self):
        from skill_scanner.cli.policy_tui import RulePropertiesEditorScreen

        text = "MY_RULE:\n  severity: HIGH\n  threshold: 50\n"
        result = RulePropertiesEditorScreen._text_to_props(text)
        assert result == {"MY_RULE": {"severity": "HIGH", "threshold": 50}}

    def test_multiple_rules(self):
        from skill_scanner.cli.policy_tui import RulePropertiesEditorScreen

        text = "RULE_A:\n  key: value\n\nRULE_B:\n  flag: true\n"
        result = RulePropertiesEditorScreen._text_to_props(text)
        assert result == {"RULE_A": {"key": "value"}, "RULE_B": {"flag": True}}

    def test_bool_coercion(self):
        from skill_scanner.cli.policy_tui import RulePropertiesEditorScreen

        text = "R:\n  a: true\n  b: false\n  c: yes\n  d: no\n"
        result = RulePropertiesEditorScreen._text_to_props(text)
        assert result["R"]["a"] is True
        assert result["R"]["b"] is False
        assert result["R"]["c"] is True
        assert result["R"]["d"] is False

    def test_roundtrip_text(self):
        from skill_scanner.cli.policy_tui import RulePropertiesEditorScreen

        original = {"RULE_X": {"severity": "LOW", "threshold": 100}}
        text = RulePropertiesEditorScreen._props_to_text(original)
        parsed = RulePropertiesEditorScreen._text_to_props(text)
        assert parsed == original

    def test_invalid_line_raises(self):
        from skill_scanner.cli.policy_tui import RulePropertiesEditorScreen

        with pytest.raises(ValueError, match="unexpected content"):
            RulePropertiesEditorScreen._text_to_props("not a valid line")


class TestRulePropertiesAnalyzerIntegration:
    """Test that rule_properties are actually consumed by analyzers."""

    @staticmethod
    def _make_skill(tmp_path, name="test-skill", description="A comprehensive test skill for unit testing"):
        from skill_scanner.core.models import Skill, SkillFile, SkillManifest

        skill_dir = tmp_path / "skill"
        skill_dir.mkdir(exist_ok=True)
        skillmd = skill_dir / "SKILL.md"
        skillmd.write_text(f"---\nname: {name}\ndescription: {description}\n---\n# Test\n")
        files = [
            SkillFile(
                path=skillmd,
                relative_path="SKILL.md",
                file_type="markdown",
                content=skillmd.read_text(),
                size_bytes=skillmd.stat().st_size,
            ),
        ]
        return Skill(
            directory=skill_dir,
            manifest=SkillManifest(name=name, description=description),
            skill_md_path=skillmd,
            instruction_body="# Test\n",
            files=files,
        )

    def test_manifest_name_length_override(self, tmp_path):
        """rule_properties should override global max_name_length for MANIFEST_INVALID_NAME."""
        from skill_scanner.core.analyzers.static import StaticAnalyzer

        # A very long name that exceeds default 64 but fits in 200
        long_name = "a" * 100
        skill = self._make_skill(tmp_path, name=long_name)

        # Default policy: name > 64 → finding
        analyzer_default = StaticAnalyzer()
        findings_default = analyzer_default._check_manifest(skill)
        assert any(f.rule_id == "MANIFEST_INVALID_NAME" for f in findings_default)

        # Custom policy: raise limit to 200 → no finding from length
        policy = ScanPolicy.default()
        policy.rule_properties["MANIFEST_INVALID_NAME"] = {"max_name_length": 200}
        analyzer_custom = StaticAnalyzer(policy=policy)
        findings_custom = analyzer_custom._check_manifest(skill)
        # May still fire for pattern mismatch (uppercase not allowed), but length check passes
        length_findings = [f for f in findings_custom if "maximum length" in (f.description or "")]
        # The description should use the new threshold
        for f in findings_custom:
            if f.rule_id == "MANIFEST_INVALID_NAME" and "maximum length" in (f.description or ""):
                assert "200" in f.description

    def test_min_description_length_override(self, tmp_path):
        """rule_properties should override min_description_length for SOCIAL_ENG_VAGUE_DESCRIPTION."""
        from skill_scanner.core.analyzers.static import StaticAnalyzer

        short_desc = "Short"  # 5 chars, below default 20
        skill = self._make_skill(tmp_path, description=short_desc)

        # Default → finding (5 < 20)
        analyzer = StaticAnalyzer()
        findings = analyzer._check_manifest(skill)
        assert any(f.rule_id == "SOCIAL_ENG_VAGUE_DESCRIPTION" for f in findings)

        # Override to lower threshold → no finding
        policy = ScanPolicy.default()
        policy.rule_properties["SOCIAL_ENG_VAGUE_DESCRIPTION"] = {"min_description_length": 3}
        analyzer2 = StaticAnalyzer(policy=policy)
        findings2 = analyzer2._check_manifest(skill)
        assert not any(f.rule_id == "SOCIAL_ENG_VAGUE_DESCRIPTION" for f in findings2)

    def test_max_file_count_override(self, tmp_path):
        """rule_properties should override max_file_count for EXCESSIVE_FILE_COUNT."""
        from skill_scanner.core.analyzers.static import StaticAnalyzer
        from skill_scanner.core.models import SkillFile

        skill = self._make_skill(tmp_path)
        # Add lots of fake files
        for i in range(150):
            fake = tmp_path / "skill" / f"file_{i}.txt"
            fake.write_text("x")
            skill.files.append(
                SkillFile(path=fake, relative_path=f"file_{i}.txt", file_type="other", content="x", size_bytes=1)
            )

        # Default → fires (150 > 100)
        analyzer = StaticAnalyzer()
        findings = analyzer._check_file_inventory(skill)
        assert any(f.rule_id == "EXCESSIVE_FILE_COUNT" for f in findings)

        # Override to 200 → does not fire
        policy = ScanPolicy.default()
        policy.rule_properties["EXCESSIVE_FILE_COUNT"] = {"max_file_count": 200}
        analyzer2 = StaticAnalyzer(policy=policy)
        findings2 = analyzer2._check_file_inventory(skill)
        assert not any(f.rule_id == "EXCESSIVE_FILE_COUNT" for f in findings2)

    def test_bytecode_analyzer_accepts_policy(self):
        """BytecodeAnalyzer should accept and store a policy."""
        from skill_scanner.core.analyzers.bytecode_analyzer import BytecodeAnalyzer

        policy = ScanPolicy.default()
        policy.rule_properties["BYTECODE_NO_SOURCE"] = {"severity": "LOW"}
        analyzer = BytecodeAnalyzer(policy=policy)
        assert analyzer.policy is policy

    def test_bytecode_analyzer_default_policy(self):
        """BytecodeAnalyzer without explicit policy should use default."""
        from skill_scanner.core.analyzers.bytecode_analyzer import BytecodeAnalyzer

        analyzer = BytecodeAnalyzer()
        assert analyzer.policy is not None
        assert analyzer.policy.rule_properties == {}

    def test_comprehensive_rule_properties_from_yaml(self, tmp_path):
        """A single YAML file with many rule_properties should parse and round-trip."""
        policy_file = tmp_path / "full.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            rule_properties:
              MANIFEST_INVALID_NAME:
                max_name_length: 128
              MANIFEST_DESCRIPTION_TOO_LONG:
                max_description_length: 2048
              SOCIAL_ENG_VAGUE_DESCRIPTION:
                min_description_length: 5
              EXCESSIVE_FILE_COUNT:
                max_file_count: 500
              OVERSIZED_FILE:
                max_file_size_bytes: 10485760
              LAZY_LOAD_DEEP_NESTING:
                max_reference_depth: 10
              RESOURCE_ABUSE_INFINITE_LOOP:
                exception_handler_context_lines: 40
              YARA_prompt_injection_unicode_steganography:
                zerowidth_threshold_with_decode: 100
                zerowidth_threshold_alone: 500
                short_match_max_chars: 4
                cyrillic_cjk_min_chars: 20
              YARA_tool_chaining_abuse_generic:
                exfil_hints: send,upload,webhook
              PIPELINE_TAINT_FLOW:
                demote_instructional: false
                demote_in_docs: false
              BYTECODE_NO_SOURCE:
                severity: MEDIUM
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)

        # Verify all parsed correctly
        assert policy.get_rule_property_int("MANIFEST_INVALID_NAME", "max_name_length", 64) == 128
        assert policy.get_rule_property_int("MANIFEST_DESCRIPTION_TOO_LONG", "max_description_length", 1024) == 2048
        assert policy.get_rule_property_int("SOCIAL_ENG_VAGUE_DESCRIPTION", "min_description_length", 20) == 5
        assert policy.get_rule_property_int("EXCESSIVE_FILE_COUNT", "max_file_count", 100) == 500
        assert policy.get_rule_property_int("OVERSIZED_FILE", "max_file_size_bytes", 5242880) == 10485760
        assert policy.get_rule_property_int("LAZY_LOAD_DEEP_NESTING", "max_reference_depth", 5) == 10
        assert policy.get_rule_property_int("RESOURCE_ABUSE_INFINITE_LOOP", "exception_handler_context_lines", 20) == 40
        assert (
            policy.get_rule_property_int(
                "YARA_prompt_injection_unicode_steganography", "zerowidth_threshold_with_decode", 50
            )
            == 100
        )
        assert (
            policy.get_rule_property_int("YARA_prompt_injection_unicode_steganography", "short_match_max_chars", 2) == 4
        )
        assert (
            policy.get_rule_property_int("YARA_prompt_injection_unicode_steganography", "cyrillic_cjk_min_chars", 10)
            == 20
        )
        assert policy.get_rule_property("YARA_tool_chaining_abuse_generic", "exfil_hints") == "send,upload,webhook"
        assert policy.get_rule_property_bool("PIPELINE_TAINT_FLOW", "demote_instructional", True) is False
        assert policy.get_rule_property_bool("PIPELINE_TAINT_FLOW", "demote_in_docs", True) is False
        assert policy.get_rule_property("BYTECODE_NO_SOURCE", "severity") == "MEDIUM"

        # Round-trip
        out = tmp_path / "rt.yaml"
        policy.to_yaml(out)
        reloaded = ScanPolicy.from_yaml(out)
        assert len(reloaded.rule_properties) == len(policy.rule_properties)
        assert reloaded.get_rule_property_int("EXCESSIVE_FILE_COUNT", "max_file_count", 100) == 500


class TestScanPolicyIntegration:
    """Test that the policy is actually used by analyzers."""

    def test_static_analyzer_uses_policy_dotfiles(self, tmp_path):
        """A custom policy with no benign dotfiles should flag .gitignore."""
        from skill_scanner.core.analyzers.static import StaticAnalyzer
        from skill_scanner.core.models import Skill, SkillFile, SkillManifest

        # Create policy with empty benign lists
        policy_file = tmp_path / "strict.yaml"
        policy_file.write_text(
            textwrap.dedent("""\
            hidden_files:
              benign_dotfiles: []
              benign_dotdirs: []
        """)
        )
        policy = ScanPolicy.from_yaml(policy_file)

        # Create a skill with a .gitignore
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()
        skillmd = skill_dir / "SKILL.md"
        skillmd.write_text("---\nname: test-skill\ndescription: Test\n---\n# Test\n")
        gitignore = skill_dir / ".gitignore"
        gitignore.write_text("node_modules/\n")

        files = [
            SkillFile(
                path=gitignore,
                relative_path=".gitignore",
                file_type="other",
                content="node_modules/\n",
                size_bytes=14,
            ),
        ]

        skill = Skill(
            directory=skill_dir,
            manifest=SkillManifest(name="test-skill", description="Test"),
            skill_md_path=skillmd,
            instruction_body="# Test\n",
            files=files,
        )

        # With strict policy, .gitignore should be flagged
        analyzer = StaticAnalyzer(policy=policy)
        findings = analyzer._check_hidden_files(skill)
        hidden_findings = [f for f in findings if f.rule_id == "HIDDEN_DATA_FILE"]
        assert len(hidden_findings) >= 1, "Strict policy should flag .gitignore"

        # With default policy, .gitignore should NOT be flagged
        default_analyzer = StaticAnalyzer()
        default_findings = default_analyzer._check_hidden_files(skill)
        default_hidden = [f for f in default_findings if f.rule_id == "HIDDEN_DATA_FILE"]
        assert len(default_hidden) == 0, "Default policy should not flag .gitignore"
