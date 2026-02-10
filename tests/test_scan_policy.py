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
