# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Tests for CLI custom rules and disable-rule functionality.

Tests the --custom-rules, --disable-rule, and --yara-mode CLI options.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def safe_skill_dir():
    """Path to a safe test skill."""
    return Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"


@pytest.fixture
def malicious_skill_dir():
    """Path to a malicious test skill."""
    return Path(__file__).parent.parent / "evals" / "skills" / "command-injection" / "eval-execution"


@pytest.fixture
def custom_rules_dir(tmp_path):
    """Create a temporary directory with custom YARA rules."""
    rules_dir = tmp_path / "custom_rules"
    rules_dir.mkdir()

    # Create a simple custom YARA rule
    custom_rule = rules_dir / "custom_test.yara"
    custom_rule.write_text("""
rule custom_test_pattern
{
    meta:
        description = "Test custom rule"
        severity = "LOW"
        category = "policy_violation"

    strings:
        $test = "custom_test_marker_xyz123"

    condition:
        $test
}
""")
    return rules_dir


def run_cli(args: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """
    Run the skill-scanner CLI and return stdout, stderr, return code.
    """
    cmd = [sys.executable, "-m", "skill_scanner.cli.cli"] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=Path(__file__).parent.parent,
    )
    return result.stdout, result.stderr, result.returncode


# =============================================================================
# YARA Mode Tests
# =============================================================================
class TestYaraMode:
    """Tests for --yara-mode option."""

    def test_default_mode_is_balanced(self, safe_skill_dir):
        """Test that default mode is balanced."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json"])
        assert code == 0, f"CLI failed: {stderr}"
        # Should succeed without specifying mode

    def test_strict_mode_accepted(self, safe_skill_dir):
        """Test that strict mode is accepted."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--yara-mode", "strict"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_balanced_mode_accepted(self, safe_skill_dir):
        """Test that balanced mode is accepted."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--yara-mode", "balanced"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_permissive_mode_accepted(self, safe_skill_dir):
        """Test that permissive mode is accepted."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--yara-mode", "permissive"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_invalid_mode_rejected(self, safe_skill_dir):
        """Test that invalid mode is rejected."""
        _, stderr, code = run_cli(["scan", str(safe_skill_dir), "--yara-mode", "invalid_mode"])
        assert code != 0
        assert "invalid" in stderr.lower() or "choice" in stderr.lower()


# =============================================================================
# Disable Rule Tests
# =============================================================================
class TestDisableRule:
    """Tests for --disable-rule option."""

    def test_disable_single_rule(self, malicious_skill_dir):
        """Test disabling a single rule."""
        # First scan without disabling
        stdout1, _, code1 = run_cli(["scan", str(malicious_skill_dir), "--format", "json"])
        assert code1 == 0
        data1 = json.loads(stdout1)
        findings1 = data1.get("findings", [])

        # Find a rule to disable
        if findings1:
            rule_to_disable = findings1[0].get("rule_id", "")
            if rule_to_disable:
                # Scan with rule disabled
                stdout2, _, code2 = run_cli(
                    ["scan", str(malicious_skill_dir), "--format", "json", "--disable-rule", rule_to_disable]
                )
                assert code2 == 0
                data2 = json.loads(stdout2)
                findings2 = data2.get("findings", [])

                # Should have fewer findings
                disabled_count = sum(1 for f in findings1 if f.get("rule_id") == rule_to_disable)
                assert len(findings2) == len(findings1) - disabled_count

    def test_disable_multiple_rules(self, malicious_skill_dir):
        """Test disabling multiple rules."""
        stdout, _, code = run_cli(
            [
                "scan",
                str(malicious_skill_dir),
                "--format",
                "json",
                "--disable-rule",
                "COMMAND_INJECTION_EVAL",
                "--disable-rule",
                "MANIFEST_MISSING_LICENSE",
            ]
        )
        assert code == 0
        data = json.loads(stdout)
        findings = data.get("findings", [])

        # Verify disabled rules are not in findings
        for finding in findings:
            assert finding.get("rule_id") != "COMMAND_INJECTION_EVAL"
            assert finding.get("rule_id") != "MANIFEST_MISSING_LICENSE"

    def test_disable_nonexistent_rule(self, safe_skill_dir):
        """Test that disabling nonexistent rule doesn't cause error."""
        stdout, stderr, code = run_cli(
            ["scan", str(safe_skill_dir), "--format", "json", "--disable-rule", "NONEXISTENT_RULE_XYZ"]
        )
        # Should succeed (nonexistent rule just has no effect)
        assert code == 0

    def test_disable_yara_rule(self, malicious_skill_dir):
        """Test disabling a YARA rule."""
        # Scan with YARA_script_injection disabled
        stdout, _, code = run_cli(
            ["scan", str(malicious_skill_dir), "--format", "json", "--disable-rule", "YARA_script_injection"]
        )
        assert code == 0
        data = json.loads(stdout)
        findings = data.get("findings", [])

        # Verify YARA rule is not in findings
        for finding in findings:
            assert finding.get("rule_id") != "YARA_script_injection"


# =============================================================================
# Custom Rules Tests
# =============================================================================
class TestCustomRules:
    """Tests for --custom-rules option."""

    def test_custom_rules_directory(self, safe_skill_dir, custom_rules_dir):
        """Test using custom rules from directory."""
        stdout, stderr, code = run_cli(
            ["scan", str(safe_skill_dir), "--format", "json", "--custom-rules", str(custom_rules_dir)]
        )
        # Should succeed with custom rules
        assert code == 0, f"CLI failed: {stderr}"

    def test_custom_rules_invalid_path(self, safe_skill_dir):
        """Test graceful handling for invalid custom rules path."""
        stdout, stderr, code = run_cli(
            ["scan", str(safe_skill_dir), "--format", "json", "--custom-rules", "/nonexistent/path/to/rules"]
        )
        # Should succeed but with warning in stderr (graceful degradation)
        assert code == 0
        # Warning about missing rules should be in stderr
        assert "not found" in stderr.lower() or "could not load" in stderr.lower()


# =============================================================================
# Scan-all Command Tests
# =============================================================================
class TestScanAllCustomOptions:
    """Tests for custom options with scan-all command."""

    def test_scan_all_with_yara_mode(self):
        """Test scan-all with --yara-mode."""
        test_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe"
        stdout, stderr, code = run_cli(["scan-all", str(test_dir), "--format", "json", "--yara-mode", "permissive"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_scan_all_with_disable_rule(self):
        """Test scan-all with --disable-rule."""
        test_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe"
        stdout, stderr, code = run_cli(
            ["scan-all", str(test_dir), "--format", "json", "--disable-rule", "MANIFEST_MISSING_LICENSE"]
        )
        assert code == 0, f"CLI failed: {stderr}"


# =============================================================================
# Integration Tests
# =============================================================================
class TestCustomRulesIntegration:
    """Integration tests combining multiple custom options."""

    def test_mode_and_disable_combined(self, malicious_skill_dir):
        """Test combining --yara-mode and --disable-rule."""
        stdout, stderr, code = run_cli(
            [
                "scan",
                str(malicious_skill_dir),
                "--format",
                "json",
                "--yara-mode",
                "strict",
                "--disable-rule",
                "MANIFEST_MISSING_LICENSE",
            ]
        )
        assert code == 0, f"CLI failed: {stderr}"
        data = json.loads(stdout)
        findings = data.get("findings", [])

        # Verify disabled rule not present
        for finding in findings:
            assert finding.get("rule_id") != "MANIFEST_MISSING_LICENSE"

    def test_all_options_combined(self, safe_skill_dir, custom_rules_dir):
        """Test combining all custom rule options."""
        stdout, stderr, code = run_cli(
            [
                "scan",
                str(safe_skill_dir),
                "--format",
                "json",
                "--yara-mode",
                "balanced",
                "--custom-rules",
                str(custom_rules_dir),
                "--disable-rule",
                "SOME_RULE",
            ]
        )
        assert code == 0, f"CLI failed: {stderr}"
