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
Tests for CLI custom rules and --policy functionality.

Tests the --custom-rules and --policy CLI options.
"""

import json
import subprocess
import sys
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
    """Run the skill-scanner CLI and return stdout, stderr, return code."""
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
# Policy Preset Tests
# =============================================================================
class TestPolicyPresets:
    """Tests for --policy option."""

    def test_default_uses_balanced(self, safe_skill_dir):
        """Test that default (no --policy flag) works."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_strict_policy(self, safe_skill_dir):
        """Test that strict policy is accepted."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--policy", "strict"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_balanced_policy(self, safe_skill_dir):
        """Test that balanced policy is accepted."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--policy", "balanced"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_permissive_policy(self, safe_skill_dir):
        """Test that permissive policy is accepted."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--policy", "permissive"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_invalid_policy_exits_with_error(self, safe_skill_dir):
        """Test that invalid policy file path causes an error."""
        _, stderr, code = run_cli(["scan", str(safe_skill_dir), "--policy", "/nonexistent/policy.yaml"])
        assert code != 0
        assert "not found" in stderr.lower() or "error" in stderr.lower()

    def test_strict_may_produce_more_findings(self, malicious_skill_dir):
        """Test that strict policy may produce more findings than permissive."""
        if not malicious_skill_dir.exists():
            pytest.skip("Malicious test skill not found")

        stdout_s, _, code_s = run_cli(["scan", str(malicious_skill_dir), "--format", "json", "--policy", "strict"])
        stdout_p, _, code_p = run_cli(["scan", str(malicious_skill_dir), "--format", "json", "--policy", "permissive"])

        if code_s == 0 and code_p == 0:
            data_s = json.loads(stdout_s)
            data_p = json.loads(stdout_p)
            # Strict should find at least as many issues as permissive
            assert data_s.get("findings_count", 0) >= data_p.get("findings_count", 0)


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
        assert code == 0, f"CLI failed: {stderr}"

    def test_custom_rules_invalid_path(self, safe_skill_dir):
        """Test graceful handling for invalid custom rules path."""
        stdout, stderr, code = run_cli(
            ["scan", str(safe_skill_dir), "--format", "json", "--custom-rules", "/nonexistent/path/to/rules"]
        )
        # Should succeed with warning (graceful degradation)
        assert code == 0
        assert "not found" in stderr.lower() or "could not load" in stderr.lower()


# =============================================================================
# Scan-all Command Tests
# =============================================================================
class TestScanAllCustomOptions:
    """Tests for custom options with scan-all command."""

    def test_scan_all_with_policy(self):
        """Test scan-all with --policy."""
        test_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe"
        stdout, stderr, code = run_cli(["scan-all", str(test_dir), "--format", "json", "--policy", "permissive"])
        assert code == 0, f"CLI failed: {stderr}"

    def test_scan_all_with_custom_rules(self, custom_rules_dir):
        """Test scan-all with --custom-rules."""
        test_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe"
        stdout, stderr, code = run_cli(
            ["scan-all", str(test_dir), "--format", "json", "--custom-rules", str(custom_rules_dir)]
        )
        assert code == 0, f"CLI failed: {stderr}"


# =============================================================================
# Integration Tests
# =============================================================================
class TestCustomRulesIntegration:
    """Integration tests combining multiple custom options."""

    def test_policy_and_custom_rules_combined(self, safe_skill_dir, custom_rules_dir):
        """Test combining --policy and --custom-rules."""
        stdout, stderr, code = run_cli(
            [
                "scan",
                str(safe_skill_dir),
                "--format",
                "json",
                "--policy",
                "strict",
                "--custom-rules",
                str(custom_rules_dir),
            ]
        )
        assert code == 0, f"CLI failed: {stderr}"
