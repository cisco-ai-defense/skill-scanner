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
Tests for CLI output formats.

Ensures all --format options produce valid, parseable output.
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
def test_skills_dir():
    """Path to test skills directory."""
    return Path(__file__).parent.parent / "evals" / "test_skills"


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
# JSON Format Tests
# =============================================================================
class TestJSONFormat:
    """Tests for --format json output."""

    def test_json_format_is_valid_json(self, safe_skill_dir):
        """Test that JSON format produces valid JSON."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json"])

        assert code == 0, f"CLI failed: {stderr}"

        # Must be valid JSON
        data = json.loads(stdout)
        assert isinstance(data, dict)

    def test_json_format_has_required_fields(self, safe_skill_dir):
        """Test that JSON output has all required fields."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "json"])
        assert code == 0

        data = json.loads(stdout)

        # Check required fields
        required_fields = [
            "skill_name",
            "is_safe",
            "max_severity",
            "findings_count",
            "findings",
            "scan_duration_seconds",
            "timestamp",
        ]
        for field in required_fields:
            assert field in data, f"Missing required field: {field}"

    def test_json_format_findings_structure(self, safe_skill_dir):
        """Test that findings array has correct structure."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "json"])
        assert code == 0

        data = json.loads(stdout)
        assert isinstance(data["findings"], list)

        # If there are findings, check their structure
        for finding in data["findings"]:
            assert "id" in finding
            assert "severity" in finding
            assert "title" in finding

    def test_json_format_no_extra_output(self, safe_skill_dir):
        """Test that JSON output has no extra text before/after JSON."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "json"])
        assert code == 0

        # Stdout should start with { and end with }
        stripped = stdout.strip()
        assert stripped.startswith("{"), f"JSON output has prefix: {stripped[:50]}"
        assert stripped.endswith("}"), f"JSON output has suffix: {stripped[-50:]}"

    def test_json_compact_format(self, safe_skill_dir):
        """Test that --compact produces single-line JSON."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--compact"])
        assert code == 0

        # Should be single line (no newlines except at the end)
        lines = stdout.strip().split("\n")
        assert len(lines) == 1, f"Compact JSON should be single line, got {len(lines)} lines"

        # Should still be valid JSON
        data = json.loads(stdout)
        assert "skill_name" in data

    def test_json_format_with_behavioral(self, safe_skill_dir):
        """Test JSON format with behavioral analyzer enabled."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--use-behavioral"])
        assert code == 0, f"CLI failed: {stderr}"

        # Status messages should be in stderr, not stdout
        data = json.loads(stdout)
        assert "skill_name" in data

        # Check stderr has status message
        assert "behavioral" in stderr.lower() or stderr == ""


# =============================================================================
# Markdown Format Tests
# =============================================================================
class TestMarkdownFormat:
    """Tests for --format markdown output."""

    def test_markdown_format_has_headers(self, safe_skill_dir):
        """Test that Markdown format has proper headers."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "markdown"])
        assert code == 0

        # Should have Markdown headers
        assert "#" in stdout

    def test_markdown_format_has_skill_info(self, safe_skill_dir):
        """Test that Markdown includes skill information."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "markdown"])
        assert code == 0

        # Should mention the skill name
        assert "simple-formatter" in stdout.lower() or "skill" in stdout.lower()

    def test_markdown_format_has_status(self, safe_skill_dir):
        """Test that Markdown shows safety status."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "markdown"])
        assert code == 0

        # Should show some form of status
        assert any(word in stdout.lower() for word in ["safe", "status", "severity", "finding", "result"])

    def test_markdown_detailed_format(self, safe_skill_dir):
        """Test --detailed flag with Markdown."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "markdown", "--detailed"])
        assert code == 0

        # Should have content
        assert len(stdout) > 50


# =============================================================================
# Table Format Tests
# =============================================================================
class TestTableFormat:
    """Tests for --format table output."""

    def test_table_format_has_structure(self, safe_skill_dir):
        """Test that table format has table-like structure."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "table"])
        assert code == 0

        # Should have some tabular indicators (pipes, dashes, or aligned columns)
        assert any(char in stdout for char in ["|", "-", "+", "─", "│"])

    def test_table_format_shows_skill_name(self, safe_skill_dir):
        """Test that table shows skill name."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "table"])
        assert code == 0

        assert "simple-formatter" in stdout or "Skill" in stdout

    def test_table_format_shows_status(self, safe_skill_dir):
        """Test that table shows status information."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "table"])
        assert code == 0

        # Should show some status indicator
        assert any(word in stdout.lower() for word in ["safe", "severity", "finding", "status", "result"])


# =============================================================================
# SARIF Format Tests
# =============================================================================
class TestSARIFFormat:
    """Tests for --format sarif output."""

    def test_sarif_format_is_valid_json(self, safe_skill_dir):
        """Test that SARIF format produces valid JSON."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "sarif"])
        assert code == 0, f"CLI failed: {stderr}"

        # Must be valid JSON
        data = json.loads(stdout)
        assert isinstance(data, dict)

    def test_sarif_format_has_schema(self, safe_skill_dir):
        """Test that SARIF output has required schema fields."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "sarif"])
        assert code == 0

        data = json.loads(stdout)

        # SARIF required fields
        assert "$schema" in data
        assert "version" in data
        assert "runs" in data

    def test_sarif_format_version(self, safe_skill_dir):
        """Test that SARIF version is 2.1.0."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "sarif"])
        assert code == 0

        data = json.loads(stdout)
        assert data["version"] == "2.1.0"

    def test_sarif_format_runs_structure(self, safe_skill_dir):
        """Test that SARIF runs array has correct structure."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "sarif"])
        assert code == 0

        data = json.loads(stdout)
        assert isinstance(data["runs"], list)
        assert len(data["runs"]) > 0

        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run

    def test_sarif_tool_info(self, safe_skill_dir):
        """Test that SARIF includes tool information."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "sarif"])
        assert code == 0

        data = json.loads(stdout)
        tool = data["runs"][0]["tool"]

        assert "driver" in tool
        assert "name" in tool["driver"]


# =============================================================================
# Summary Format Tests (Default)
# =============================================================================
class TestSummaryFormat:
    """Tests for --format summary (default) output."""

    def test_summary_format_is_human_readable(self, safe_skill_dir):
        """Test that summary format is human-readable text."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "summary"])
        assert code == 0

        # Should not be JSON
        try:
            json.loads(stdout)
            # If it parses as JSON, that's wrong for summary format
            pytest.fail("Summary format should not be JSON")
        except json.JSONDecodeError:
            pass  # Expected

    def test_summary_format_shows_skill_name(self, safe_skill_dir):
        """Test that summary shows skill name."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "summary"])
        assert code == 0

        assert "simple-formatter" in stdout or "Skill" in stdout

    def test_summary_format_shows_result(self, safe_skill_dir):
        """Test that summary shows scan result."""
        stdout, _, code = run_cli(["scan", str(safe_skill_dir), "--format", "summary"])
        assert code == 0

        # Should show some result indicator
        assert any(word in stdout.lower() for word in ["safe", "finding", "severity", "result", "scan"])

    def test_default_format_is_summary(self, safe_skill_dir):
        """Test that default format (no --format) is summary."""
        import re

        stdout_default, _, code1 = run_cli(["scan", str(safe_skill_dir)])
        stdout_summary, _, code2 = run_cli(["scan", str(safe_skill_dir), "--format", "summary"])

        assert code1 == 0
        assert code2 == 0

        # Normalize scan duration (varies between runs) before comparison
        duration_pattern = r"Scan Duration: \d+\.\d+s"
        normalized_default = re.sub(duration_pattern, "Scan Duration: X.XXs", stdout_default)
        normalized_summary = re.sub(duration_pattern, "Scan Duration: X.XXs", stdout_summary)

        # Should produce same output (ignoring timing differences)
        assert normalized_default == normalized_summary


# =============================================================================
# Multi-Skill Format Tests (scan-all)
# =============================================================================
class TestMultiSkillFormats:
    """Tests for format outputs with multiple skills (scan-all)."""

    def test_json_format_scan_all(self, test_skills_dir):
        """Test JSON format with scan-all command."""
        # Use the safe subdirectory which has skills at root level
        safe_dir = test_skills_dir / "safe"
        stdout, stderr, code = run_cli(["scan-all", str(safe_dir), "--format", "json"])
        assert code == 0, f"CLI failed: {stderr}"

        data = json.loads(stdout)

        # Should have multi-skill structure
        assert "skills" in data or "results" in data or "total_skills_scanned" in data

    def test_sarif_format_scan_all(self, test_skills_dir):
        """Test SARIF format with scan-all command."""
        # Use the safe subdirectory which has skills at root level
        safe_dir = test_skills_dir / "safe"
        stdout, stderr, code = run_cli(["scan-all", str(safe_dir), "--format", "sarif"])
        assert code == 0, f"CLI failed: {stderr}"

        data = json.loads(stdout)
        assert "$schema" in data
        assert "version" in data
        assert "runs" in data


# =============================================================================
# Error Handling Tests
# =============================================================================
class TestFormatErrorHandling:
    """Tests for format error handling."""

    def test_invalid_format_rejected(self, safe_skill_dir):
        """Test that invalid format is rejected."""
        _, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "invalid_format"])

        # Should fail with non-zero exit code
        assert code != 0
        assert "invalid" in stderr.lower() or "choice" in stderr.lower()

    def test_nonexistent_skill_error(self):
        """Test error handling for nonexistent skill."""
        stdout, stderr, code = run_cli(["scan", "/nonexistent/path", "--format", "json"])

        # Should fail
        assert code != 0
        assert "error" in stderr.lower() or "not" in stderr.lower()

    def test_json_format_error_in_stderr(self):
        """Test that errors go to stderr, not stdout, for JSON format."""
        stdout, stderr, code = run_cli(["scan", "/nonexistent/path", "--format", "json"])

        # Error messages should be in stderr
        assert len(stderr) > 0

        # stdout should be empty or valid JSON (even error response)
        if stdout.strip():
            try:
                json.loads(stdout)
            except json.JSONDecodeError:
                pytest.fail("JSON format stdout should be empty or valid JSON on error")


# =============================================================================
# Analyzer Status in JSON Tests
# =============================================================================
class TestAnalyzerStatusInJSON:
    """Tests ensuring analyzer status messages don't break JSON."""

    def test_behavioral_status_not_in_json(self, safe_skill_dir):
        """Test behavioral analyzer status goes to stderr."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--use-behavioral"])
        assert code == 0

        # JSON should be clean
        data = json.loads(stdout)
        assert "skill_name" in data

        # Status should be in stderr if present
        if "behavioral" in (stdout + stderr).lower():
            assert "behavioral" not in stdout.lower() or "analyzers_used" in stdout

    def test_trigger_status_not_in_json(self, safe_skill_dir):
        """Test trigger analyzer status goes to stderr."""
        stdout, stderr, code = run_cli(["scan", str(safe_skill_dir), "--format", "json", "--use-trigger"])
        assert code == 0

        # JSON should be clean
        data = json.loads(stdout)
        assert "skill_name" in data
