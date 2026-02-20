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
Unit tests for scanner engine.
"""

from pathlib import Path

import pytest

from skill_scanner.core.models import Severity
from skill_scanner.core.scanner import SkillScanner, scan_skill


@pytest.fixture
def example_skills_dir():
    """Get path to example skills directory."""
    return Path(__file__).parent.parent / "evals" / "test_skills"


@pytest.fixture
def scanner():
    """Create a scanner instance."""
    return SkillScanner()


def test_scan_single_skill(scanner, example_skills_dir):
    """Test scanning a single skill."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    result = scanner.scan_skill(skill_dir)

    assert result.skill_name == "simple-formatter"
    assert result.scan_duration_seconds > 0
    assert len(result.analyzers_used) > 0
    assert "static_analyzer" in result.analyzers_used


def test_scan_result_is_safe_property(scanner, example_skills_dir):
    """Test the is_safe property of scan results."""
    # Safe skill should be safe
    safe_dir = example_skills_dir / "safe" / "simple-formatter"
    safe_result = scanner.scan_skill(safe_dir)
    assert safe_result.is_safe

    # Malicious skill should not be safe
    malicious_dir = example_skills_dir / "malicious" / "exfiltrator"
    malicious_result = scanner.scan_skill(malicious_dir)
    assert not malicious_result.is_safe


def test_scan_result_max_severity(scanner, example_skills_dir):
    """Test max_severity calculation."""
    malicious_dir = example_skills_dir / "malicious" / "exfiltrator"
    result = scanner.scan_skill(malicious_dir)

    # Should have at least HIGH or CRITICAL
    assert result.max_severity in [Severity.CRITICAL, Severity.HIGH]


def test_scan_directory(scanner, example_skills_dir):
    """Test scanning a directory of skills."""
    report = scanner.scan_directory(example_skills_dir, recursive=True)

    assert report.total_skills_scanned >= 2  # At least 2 test skills
    assert len(report.scan_results) >= 2

    # Should have at least one safe skill
    assert report.safe_count >= 1

    # Should have detected issues in malicious skills
    assert report.critical_count > 0 or report.high_count > 0


def test_scan_result_to_dict(scanner, example_skills_dir):
    """Test conversion of ScanResult to dictionary."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    result = scanner.scan_skill(skill_dir)

    result_dict = result.to_dict()

    assert "skill_name" in result_dict
    assert "is_safe" in result_dict
    assert "findings" in result_dict
    assert "max_severity" in result_dict
    assert isinstance(result_dict["findings"], list)


def test_report_to_dict(scanner, example_skills_dir):
    """Test conversion of Report to dictionary."""
    report = scanner.scan_directory(example_skills_dir)

    report_dict = report.to_dict()

    assert "summary" in report_dict
    assert "results" in report_dict
    assert "total_skills_scanned" in report_dict["summary"]
    assert isinstance(report_dict["results"], list)


def test_convenience_function(example_skills_dir):
    """Test the convenience scan_skill function."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    result = scan_skill(skill_dir)

    assert result.skill_name == "simple-formatter"
    assert result.scan_duration_seconds > 0


def test_scanner_list_analyzers(scanner):
    """Test listing available analyzers."""
    analyzers = scanner.list_analyzers()

    assert len(analyzers) > 0
    assert "static_analyzer" in analyzers


def test_findings_include_analyzer_field(scanner, example_skills_dir):
    """Test that all findings in scan results include the analyzer field."""
    malicious_dir = example_skills_dir / "malicious" / "exfiltrator"
    result = scanner.scan_skill(malicious_dir)

    # Should have findings
    assert len(result.findings) > 0

    for finding in result.findings:
        # Check that analyzer field is set
        assert finding.analyzer is not None, f"Finding {finding.id} has no analyzer field"
        assert isinstance(finding.analyzer, str), f"Finding {finding.id} analyzer should be a string"
        assert len(finding.analyzer) > 0, f"Finding {finding.id} has empty analyzer field"


def test_findings_to_dict_includes_analyzer_in_json(scanner, example_skills_dir):
    """Test that analyzer field appears in JSON output from scan results."""
    malicious_dir = example_skills_dir / "malicious" / "exfiltrator"
    result = scanner.scan_skill(malicious_dir)

    # Convert to dict (JSON-like structure)
    result_dict = result.to_dict()

    # Should have findings
    assert len(result_dict["findings"]) > 0

    for finding_dict in result_dict["findings"]:
        # Verify analyzer field is present in JSON output
        assert "analyzer" in finding_dict, (
            f"analyzer field missing from finding JSON: {finding_dict.get('id', 'unknown')}"
        )
        assert finding_dict["analyzer"] is not None, (
            f"analyzer field is None for finding: {finding_dict.get('id', 'unknown')}"
        )
        assert isinstance(finding_dict["analyzer"], str), (
            f"analyzer should be string in JSON for finding: {finding_dict.get('id', 'unknown')}"
        )


def test_static_analyzer_findings_labeled_correctly(scanner, example_skills_dir):
    """Test that static analyzer findings are labeled with analyzer='static'."""
    malicious_dir = example_skills_dir / "malicious" / "exfiltrator"
    result = scanner.scan_skill(malicious_dir)

    # Convert to dict
    result_dict = result.to_dict()

    # Find findings from static analyzer (they should exist since it's always enabled)
    static_findings = [f for f in result_dict["findings"] if f.get("analyzer") == "static"]

    # Should have some static analyzer findings
    assert len(static_findings) > 0, "Expected to find findings from static analyzer"

    # Verify all static findings have the correct analyzer value
    for finding in static_findings:
        assert finding["analyzer"] == "static"
