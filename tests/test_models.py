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
Unit tests for core data models.
"""

from datetime import datetime

import pytest

from skill_scanner.core.models import Finding, Report, ScanResult, Severity, ThreatCategory


class TestFindingModel:
    """Test Finding dataclass."""

    def test_finding_with_analyzer_field(self):
        """Test that Finding can be created with analyzer field."""
        finding = Finding(
            id="test_001",
            rule_id="TEST_RULE",
            category=ThreatCategory.COMMAND_INJECTION,
            severity=Severity.HIGH,
            title="Test Finding",
            description="A test finding",
            analyzer="static",
        )

        assert finding.analyzer == "static"

    def test_finding_analyzer_defaults_to_none(self):
        """Test that analyzer field defaults to None when not specified."""
        finding = Finding(
            id="test_002",
            rule_id="TEST_RULE",
            category=ThreatCategory.COMMAND_INJECTION,
            severity=Severity.HIGH,
            title="Test Finding",
            description="A test finding",
        )

        assert finding.analyzer is None

    def test_finding_to_dict_includes_analyzer(self):
        """Test that to_dict() includes analyzer field."""
        finding = Finding(
            id="test_003",
            rule_id="TEST_RULE",
            category=ThreatCategory.DATA_EXFILTRATION,
            severity=Severity.CRITICAL,
            title="Test Finding",
            description="A test finding",
            analyzer="behavioral",
        )

        finding_dict = finding.to_dict()

        assert "analyzer" in finding_dict
        assert finding_dict["analyzer"] == "behavioral"

    def test_finding_to_dict_analyzer_none_when_not_set(self):
        """Test that to_dict() returns None for analyzer when not set."""
        finding = Finding(
            id="test_004",
            rule_id="TEST_RULE",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=Severity.MEDIUM,
            title="Test Finding",
            description="A test finding",
        )

        finding_dict = finding.to_dict()

        assert "analyzer" in finding_dict
        assert finding_dict["analyzer"] is None

    @pytest.mark.parametrize(
        "analyzer_value",
        [
            "static",
            "llm",
            "behavioral",
            "aidefense",
            "virustotal",
            "cross_skill",
            "trigger",
        ],
    )
    def test_finding_accepts_all_analyzer_values(self, analyzer_value):
        """Test that Finding accepts all expected analyzer values."""
        finding = Finding(
            id=f"test_{analyzer_value}",
            rule_id="TEST_RULE",
            category=ThreatCategory.POLICY_VIOLATION,
            severity=Severity.LOW,
            title="Test Finding",
            description="A test finding",
            analyzer=analyzer_value,
        )

        assert finding.analyzer == analyzer_value

        finding_dict = finding.to_dict()
        assert finding_dict["analyzer"] == analyzer_value

    def test_finding_to_dict_contains_all_expected_keys(self):
        """Test that to_dict() output contains all expected keys including analyzer."""
        finding = Finding(
            id="test_keys",
            rule_id="TEST_RULE",
            category=ThreatCategory.MALWARE,
            severity=Severity.CRITICAL,
            title="Test Finding",
            description="A test finding",
            file_path="test.py",
            line_number=42,
            snippet="dangerous_code()",
            remediation="Fix the code",
            analyzer="static",
            metadata={"key": "value"},
        )

        finding_dict = finding.to_dict()

        expected_keys = {
            "id",
            "rule_id",
            "category",
            "severity",
            "title",
            "description",
            "file_path",
            "line_number",
            "snippet",
            "remediation",
            "analyzer",
            "metadata",
        }

        assert set(finding_dict.keys()) == expected_keys

    def test_finding_to_dict_json_serializable(self):
        """Test that to_dict() output is JSON serializable."""
        import json

        finding = Finding(
            id="test_json",
            rule_id="TEST_RULE",
            category=ThreatCategory.COMMAND_INJECTION,
            severity=Severity.HIGH,
            title="Test Finding",
            description="A test finding",
            analyzer="llm",
            metadata={"confidence": 0.95},
        )

        finding_dict = finding.to_dict()

        # Should not raise
        json_str = json.dumps(finding_dict)
        assert isinstance(json_str, str)

        # Round-trip should preserve analyzer
        parsed = json.loads(json_str)
        assert parsed["analyzer"] == "llm"


def _mk_finding(finding_id: str, severity: Severity, category: ThreatCategory) -> Finding:
    return Finding(
        id=finding_id,
        rule_id=f"RULE_{finding_id}",
        category=category,
        severity=severity,
        title=f"Finding {finding_id}",
        description=f"Description for {finding_id}",
        analyzer="static",
    )


class TestScanResultModel:
    """Behavioral tests for ScanResult aggregation methods."""

    def test_is_safe_false_when_high_or_critical_exists(self):
        result = ScanResult(
            skill_name="unsafe-skill",
            skill_directory="/tmp/unsafe-skill",
            findings=[
                _mk_finding("1", Severity.LOW, ThreatCategory.SOCIAL_ENGINEERING),
                _mk_finding("2", Severity.HIGH, ThreatCategory.COMMAND_INJECTION),
            ],
        )
        assert not result.is_safe

    def test_max_severity_uses_priority_order(self):
        result = ScanResult(
            skill_name="mixed-skill",
            skill_directory="/tmp/mixed-skill",
            findings=[
                _mk_finding("1", Severity.INFO, ThreatCategory.POLICY_VIOLATION),
                _mk_finding("2", Severity.MEDIUM, ThreatCategory.OBFUSCATION),
                _mk_finding("3", Severity.CRITICAL, ThreatCategory.MALWARE),
                _mk_finding("4", Severity.HIGH, ThreatCategory.DATA_EXFILTRATION),
            ],
        )
        assert result.max_severity == Severity.CRITICAL

    def test_to_dict_has_duration_ms_and_serialized_findings(self):
        result = ScanResult(
            skill_name="serialize-skill",
            skill_directory="/tmp/serialize-skill",
            findings=[_mk_finding("1", Severity.MEDIUM, ThreatCategory.RESOURCE_ABUSE)],
            scan_duration_seconds=2.789,
            analyzers_used=["static", "behavioral"],
            timestamp=datetime(2026, 1, 5, 9, 30, 0),
        )

        payload = result.to_dict()

        assert payload["skill_name"] == "serialize-skill"
        assert payload["is_safe"] is True
        assert payload["max_severity"] == "MEDIUM"
        assert payload["duration_ms"] == 2789
        assert payload["findings"][0]["analyzer"] == "static"
        assert payload["timestamp"] == "2026-01-05T09:30:00"

    def test_get_findings_by_category_filters_exactly(self):
        result = ScanResult(
            skill_name="category-skill",
            skill_directory="/tmp/category-skill",
            findings=[
                _mk_finding("1", Severity.MEDIUM, ThreatCategory.OBFUSCATION),
                _mk_finding("2", Severity.HIGH, ThreatCategory.COMMAND_INJECTION),
                _mk_finding("3", Severity.LOW, ThreatCategory.OBFUSCATION),
            ],
        )

        obfuscation_findings = result.get_findings_by_category(ThreatCategory.OBFUSCATION)
        assert [finding.id for finding in obfuscation_findings] == ["1", "3"]


class TestReportModel:
    """Behavioral tests for Report counter updates and serialization."""

    def test_add_scan_result_updates_all_counters(self):
        safe_result = ScanResult(
            skill_name="safe",
            skill_directory="/tmp/safe",
            findings=[],
        )
        unsafe_result = ScanResult(
            skill_name="unsafe",
            skill_directory="/tmp/unsafe",
            findings=[
                _mk_finding("1", Severity.CRITICAL, ThreatCategory.MALWARE),
                _mk_finding("2", Severity.HIGH, ThreatCategory.COMMAND_INJECTION),
                _mk_finding("3", Severity.LOW, ThreatCategory.SOCIAL_ENGINEERING),
            ],
        )

        report = Report(timestamp=datetime(2026, 1, 5, 10, 0, 0))
        report.add_scan_result(safe_result)
        report.add_scan_result(unsafe_result)

        assert report.total_skills_scanned == 2
        assert report.total_findings == 3
        assert report.safe_count == 1
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.medium_count == 0
        assert report.low_count == 1
        assert report.info_count == 0

    def test_report_to_dict_summary_matches_runtime_counts(self):
        result = ScanResult(
            skill_name="summary-skill",
            skill_directory="/tmp/summary-skill",
            findings=[_mk_finding("1", Severity.INFO, ThreatCategory.POLICY_VIOLATION)],
        )
        report = Report(timestamp=datetime(2026, 1, 5, 11, 0, 0))
        report.add_scan_result(result)

        payload = report.to_dict()
        summary = payload["summary"]

        assert summary["total_skills_scanned"] == 1
        assert summary["total_findings"] == 1
        assert summary["safe_skills"] == 1
        assert summary["findings_by_severity"] == {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 1,
        }
        assert summary["timestamp"] == "2026-01-05T11:00:00"
