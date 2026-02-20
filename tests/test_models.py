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

import pytest

from skill_scanner.core.models import Finding, Severity, ThreatCategory


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
