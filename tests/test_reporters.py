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

"""Tests for report generation semantics across all reporter formats."""

from __future__ import annotations

import json
from datetime import datetime

import pytest

from skill_scanner.core.models import Finding, Report, ScanResult, Severity, ThreatCategory
from skill_scanner.core.reporters.json_reporter import JSONReporter
from skill_scanner.core.reporters.markdown_reporter import MarkdownReporter
from skill_scanner.core.reporters.table_reporter import TableReporter


def _sample_findings() -> list[Finding]:
    long_title = "Command injection in deployment helper script executes untrusted input"
    long_path = "scripts/deeply/nested/path/deploy_helper_script_with_long_name.sh"
    return [
        Finding(
            id="FIND-001",
            rule_id="COMMAND_INJECTION_001",
            category=ThreatCategory.COMMAND_INJECTION,
            severity=Severity.CRITICAL,
            title=long_title,
            description="Unsanitized input flows into shell execution.",
            file_path=long_path,
            line_number=42,
            snippet="subprocess.run(user_input, shell=True)",
            remediation="Avoid shell=True and sanitize user-controlled inputs.",
            analyzer="static",
            metadata={"confidence": 0.97},
        ),
        Finding(
            id="FIND-002",
            rule_id="OBFUSCATION_001",
            category=ThreatCategory.OBFUSCATION,
            severity=Severity.HIGH,
            title="Encoded payload is decoded before runtime execution",
            description="Code decodes and executes a base64 payload.",
            file_path="scripts/decoder.py",
            line_number=11,
            snippet="```python\nexec(base64.b64decode(payload))\n```",
            remediation="Remove dynamic execution and decode paths.",
            analyzer="behavioral",
            metadata={"confidence": 0.91},
        ),
        Finding(
            id="FIND-003",
            rule_id="SOCIAL_ENGINEERING_001",
            category=ThreatCategory.SOCIAL_ENGINEERING,
            severity=Severity.LOW,
            title="Misleading skill description",
            description="Manifest description does not match behavior.",
            file_path="SKILL.md",
            analyzer="static",
            metadata={"confidence": 0.63},
        ),
    ]


@pytest.fixture
def scan_result() -> ScanResult:
    return ScanResult(
        skill_name="dangerous-helper",
        skill_directory="/tmp/dangerous-helper",
        findings=_sample_findings(),
        scan_duration_seconds=1.234,
        analyzers_used=["static", "behavioral"],
        timestamp=datetime(2026, 1, 2, 3, 4, 5),
    )


@pytest.fixture
def report(scan_result: ScanResult) -> Report:
    safe_result = ScanResult(
        skill_name="safe-helper",
        skill_directory="/tmp/safe-helper",
        findings=[],
        scan_duration_seconds=0.456,
        analyzers_used=["static"],
        timestamp=datetime(2026, 1, 2, 3, 5, 0),
    )

    aggregate = Report(timestamp=datetime(2026, 1, 2, 3, 6, 0))
    aggregate.add_scan_result(scan_result)
    aggregate.add_scan_result(safe_result)
    return aggregate


def test_json_reporter_pretty_and_compact_are_semantically_equal(scan_result: ScanResult):
    pretty_reporter = JSONReporter(pretty=True)
    compact_reporter = JSONReporter(pretty=False)

    pretty_json = pretty_reporter.generate_report(scan_result)
    compact_json = compact_reporter.generate_report(scan_result)

    pretty_payload = json.loads(pretty_json)
    compact_payload = json.loads(compact_json)

    assert pretty_payload == compact_payload
    assert pretty_payload["skill_name"] == "dangerous-helper"
    assert pretty_payload["findings_count"] == 3
    assert pretty_payload["max_severity"] == "CRITICAL"
    assert pretty_payload["duration_ms"] == 1234
    assert pretty_payload["findings"][0]["analyzer"] == "static"


def test_json_reporter_multi_skill_summary_is_correct(report: Report):
    output = JSONReporter(pretty=True).generate_report(report)
    payload = json.loads(output)

    summary = payload["summary"]
    assert summary["total_skills_scanned"] == 2
    assert summary["safe_skills"] == 1
    assert summary["total_findings"] == 3
    assert summary["findings_by_severity"] == {
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 1,
        "info": 0,
    }


def test_markdown_reporter_single_scan_has_grouping_and_location(scan_result: ScanResult):
    output = MarkdownReporter(detailed=True).generate_report(scan_result)

    assert "# Agent Skill Security Scan Report" in output
    assert "### CRITICAL Severity" in output
    assert "**Location:** scripts/deeply/nested/path/deploy_helper_script_with_long_name.sh:42" in output
    assert "**Remediation:** Avoid shell=True and sanitize user-controlled inputs." in output
    # One snippet is plain text (auto-fenced), one is pre-fenced (preserved)
    assert output.count("```") == 4


def test_markdown_reporter_multi_skill_contains_statuses_and_counts(report: Report):
    output = MarkdownReporter(detailed=False).generate_report(report)

    assert "- **Total Skills Scanned:** 2" in output
    assert "- **Safe Skills:** 1" in output
    assert "### [FAIL] dangerous-helper" in output
    assert "### [OK] safe-helper" in output


def test_table_reporter_single_scan_truncates_long_fields_and_shows_snippets(scan_result: ScanResult):
    output = TableReporter(format_style="plain", show_snippets=True).generate_report(scan_result)

    expected_title = "Command injection in deployment helper s..."
    expected_location = "scripts/deeply/nested/path/dep..."

    assert "Detailed Findings:" in output
    assert expected_title in output
    assert expected_location in output
    assert "CODE EVIDENCE" in output
    assert "subprocess.run(user_input, shell=True)" in output


def test_table_reporter_multi_skill_includes_overview_table(report: Report):
    output = TableReporter(format_style="simple").generate_report(report)

    assert "Skills Overview:" in output
    assert "dangerous-helper" in output
    assert "safe-helper" in output
    assert "[FAIL] ISSUES" in output
    assert "[OK] SAFE" in output


def test_save_report_writes_exact_generated_content(tmp_path, scan_result: ScanResult):
    outputs = [
        ("result.json", JSONReporter(pretty=True)),
        ("result.md", MarkdownReporter(detailed=True)),
        ("result.txt", TableReporter(format_style="simple")),
    ]

    for filename, reporter in outputs:
        target = tmp_path / filename
        expected = reporter.generate_report(scan_result)
        reporter.save_report(scan_result, str(target))
        assert target.read_text(encoding="utf-8") == expected
