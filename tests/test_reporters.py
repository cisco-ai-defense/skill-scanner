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
Unit tests for reporters.
"""

import json
from pathlib import Path

import pytest

from skill_scanner.core.reporters.json_reporter import JSONReporter
from skill_scanner.core.reporters.markdown_reporter import MarkdownReporter
from skill_scanner.core.reporters.table_reporter import TableReporter
from skill_scanner.core.scanner import SkillScanner, scan_skill


@pytest.fixture
def example_skills_dir():
    """Get path to example skills directory."""
    return Path(__file__).parent.parent / "evals" / "test_skills"


@pytest.fixture
def scan_result(example_skills_dir):
    """Get a scan result for testing."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    return scan_skill(skill_dir)


@pytest.fixture
def report(example_skills_dir):
    """Get a full report for testing."""
    scanner = SkillScanner()
    return scanner.scan_directory(example_skills_dir, recursive=True)


def test_json_reporter(scan_result):
    """Test JSON reporter."""
    reporter = JSONReporter(pretty=True)
    output = reporter.generate_report(scan_result)

    # Should be valid JSON
    data = json.loads(output)
    assert "skill_name" in data
    assert "findings" in data


def test_json_reporter_compact(scan_result):
    """Test compact JSON output."""
    reporter = JSONReporter(pretty=False)
    output = reporter.generate_report(scan_result)

    # Should not have extra whitespace
    assert "\n  " not in output

    # But should still be valid JSON
    data = json.loads(output)
    assert "skill_name" in data


def test_markdown_reporter(scan_result):
    """Test Markdown reporter."""
    reporter = MarkdownReporter(detailed=True)
    output = reporter.generate_report(scan_result)

    # Should have Markdown headers
    assert "#" in output
    assert "Skill:" in output or "skill" in output.lower()


def test_markdown_reporter_multi_skill(report):
    """Test Markdown reporter with multiple skills."""
    reporter = MarkdownReporter(detailed=False)
    output = reporter.generate_report(report)

    # Should have summary section
    assert "Summary" in output or "summary" in output.lower()
    assert str(report.total_skills_scanned) in output


def test_table_reporter(scan_result):
    """Test table reporter."""
    reporter = TableReporter(format_style="simple")
    output = reporter.generate_report(scan_result)

    # Should contain table elements
    assert "Skill" in output or "skill" in output.lower()


def test_table_reporter_multi_skill(report):
    """Test table reporter with multiple skills."""
    reporter = TableReporter(format_style="grid")
    output = reporter.generate_report(report)

    # Should show all scanned skills
    assert report.total_skills_scanned > 0
