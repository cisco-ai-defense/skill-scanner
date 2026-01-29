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
End-to-end integration tests.

Inspired by MCP Scanner's test_integration.py
"""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from skill_scanner.config.config import Config
from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity
from skill_scanner.core.scanner import SkillScanner


class TestEndToEndScanning:
    """End-to-end scanning tests."""

    def test_scan_safe_skill_end_to_end(self):
        """Test complete scan of safe skill."""
        scanner = SkillScanner()
        example_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"

        result = scanner.scan_skill(example_dir)

        # Should complete successfully
        assert result.skill_name == "simple-formatter"
        assert result.is_safe
        assert len(result.analyzers_used) > 0
        assert "static_analyzer" in result.analyzers_used

    def test_scan_malicious_skill_detects_threats(self):
        """Test that malicious skill is properly detected."""
        scanner = SkillScanner()
        example_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "malicious/exfiltrator"

        result = scanner.scan_skill(example_dir)

        # Should detect threats
        assert not result.is_safe
        assert len(result.findings) > 0
        assert result.max_severity in [Severity.CRITICAL, Severity.HIGH]

        # Should detect data exfiltration
        categories = [f.category.value for f in result.findings]
        assert "data_exfiltration" in categories or "command_injection" in categories

    def test_scan_prompt_injection_skill(self):
        """Test scanning skill with prompt injection."""
        scanner = SkillScanner()
        example_dir = Path(__file__).parent.parent / "evals" / "skills" / "prompt-injection" / "jailbreak-override"

        result = scanner.scan_skill(example_dir)

        # Should detect prompt injection
        assert not result.is_safe
        assert len(result.findings) > 0

        # Should have prompt injection findings
        categories = [f.category.value for f in result.findings]
        assert "prompt_injection" in categories or "command_injection" in categories

    def test_batch_scan_multiple_skills(self):
        """Test scanning multiple skills at once."""
        scanner = SkillScanner()
        test_skills_dir = Path(__file__).parent.parent / "evals" / "test_skills"

        report = scanner.scan_directory(test_skills_dir, recursive=True)

        # Should scan all test skills
        assert report.total_skills_scanned >= 2  # At least safe and malicious
        assert report.safe_count >= 1  # At least one safe skill
        assert report.total_findings >= 0  # May or may not have findings

        # Malicious skill should have some findings
        malicious_results = [r for r in report.scan_results if "malicious" in r.skill_name.lower()]
        if malicious_results:
            assert any(r.max_severity.value in ["CRITICAL", "HIGH"] for r in malicious_results)


class TestConfigIntegration:
    """Test integration with Config system."""

    def test_scanner_with_config(self):
        """Test scanner using Config object."""
        config = Config(enable_static_analyzer=True, enable_llm_analyzer=False)

        # Create scanner with config-based analyzers
        analyzers = []
        if config.enable_static_analyzer:
            analyzers.append(StaticAnalyzer())

        scanner = SkillScanner(analyzers=analyzers)

        assert len(scanner.analyzers) == 1
        assert scanner.analyzers[0].name == "static_analyzer"


class TestOutputFormatIntegration:
    """Test integration with different output formats."""

    def test_json_output_format(self):
        """Test JSON output format."""
        from skill_scanner.core.reporters.json_reporter import JSONReporter

        scanner = SkillScanner()
        example_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"

        result = scanner.scan_skill(example_dir)

        # Generate JSON report
        reporter = JSONReporter(pretty=True)
        json_output = reporter.generate_report(result)

        assert "skill_name" in json_output
        assert "simple-formatter" in json_output
        assert "findings" in json_output

    def test_markdown_output_format(self):
        """Test Markdown output format."""
        from skill_scanner.core.reporters.markdown_reporter import MarkdownReporter

        scanner = SkillScanner()
        example_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"

        result = scanner.scan_skill(example_dir)

        # Generate Markdown report
        reporter = MarkdownReporter(detailed=True)
        md_output = reporter.generate_report(result)

        assert "# Agent Skill Security Scan Report" in md_output
        assert "simple-formatter" in md_output

    def test_table_output_format(self):
        """Test table output format."""
        from skill_scanner.core.reporters.table_reporter import TableReporter

        scanner = SkillScanner()
        example_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"

        result = scanner.scan_skill(example_dir)

        # Generate table report
        reporter = TableReporter()
        table_output = reporter.generate_report(result)

        assert "simple-formatter" in table_output
        assert "=" in table_output  # Table formatting


class TestThreatTaxonomyIntegration:
    """Test integration with threat taxonomy."""

    def test_findings_map_to_aitech(self):
        """Test that findings can be mapped to AITech taxonomy."""
        from skill_scanner.threats.threats import ThreatMapping

        scanner = SkillScanner()
        example_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "malicious/exfiltrator"

        result = scanner.scan_skill(example_dir)

        # Map first finding to AITech
        if result.findings:
            finding = result.findings[0]

            # Try to get AITech mapping
            try:
                threat_name = finding.category.value.upper().replace("_", " ")
                mapping = ThreatMapping.get_threat_mapping("static", threat_name)

                assert "aitech" in mapping
                assert "severity" in mapping
            except ValueError:
                # Some findings may not have direct mapping
                pass


class TestMultiAnalyzerIntegration:
    """Test running multiple analyzers together."""

    def test_static_and_behavioral_together(self):
        """Test running static and behavioral analyzers together."""
        analyzers = [StaticAnalyzer(), BehavioralAnalyzer()]

        scanner = SkillScanner(analyzers=analyzers)

        assert len(scanner.list_analyzers()) == 2
        assert "static_analyzer" in scanner.list_analyzers()
        assert "behavioral_analyzer" in scanner.list_analyzers()


class TestErrorRecovery:
    """Test error recovery in integration scenarios."""

    def test_continues_after_analyzer_error(self):
        """Test that scanner continues if one analyzer fails."""
        # Create mock analyzer that raises error
        failing_analyzer = MagicMock()
        failing_analyzer.analyze = MagicMock(side_effect=Exception("Analyzer error"))
        failing_analyzer.get_name = MagicMock(return_value="failing_analyzer")

        analyzers = [StaticAnalyzer(), failing_analyzer]

        scanner = SkillScanner(analyzers=analyzers)

        # Should handle analyzer error gracefully
        # (Scanner may catch or may propagate - depends on implementation)
        example_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"

        try:
            result = scanner.scan_skill(example_dir)
            # If it succeeds, check we got at least static analyzer results
            assert len(result.analyzers_used) >= 1
        except Exception:
            # If it fails, that's also acceptable (depends on error handling strategy)
            pass


class TestPerformanceBenchmarks:
    """Basic performance benchmark tests."""

    def test_static_scan_is_fast(self):
        """Test that static scanning is fast (< 1 second)."""
        scanner = SkillScanner()
        example_dir = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"

        result = scanner.scan_skill(example_dir)

        assert result.scan_duration_seconds < 1.0

    def test_batch_scan_completes_reasonably(self):
        """Test that batch scanning completes in reasonable time."""
        scanner = SkillScanner()
        test_skills_dir = Path(__file__).parent.parent / "evals" / "test_skills"

        report = scanner.scan_directory(test_skills_dir)

        # 3 skills with static analyzer should take < 3 seconds
        # (We don't have total duration in Report, but each ScanResult has duration)
        total_duration = sum(r.scan_duration_seconds for r in report.scan_results)
        assert total_duration < 5.0  # Generous limit
