# Copyright 2026 Cisco Systems, Inc.
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
Tests for the Meta Analyzer.

Tests cover:
- MetaAnalysisResult dataclass
- MetaAnalyzer initialization with separate LLM keys
- Finding validation and enrichment
- False positive filtering
- Missed threat detection
- Integration with reporters (JSON, SARIF, Markdown)
"""

import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from skill_scanner.core.models import Finding, Severity, Skill, SkillFile, SkillManifest, ThreatCategory


# Test MetaAnalysisResult
class TestMetaAnalysisResult:
    """Tests for MetaAnalysisResult dataclass."""

    def test_empty_result(self):
        """Test empty MetaAnalysisResult."""
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalysisResult

        result = MetaAnalysisResult()

        assert result.validated_findings == []
        assert result.false_positives == []
        assert result.missed_threats == []
        assert result.priority_order == []
        assert result.correlations == []
        assert result.recommendations == []
        assert result.overall_risk_assessment == {}

    def test_to_dict(self):
        """Test MetaAnalysisResult.to_dict() method."""
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalysisResult

        result = MetaAnalysisResult(
            validated_findings=[{"id": "1", "severity": "HIGH"}],
            false_positives=[{"id": "2", "reason": "false positive"}],
            missed_threats=[{"title": "new threat"}],
            overall_risk_assessment={"risk_level": "HIGH", "summary": "Test"},
        )

        result_dict = result.to_dict()

        assert result_dict["validated_findings"] == [{"id": "1", "severity": "HIGH"}]
        assert result_dict["false_positives"] == [{"id": "2", "reason": "false positive"}]
        assert result_dict["missed_threats"] == [{"title": "new threat"}]
        assert result_dict["summary"]["validated_count"] == 1
        assert result_dict["summary"]["false_positive_count"] == 1
        assert result_dict["summary"]["missed_threats_count"] == 1

    def test_get_validated_findings(self):
        """Test converting validated findings to Finding objects."""
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalysisResult

        # Create a mock skill
        skill = MagicMock(spec=Skill)
        skill.name = "test-skill"

        result = MetaAnalysisResult(
            validated_findings=[
                {
                    "id": "test_1",
                    "rule_id": "TEST_RULE",
                    "category": "prompt_injection",
                    "severity": "HIGH",
                    "title": "Test Finding",
                    "description": "Test description",
                    "confidence": "HIGH",
                    "confidence_reason": "Multiple signals",
                }
            ]
        )

        findings = result.get_validated_findings(skill)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == ThreatCategory.PROMPT_INJECTION
        assert findings[0].title == "Test Finding"
        assert findings[0].metadata.get("meta_validated") is True
        assert findings[0].metadata.get("meta_confidence") == "HIGH"

    def test_get_missed_threats(self):
        """Test converting missed threats to Finding objects."""
        from skill_scanner.core.analyzers.meta_analyzer import MetaAnalysisResult

        skill = MagicMock(spec=Skill)
        skill.name = "test-skill"

        result = MetaAnalysisResult(
            missed_threats=[
                {
                    "aitech": "AITech-1.1",
                    "severity": "HIGH",
                    "title": "Missed Prompt Injection",
                    "description": "Detected by meta-analysis",
                    "detection_reason": "Semantic analysis",
                }
            ]
        )

        findings = result.get_missed_threats(skill)

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].title == "Missed Prompt Injection"
        assert findings[0].analyzer == "meta"
        assert findings[0].metadata.get("meta_detected") is True


class TestMetaAnalyzerInit:
    """Tests for MetaAnalyzer initialization."""

    @pytest.fixture
    def mock_litellm(self):
        """Mock litellm availability."""
        with patch("skill_scanner.core.analyzers.meta_analyzer.LITELLM_AVAILABLE", True):
            with patch("skill_scanner.core.analyzers.meta_analyzer.acompletion", AsyncMock()):
                yield

    def test_separate_meta_api_key(self, mock_litellm):
        """Test that meta-analyzer can use separate API key from LLM analyzer."""
        with patch.dict(
            os.environ,
            {
                "SKILL_SCANNER_META_LLM_API_KEY": "test-meta-key-for-testing",
                "SKILL_SCANNER_META_LLM_MODEL": "gpt-4o",
                "SKILL_SCANNER_LLM_API_KEY": "test-regular-key-for-testing",
                "SKILL_SCANNER_LLM_MODEL": "claude-3-5-sonnet",
            },
            clear=True,
        ):
            from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

            # This should use meta-specific keys
            analyzer = MetaAnalyzer()

            assert analyzer.api_key == "test-meta-key-for-testing"
            assert analyzer.model == "gpt-4o"

    def test_fallback_to_llm_key(self, mock_litellm):
        """Test that meta-analyzer falls back to LLM analyzer key if meta key not set."""
        with patch.dict(
            os.environ,
            {
                "SKILL_SCANNER_LLM_API_KEY": "test-regular-key-for-testing",
                "SKILL_SCANNER_LLM_MODEL": "claude-3-5-sonnet",
            },
            clear=True,
        ):
            from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

            analyzer = MetaAnalyzer()

            # Should fall back to SKILL_SCANNER_LLM_* keys
            assert analyzer.api_key == "test-regular-key-for-testing"
            assert analyzer.model == "claude-3-5-sonnet"

    def test_explicit_parameters_override_env(self, mock_litellm):
        """Test that explicit parameters override environment variables."""
        with patch.dict(
            os.environ,
            {
                "SKILL_SCANNER_META_LLM_API_KEY": "test-env-key-for-testing",
                "SKILL_SCANNER_META_LLM_MODEL": "env-model",
            },
            clear=True,
        ):
            from skill_scanner.core.analyzers.meta_analyzer import MetaAnalyzer

            analyzer = MetaAnalyzer(api_key="test-explicit-key-for-testing", model="explicit-model")

            assert analyzer.api_key == "test-explicit-key-for-testing"
            assert analyzer.model == "explicit-model"


class TestApplyMetaAnalysis:
    """Tests for apply_meta_analysis_to_results function."""

    def test_marks_false_positives_with_metadata(self):
        """Test that false positives are marked with metadata but retained in output."""
        from skill_scanner.core.analyzers.meta_analyzer import (
            MetaAnalysisResult,
            apply_meta_analysis_to_results,
        )

        skill = MagicMock(spec=Skill)
        skill.name = "test-skill"

        original_findings = [
            Finding(
                id="finding_0",
                rule_id="RULE_1",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=Severity.HIGH,
                title="Real Finding",
                description="This is a real threat",
                analyzer="static",
            ),
            Finding(
                id="finding_1",
                rule_id="RULE_2",
                category=ThreatCategory.OBFUSCATION,
                severity=Severity.MEDIUM,
                title="False Positive",
                description="This is a false positive",
                analyzer="static",
            ),
        ]

        meta_result = MetaAnalysisResult(
            validated_findings=[
                {
                    "_index": 0,
                    "id": "finding_0",
                    "confidence": "HIGH",
                }
            ],
            false_positives=[
                {
                    "_index": 1,
                    "id": "finding_1",
                    "false_positive_reason": "Pattern match without malicious context",
                }
            ],
            priority_order=[0],  # Validated finding has priority 1
        )

        result = apply_meta_analysis_to_results(original_findings, meta_result, skill)

        # Both findings should be in output (false positives are no longer filtered)
        assert len(result) == 2

        # First finding should be validated (not a false positive)
        assert result[0].id == "finding_0"
        assert result[0].metadata.get("meta_false_positive") is False
        assert result[0].metadata.get("meta_confidence") == "HIGH"
        assert result[0].metadata.get("meta_priority") == 1

        # Second finding should be marked as a false positive with reason
        assert result[1].id == "finding_1"
        assert result[1].metadata.get("meta_false_positive") is True
        assert result[1].metadata.get("meta_reason") == "Pattern match without malicious context"

    def test_adds_missed_threats(self):
        """Test that missed threats are added to results."""
        from skill_scanner.core.analyzers.meta_analyzer import (
            MetaAnalysisResult,
            apply_meta_analysis_to_results,
        )

        skill = MagicMock(spec=Skill)
        skill.name = "test-skill"

        original_findings = []

        meta_result = MetaAnalysisResult(
            validated_findings=[],
            false_positives=[],
            missed_threats=[
                {
                    "aitech": "AITech-8.2",
                    "severity": "CRITICAL",
                    "title": "Hidden Data Exfiltration",
                    "description": "Credential theft detected",
                    "detection_reason": "Semantic analysis found credential access + network call",
                }
            ],
        )

        result = apply_meta_analysis_to_results(original_findings, meta_result, skill)

        # Should have the new threat detected by meta-analyzer
        assert len(result) == 1
        assert result[0].title == "Hidden Data Exfiltration"
        assert result[0].analyzer == "meta"
        assert result[0].metadata.get("meta_detected") is True
        # Missed threats should also be marked as not false positives
        assert result[0].metadata.get("meta_false_positive") is False


class TestReporterCompatibility:
    """Tests to verify meta-analysis findings work with all reporters."""

    @pytest.fixture
    def sample_scan_result(self):
        """Create a sample ScanResult with meta-analyzed findings."""
        from skill_scanner.core.models import ScanResult

        findings = [
            Finding(
                id="meta_finding_1",
                rule_id="META_VALIDATED",
                category=ThreatCategory.DATA_EXFILTRATION,
                severity=Severity.HIGH,
                title="Data Exfiltration via Network",
                description="Skill sends sensitive data to external server",
                file_path="scripts/helper.py",
                line_number=42,
                snippet="requests.post(url, json={'creds': creds})",
                remediation="Remove the network call or sanitize data",
                analyzer="meta",
                metadata={
                    "meta_validated": True,
                    "meta_confidence": "HIGH",
                    "meta_exploitability": "Easy",
                    "meta_impact": "Critical",
                    "aitech": "AITech-8.2",
                },
            )
        ]

        return ScanResult(
            skill_name="test-skill",
            skill_directory="/tmp/test-skill",
            findings=findings,
            scan_duration_seconds=1.5,
            analyzers_used=["static_analyzer", "llm_analyzer", "meta_analyzer"],
        )

    def test_json_reporter(self, sample_scan_result):
        """Test that JSON reporter handles meta-analysis findings."""
        from skill_scanner.core.reporters.json_reporter import JSONReporter

        reporter = JSONReporter(pretty=True)
        output = reporter.generate_report(sample_scan_result)

        # Parse and verify
        data = json.loads(output)
        assert "findings" in data
        assert len(data["findings"]) == 1
        assert data["findings"][0]["analyzer"] == "meta"
        assert data["findings"][0]["metadata"]["meta_validated"] is True
        assert "meta_analyzer" in data["analyzers_used"]

    def test_sarif_reporter(self, sample_scan_result):
        """Test that SARIF reporter handles meta-analysis findings."""
        from skill_scanner.core.reporters.sarif_reporter import SARIFReporter

        reporter = SARIFReporter()
        output = reporter.generate_report(sample_scan_result)

        # Parse and verify
        sarif = json.loads(output)
        assert sarif["$schema"] is not None
        assert len(sarif["runs"]) == 1
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert "meta" in results[0]["message"]["text"].lower() or results[0]["ruleId"] == "META_VALIDATED"

    def test_markdown_reporter(self, sample_scan_result):
        """Test that Markdown reporter handles meta-analysis findings."""
        from skill_scanner.core.reporters.markdown_reporter import MarkdownReporter

        reporter = MarkdownReporter(detailed=True)
        output = reporter.generate_report(sample_scan_result)

        # Verify markdown contains expected content
        assert "Data Exfiltration" in output
        assert "meta" in output.lower()
        assert "HIGH" in output

    def test_table_reporter(self, sample_scan_result):
        """Test that Table reporter handles meta-analysis findings."""
        from skill_scanner.core.reporters.table_reporter import TableReporter

        reporter = TableReporter()
        output = reporter.generate_report(sample_scan_result)

        # Verify table contains expected content
        assert "Data Exfiltration" in output
        assert "HIGH" in output


class TestAITechTaxonomy:
    """Tests for AITech taxonomy alignment."""

    def test_aitech_codes_in_prompt(self):
        """Verify all AITech codes in the prompt match threats.py."""
        from skill_scanner.threats.threats import ThreatMapping

        prompt_path = (
            Path(__file__).parent.parent / "skill_scanner" / "data" / "prompts" / "skill_meta_analysis_prompt.md"
        )

        if not prompt_path.exists():
            pytest.skip("Prompt file not found")

        prompt_content = prompt_path.read_text()

        # Check that key AITech codes are mentioned
        expected_codes = [
            "AITech-1.1",
            "AITech-1.2",
            "AITech-4.3",
            "AITech-8.2",
            "AITech-9.1",
            "AITech-12.1",
            "AITech-13.3",
            "AITech-15.1",
        ]

        for code in expected_codes:
            assert code in prompt_content, f"AITech code {code} missing from prompt"

            # Verify the code maps correctly
            mapping = ThreatMapping.get_threat_mapping_by_aitech(code)
            assert mapping is not None

    def test_threat_category_mapping(self):
        """Test that AITech codes map to valid ThreatCategory values."""
        from skill_scanner.threats.threats import ThreatMapping

        aitech_codes = [
            "AITech-1.1",
            "AITech-1.2",
            "AITech-4.3",
            "AITech-8.2",
            "AITech-9.1",
            "AITech-12.1",
            "AITech-13.3",
            "AITech-15.1",
        ]

        for code in aitech_codes:
            category = ThreatMapping.get_threat_category_from_aitech(code)
            # Verify it's a valid ThreatCategory value
            try:
                ThreatCategory(category)
            except ValueError:
                pytest.fail(f"AITech code {code} maps to invalid category: {category}")
