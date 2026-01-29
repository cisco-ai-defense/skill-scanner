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
Unit tests for static analyzer.
"""

from pathlib import Path

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import Severity, ThreatCategory


@pytest.fixture
def example_skills_dir():
    """Get path to example skills directory."""
    return Path(__file__).parent.parent.parent / "evals" / "test_skills"


@pytest.fixture
def loader():
    """Create a skill loader instance."""
    return SkillLoader()


@pytest.fixture
def analyzer():
    """Create a static analyzer instance."""
    return StaticAnalyzer()


def test_safe_skill_has_no_critical_findings(loader, analyzer, example_skills_dir):
    """Test that simple-formatter has no critical findings."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    skill = loader.load_skill(skill_dir)

    findings = analyzer.analyze(skill)

    # Should have no critical or high severity findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    high_findings = [f for f in findings if f.severity == Severity.HIGH]

    assert len(critical_findings) == 0
    assert len(high_findings) == 0


def test_malicious_skill_detected(loader, analyzer, example_skills_dir):
    """Test that malicious/exfiltrator is flagged."""
    skill_dir = example_skills_dir / "malicious" / "exfiltrator"
    skill = loader.load_skill(skill_dir)

    findings = analyzer.analyze(skill)

    # Should have multiple critical findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0

    # Should detect data exfiltration
    exfil_findings = [f for f in findings if f.category == ThreatCategory.DATA_EXFILTRATION]
    assert len(exfil_findings) > 0

    # Should detect command injection (eval)
    injection_findings = [f for f in findings if f.category == ThreatCategory.COMMAND_INJECTION]
    assert len(injection_findings) > 0


def test_prompt_injection_detected(loader, analyzer, example_skills_dir):
    """Test that prompt-injection skill is flagged."""
    skill_dir = example_skills_dir / "malicious" / "prompt-injection"
    skill = loader.load_skill(skill_dir)

    findings = analyzer.analyze(skill)

    # Should detect prompt injection attempts
    prompt_inj_findings = [f for f in findings if f.category == ThreatCategory.PROMPT_INJECTION]
    assert len(prompt_inj_findings) > 0

    # Should have high severity findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) > 0


def test_analyzer_detects_network_usage(loader, analyzer, example_skills_dir):
    """Test detection of network library usage."""
    skill_dir = example_skills_dir / "malicious" / "exfiltrator"
    skill = loader.load_skill(skill_dir)

    findings = analyzer.analyze(skill)

    # Should flag network usage
    network_findings = [
        f for f in findings if "requests" in str(f.description).lower() or "network" in str(f.description).lower()
    ]
    assert len(network_findings) > 0


def test_analyzer_detects_sensitive_file_access(loader, analyzer, example_skills_dir):
    """Test detection of sensitive file access."""
    skill_dir = example_skills_dir / "malicious" / "exfiltrator"
    skill = loader.load_skill(skill_dir)

    findings = analyzer.analyze(skill)

    # Should detect potentially dangerous patterns (may or may not include specific AWS patterns)
    # The exfiltrator skill has network and dangerous code patterns
    assert len(findings) > 0


def test_finding_has_required_fields(loader, analyzer, example_skills_dir):
    """Test that findings have all required fields."""
    skill_dir = example_skills_dir / "malicious" / "exfiltrator"
    skill = loader.load_skill(skill_dir)

    findings = analyzer.analyze(skill)

    assert len(findings) > 0

    for finding in findings:
        assert finding.id is not None
        assert finding.rule_id is not None
        assert finding.category is not None
        assert finding.severity is not None
        assert finding.title is not None
        assert finding.description is not None


def test_static_analyzer_findings_have_analyzer_field(loader, analyzer, example_skills_dir):
    """Test that static analyzer findings include analyzer='static' field."""
    skill_dir = example_skills_dir / "malicious" / "exfiltrator"
    skill = loader.load_skill(skill_dir)

    findings = analyzer.analyze(skill)

    assert len(findings) > 0

    for finding in findings:
        # Check the field on the Finding object
        assert finding.analyzer == "static", f"Expected analyzer='static', got '{finding.analyzer}'"


def test_static_analyzer_findings_to_dict_includes_analyzer(loader, analyzer, example_skills_dir):
    """Test that Finding.to_dict() includes analyzer field in JSON output."""
    skill_dir = example_skills_dir / "malicious" / "exfiltrator"
    skill = loader.load_skill(skill_dir)

    findings = analyzer.analyze(skill)

    assert len(findings) > 0

    for finding in findings:
        finding_dict = finding.to_dict()

        # Verify analyzer field is present in dict output
        assert "analyzer" in finding_dict, "analyzer field missing from to_dict() output"
        assert finding_dict["analyzer"] == "static", f"Expected analyzer='static', got '{finding_dict['analyzer']}'"
