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

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.models import Finding, Severity, ThreatCategory
from skill_scanner.core.scan_policy import ScanPolicy, SeverityOverride
from skill_scanner.core.scanner import SkillScanner, scan_skill
from skill_scanner.core.scanner import scan_directory as convenience_scan_directory


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


class _StubAnalyzer(BaseAnalyzer):
    """Test analyzer that emits predetermined findings."""

    def __init__(self, name: str, findings: list[Finding], policy: ScanPolicy | None = None):
        super().__init__(name=name, policy=policy)
        self._findings = findings

    def analyze(self, skill):  # pragma: no cover - simple test stub
        return list(self._findings)


def _mk_finding(
    *,
    rule_id: str,
    category: ThreatCategory,
    severity: Severity,
    file_path: str = "tool.py",
    line_number: int = 10,
    snippet: str = "danger()",
    title: str = "Test finding",
    description: str = "Test finding",
    remediation: str | None = None,
    analyzer: str = "stub",
) -> Finding:
    return Finding(
        id=f"{rule_id}_{file_path}_{line_number}",
        rule_id=rule_id,
        category=category,
        severity=severity,
        title=title,
        description=description,
        file_path=file_path,
        line_number=line_number,
        snippet=snippet,
        remediation=remediation,
        analyzer=analyzer,
    )


def test_convenience_scan_skill_infers_policy_from_analyzers(example_skills_dir):
    """Convenience scan_skill should use policy attached to provided analyzers."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    policy = ScanPolicy.default()
    policy.severity_overrides = [SeverityOverride(rule_id="RULE_POLICY_TEST", severity="LOW", reason="test")]

    finding = _mk_finding(
        rule_id="RULE_POLICY_TEST",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        analyzer="stub",
    )
    analyzers = [_StubAnalyzer("stub", [finding], policy=policy)]

    result = scan_skill(skill_dir, analyzers=analyzers)
    matched = [f for f in result.findings if f.rule_id == "RULE_POLICY_TEST"]

    assert matched
    assert matched[0].severity == Severity.LOW


def test_convenience_scan_directory_infers_policy_from_analyzers(example_skills_dir):
    """Convenience scan_directory should apply disabled_rules from analyzer policy."""
    policy = ScanPolicy.default()
    policy.disabled_rules.add("RULE_POLICY_TEST")
    finding = _mk_finding(
        rule_id="RULE_POLICY_TEST",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        analyzer="stub",
    )
    analyzers = [_StubAnalyzer("stub", [finding], policy=policy)]

    report = convenience_scan_directory(
        example_skills_dir,
        recursive=True,
        analyzers=analyzers,
    )

    assert report.scan_results
    for result in report.scan_results:
        assert all(f.rule_id != "RULE_POLICY_TEST" for f in result.findings)


def test_finding_output_dedupe_exact_knob(example_skills_dir):
    """Exact duplicate findings should be policy-controlled."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"

    f1 = _mk_finding(
        rule_id="DUP_RULE",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        analyzer="stub-a",
    )
    f2 = _mk_finding(
        rule_id="DUP_RULE",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        analyzer="stub-a",
    )

    dedupe_policy = ScanPolicy.default()
    dedupe_policy.finding_output.dedupe_exact_findings = True
    dedupe_policy.finding_output.dedupe_same_issue_per_location = False
    scanner_dedupe = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [f1], policy=dedupe_policy),
            _StubAnalyzer("a2", [f2], policy=dedupe_policy),
        ],
        policy=dedupe_policy,
    )
    deduped = scanner_dedupe.scan_skill(skill_dir)
    assert len(deduped.findings) == 1

    raw_policy = ScanPolicy.default()
    raw_policy.finding_output.dedupe_exact_findings = False
    raw_policy.finding_output.dedupe_same_issue_per_location = False
    scanner_raw = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [f1], policy=raw_policy),
            _StubAnalyzer("a2", [f2], policy=raw_policy),
        ],
        policy=raw_policy,
    )
    raw = scanner_raw.scan_skill(skill_dir)
    assert len(raw.findings) == 2


def test_finding_output_same_issue_dedupe_knob(example_skills_dir):
    """Same issue from different rules on same location should collapse."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    high = _mk_finding(
        rule_id="RULE_HIGH",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        analyzer="static",
    )
    medium = _mk_finding(
        rule_id="RULE_MEDIUM",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.MEDIUM,
        analyzer="yara",
    )

    dedupe_policy = ScanPolicy.default()
    dedupe_policy.finding_output.dedupe_exact_findings = False
    dedupe_policy.finding_output.dedupe_same_issue_per_location = True
    scanner_dedupe = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [high], policy=dedupe_policy),
            _StubAnalyzer("a2", [medium], policy=dedupe_policy),
        ],
        policy=dedupe_policy,
    )
    deduped = scanner_dedupe.scan_skill(skill_dir)
    assert len(deduped.findings) == 1
    assert deduped.findings[0].rule_id == "RULE_HIGH"
    assert deduped.findings[0].metadata.get("deduped_rule_ids") == ["RULE_MEDIUM"]

    raw_policy = ScanPolicy.default()
    raw_policy.finding_output.dedupe_exact_findings = False
    raw_policy.finding_output.dedupe_same_issue_per_location = False
    scanner_raw = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [high], policy=raw_policy),
            _StubAnalyzer("a2", [medium], policy=raw_policy),
        ],
        policy=raw_policy,
    )
    raw = scanner_raw.scan_skill(skill_dir)
    assert len(raw.findings) == 2


def test_policy_fingerprint_metadata_knob(example_skills_dir):
    """Each finding should include policy fingerprint metadata when enabled."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    f = _mk_finding(
        rule_id="TRACE_RULE",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
    )

    enabled_policy = ScanPolicy.default()
    enabled_policy.finding_output.attach_policy_fingerprint = True
    scanner_enabled = SkillScanner(
        analyzers=[_StubAnalyzer("a1", [f], policy=enabled_policy)],
        policy=enabled_policy,
    )
    enabled = scanner_enabled.scan_skill(skill_dir)
    md = enabled.findings[0].metadata
    assert md.get("scan_policy_name") == enabled_policy.policy_name
    assert md.get("scan_policy_version") == enabled_policy.policy_version
    assert md.get("scan_policy_preset_base") == enabled_policy.preset_base
    assert isinstance(md.get("scan_policy_fingerprint_sha256"), str)
    assert len(md.get("scan_policy_fingerprint_sha256")) == 64

    disabled_policy = ScanPolicy.default()
    disabled_policy.finding_output.attach_policy_fingerprint = False
    f_disabled = _mk_finding(
        rule_id="TRACE_RULE",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
    )
    scanner_disabled = SkillScanner(
        analyzers=[_StubAnalyzer("a1", [f_disabled], policy=disabled_policy)],
        policy=disabled_policy,
    )
    disabled = scanner_disabled.scan_skill(skill_dir)
    md2 = disabled.findings[0].metadata
    assert "scan_policy_fingerprint_sha256" not in md2


def test_same_issue_prefers_meta_and_preserves_context(example_skills_dir):
    """Same-issue dedupe should prefer meta/LLM details while preserving max severity."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    static_high = _mk_finding(
        rule_id="RULE_STATIC_HIGH",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        snippet="subprocess.run(cmd, shell=True)",
        analyzer="static",
        description="Static analyzer shell execution pattern.",
    )
    meta_medium = _mk_finding(
        rule_id="META_VALIDATED",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.MEDIUM,
        snippet="subprocess.run(cmd, shell=True)",
        analyzer="meta_analyzer",
        title="Meta-validated shell execution path",
        description="Meta analyzer validated exploitability and impact chain.",
        remediation="Avoid shell=True and pass args as a list.",
    )
    meta_medium.metadata["reasoning"] = "taint reaches shell command construction"

    policy = ScanPolicy.default()
    policy.finding_output.dedupe_exact_findings = False
    policy.finding_output.dedupe_same_issue_per_location = True

    scanner_dedupe = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [static_high], policy=policy),
            _StubAnalyzer("a2", [meta_medium], policy=policy),
        ],
        policy=policy,
    )
    result = scanner_dedupe.scan_skill(skill_dir)
    assert len(result.findings) == 1
    kept = result.findings[0]
    assert kept.rule_id == "META_VALIDATED"
    assert kept.analyzer == "meta_analyzer"
    assert kept.severity == Severity.HIGH
    assert kept.remediation == "Avoid shell=True and pass args as a list."
    assert kept.metadata.get("reasoning") == "taint reaches shell command construction"
    assert kept.metadata.get("deduped_original_severity") == "MEDIUM"
    assert kept.metadata.get("deduped_rule_ids") == ["RULE_STATIC_HIGH"]
    assert kept.metadata.get("deduped_analyzers") == ["static"]


def test_same_issue_precedence_is_policy_controlled(example_skills_dir):
    """Analyzer precedence for same-issue collapse should follow policy knob order."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    static_medium = _mk_finding(
        rule_id="RULE_STATIC",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.MEDIUM,
        snippet="os.system(user_input)",
        analyzer="static",
        remediation="Static remediation",
    )
    llm_medium = _mk_finding(
        rule_id="LLM_COMMAND_INJECTION",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.MEDIUM,
        snippet="os.system(user_input)",
        analyzer="llm_analyzer",
        remediation="LLM remediation",
    )

    policy = ScanPolicy.default()
    policy.finding_output.dedupe_exact_findings = False
    policy.finding_output.dedupe_same_issue_per_location = True
    policy.finding_output.same_issue_preferred_analyzers = ["static", "llm_analyzer"]

    scanner_dedupe = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [static_medium], policy=policy),
            _StubAnalyzer("a2", [llm_medium], policy=policy),
        ],
        policy=policy,
    )
    result = scanner_dedupe.scan_skill(skill_dir)
    assert len(result.findings) == 1
    kept = result.findings[0]
    assert kept.analyzer == "static"
    assert kept.rule_id == "RULE_STATIC"
    assert kept.remediation == "Static remediation"


def test_same_issue_does_not_collapse_within_single_analyzer(example_skills_dir):
    """Same analyzer findings should not be collapsed by same-issue dedupe."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    f1 = _mk_finding(
        rule_id="RULE_STATIC_A",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        snippet="subprocess.run(cmd, shell=True)",
        analyzer="static",
    )
    f2 = _mk_finding(
        rule_id="RULE_STATIC_B",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.MEDIUM,
        snippet="subprocess.run(cmd, shell=True)",
        analyzer="static",
    )

    policy = ScanPolicy.default()
    policy.finding_output.dedupe_exact_findings = False
    policy.finding_output.dedupe_same_issue_per_location = True
    policy.finding_output.same_issue_collapse_within_analyzer = False

    scanner_dedupe = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [f1], policy=policy),
            _StubAnalyzer("a2", [f2], policy=policy),
        ],
        policy=policy,
    )
    result = scanner_dedupe.scan_skill(skill_dir)
    assert len(result.findings) == 2
    assert {f.rule_id for f in result.findings} == {"RULE_STATIC_A", "RULE_STATIC_B"}


def test_same_issue_can_collapse_within_single_analyzer_when_enabled(example_skills_dir):
    """Policy knob should allow same-analyzer same-issue collapse when requested."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    f1 = _mk_finding(
        rule_id="RULE_STATIC_A",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        snippet="subprocess.run(cmd, shell=True)",
        analyzer="static",
    )
    f2 = _mk_finding(
        rule_id="RULE_STATIC_B",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.MEDIUM,
        snippet="subprocess.run(cmd, shell=True)",
        analyzer="static",
    )

    policy = ScanPolicy.default()
    policy.finding_output.dedupe_exact_findings = False
    policy.finding_output.dedupe_same_issue_per_location = True
    policy.finding_output.same_issue_collapse_within_analyzer = True

    scanner_dedupe = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [f1], policy=policy),
            _StubAnalyzer("a2", [f2], policy=policy),
        ],
        policy=policy,
    )
    result = scanner_dedupe.scan_skill(skill_dir)
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "RULE_STATIC_A"
    assert result.findings[0].metadata.get("deduped_rule_ids") == ["RULE_STATIC_B"]


def test_same_path_other_rule_ids_metadata(example_skills_dir):
    """Findings on same path should include co-occurring rule IDs in metadata."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    f1 = _mk_finding(
        rule_id="RULE_A",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        file_path="scripts/run.py",
        line_number=10,
        snippet="eval(user_input)",
    )
    f2 = _mk_finding(
        rule_id="RULE_B",
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        file_path="scripts/run.py",
        line_number=22,
        snippet="requests.post(url, data=data)",
    )

    policy = ScanPolicy.default()
    policy.finding_output.dedupe_exact_findings = False
    policy.finding_output.dedupe_same_issue_per_location = False
    policy.finding_output.annotate_same_path_rule_cooccurrence = True

    scanner = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [f1], policy=policy),
            _StubAnalyzer("a2", [f2], policy=policy),
        ],
        policy=policy,
    )
    result = scanner.scan_skill(skill_dir)
    assert len(result.findings) == 2

    by_rule = {f.rule_id: f for f in result.findings}
    assert by_rule["RULE_A"].metadata.get("same_path_other_rule_ids") == ["RULE_B"]
    assert by_rule["RULE_B"].metadata.get("same_path_other_rule_ids") == ["RULE_A"]
    assert by_rule["RULE_A"].metadata.get("same_path_unique_rule_count") == 2
    assert by_rule["RULE_B"].metadata.get("same_path_findings_count") == 2


def test_same_path_other_rule_ids_knob_disable(example_skills_dir):
    """Path co-occurrence metadata should be disabled by policy knob."""
    skill_dir = example_skills_dir / "safe" / "simple-formatter"
    f1 = _mk_finding(
        rule_id="RULE_A",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.HIGH,
        file_path="scripts/run.py",
        line_number=10,
        snippet="eval(user_input)",
    )
    f2 = _mk_finding(
        rule_id="RULE_B",
        category=ThreatCategory.DATA_EXFILTRATION,
        severity=Severity.MEDIUM,
        file_path="scripts/run.py",
        line_number=22,
        snippet="requests.post(url, data=data)",
    )

    policy = ScanPolicy.default()
    policy.finding_output.dedupe_exact_findings = False
    policy.finding_output.dedupe_same_issue_per_location = False
    policy.finding_output.annotate_same_path_rule_cooccurrence = False

    scanner = SkillScanner(
        analyzers=[
            _StubAnalyzer("a1", [f1], policy=policy),
            _StubAnalyzer("a2", [f2], policy=policy),
        ],
        policy=policy,
    )
    result = scanner.scan_skill(skill_dir)
    assert len(result.findings) == 2
    for finding in result.findings:
        assert "same_path_other_rule_ids" not in finding.metadata
