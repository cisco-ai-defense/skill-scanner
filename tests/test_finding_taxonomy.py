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

"""Every finding carries a Cisco AI taxonomy code that exists in the bundled snapshot."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
import yaml

from skill_scanner.core.analyzers.aidefense_analyzer import _AIDEFENSE_TAXONOMY
from skill_scanner.core.analyzers.behavioral_analyzer import ALIGNMENT_TAXONOMY, CROSSFILE_TAXONOMY, BehavioralAnalyzer
from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.finding_taxonomy import annotate_finding_taxonomy, select_taxonomy
from skill_scanner.core.models import Finding, Severity, ThreatCategory
from skill_scanner.core.reporters.sarif_reporter import SARIFReporter
from skill_scanner.core.rule_registry import (
    TAXONOMY_NOT_APPLICABLE,
    TAXONOMY_PER_FINDING,
    PackLoader,
    RuleDefinition,
    RuleRegistry,
)
from skill_scanner.core.scanner import SkillScanner
from skill_scanner.threats import cisco_ai_taxonomy as taxonomy
from skill_scanner.threats.threats import ThreatMapping

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = REPO_ROOT / "skill_scanner" / "data" / "packs"
# The skill behind the original report of a cross-file exfiltration finding with no AITech.
EXFILTRATOR_SKILL = REPO_ROOT / "evals" / "test_skills" / "malicious" / "exfiltrator"


@pytest.fixture(scope="module")
def bundled_registry() -> RuleRegistry:
    return PackLoader().build_registry()


def _registry(*rules: RuleDefinition) -> RuleRegistry:
    registry = RuleRegistry()
    for rule in rules:
        registry.register(rule)
    return registry


def _rule(rule_id: str, selection: str, source: str = "rule") -> RuleDefinition:
    return RuleDefinition(
        id=rule_id,
        source_type="signature",
        pack_name="test",
        category="prompt_injection",
        default_severity="HIGH",
        taxonomy=selection,
        taxonomy_source=source,
    )


def _finding(rule_id: str = "TEST_RULE", **metadata) -> Finding:
    return Finding(
        id=f"{rule_id}_1",
        rule_id=rule_id,
        category=ThreatCategory.PROMPT_INJECTION,
        severity=Severity.HIGH,
        title="t",
        description="d",
        metadata=dict(metadata),
    )


# ---------------------------------------------------------------------------
# Bundled rule declarations
# ---------------------------------------------------------------------------


def test_every_bundled_rule_declares_a_real_code(bundled_registry):
    rules = bundled_registry.all_rules()
    assert len(rules) > 900
    for rule in rules.values():
        assert rule.taxonomy, rule.id
        if rule.taxonomy in (TAXONOMY_NOT_APPLICABLE, TAXONOMY_PER_FINDING):
            continue
        aitech, aisubtech = taxonomy.resolve_taxonomy_code(rule.taxonomy)
        assert aitech is not None, f"{rule.id}: {rule.taxonomy} is not in the bundled taxonomy"
        if rule.taxonomy.startswith("AISubtech-"):
            assert aisubtech == rule.taxonomy


def test_only_operational_rules_are_not_applicable(bundled_registry):
    not_applicable = {r.id for r in bundled_registry.all_rules().values() if r.taxonomy == TAXONOMY_NOT_APPLICABLE}
    assert not_applicable == {
        "MANIFEST_INVALID_NAME",
        "MANIFEST_DESCRIPTION_TOO_LONG",
        "MANIFEST_MISSING_LICENSE",
        "TRIGGER_DESCRIPTION_TOO_SHORT",
        "PYCACHE_FILES_DETECTED",
        "ARCHIVE_FILE_DETECTED",
        "UNICODE_ANALYSIS_INCOMPLETE",
        "EXCESSIVE_FILE_COUNT",
        "OVERSIZED_FILE",
        "SKILL_LOAD_FALLBACK_USED",
        "SKILL_LOAD_REJECTED_LIMIT",
        "FINDING_OUTPUT_NORMALIZATION",
        "BEHAVIOR_DATAFLOW_ANALYSIS_INCOMPLETE",
        "LLM_CONTEXT_BUDGET_EXCEEDED",
        "LLM_ANALYSIS_FAILED",
        "META_CONTEXT_BUDGET_EXCEEDED",
    }


def test_per_finding_rules_belong_to_analyzers_that_choose_codes(bundled_registry):
    for rule in bundled_registry.all_rules().values():
        if rule.taxonomy == TAXONOMY_PER_FINDING:
            assert rule.analyzer == "meta", rule.id


@pytest.mark.parametrize(
    "table",
    [ALIGNMENT_TAXONOMY, CROSSFILE_TAXONOMY, _AIDEFENSE_TAXONOMY],
    ids=["behavioral-alignment", "behavioral-crossfile", "aidefense"],
)
def test_analyzer_code_tables_use_real_codes(table):
    for label, code in table.items():
        assert taxonomy.resolve_taxonomy_code(code)[0], f"{label}: {code}"


def _copy_pack(tmp_path: Path, name: str) -> Path:
    target = tmp_path / name
    shutil.copytree(PACKS_DIR / name, target)
    return target


def _rewrite_manifest(pack_dir: Path, mutate) -> None:
    manifest_path = pack_dir / "pack.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    mutate(manifest)
    manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")


def test_bundled_pack_rejects_rule_without_taxonomy(tmp_path):
    pack_dir = _copy_pack(tmp_path, "promptguard")
    _rewrite_manifest(pack_dir, lambda m: m["rules"]["PG_PII_SSN"].pop("taxonomy"))

    with pytest.raises(ValueError, match="must declare taxonomy"):
        PackLoader().load_bundled_pack(pack_dir)


def test_bundled_pack_rejects_code_missing_from_snapshot(tmp_path):
    pack_dir = _copy_pack(tmp_path, "promptguard")
    _rewrite_manifest(pack_dir, lambda m: m["rules"]["PG_PII_SSN"].update({"taxonomy": "AISubtech-1.2.1"}))

    with pytest.raises(ValueError, match="does not exist in the bundled Cisco AI taxonomy"):
        PackLoader().load_bundled_pack(pack_dir)


def test_bundled_pack_category_default_applies(tmp_path):
    pack_dir = _copy_pack(tmp_path, "promptguard")

    def mutate(manifest):
        manifest["taxonomy_defaults"] = {"hardcoded_secrets": "AISubtech-14.1.1"}
        manifest["rules"]["PG_SECRET_NPM_TOKEN"].pop("taxonomy")

    _rewrite_manifest(pack_dir, mutate)
    rule = PackLoader().load_bundled_pack(pack_dir).rules["PG_SECRET_NPM_TOKEN"]
    assert (rule.taxonomy, rule.taxonomy_source) == ("AISubtech-14.1.1", "pack_default")


@pytest.mark.parametrize("value", ["AITech-1", "aisubtech-1.1.1", " AITech-1.1", "", 7, "per_findings"])
def test_trusted_pack_rejects_malformed_taxonomy(tmp_path, value):
    from tests.test_trusted_rule_pack_v2 import _manifest, _signature, _write_pack

    manifest = _manifest()
    manifest["rules"]["TRUSTED_FETCH"]["taxonomy"] = value
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=[_signature()])

    with pytest.raises(ValueError, match="taxonomy"):
        PackLoader().load_trusted_pack(pack_dir)


def test_trusted_pack_taxonomy_is_optional_and_carried(tmp_path):
    from tests.test_trusted_rule_pack_v2 import _manifest, _signature, _write_pack

    manifest = _manifest()
    manifest["rules"]["TRUSTED_FETCH"]["taxonomy"] = "AISubtech-9.1.4"
    pack_dir = _write_pack(tmp_path / "with", manifest=manifest, signatures=[_signature()])
    assert PackLoader().load_trusted_pack(pack_dir).rules["TRUSTED_FETCH"].taxonomy == "AISubtech-9.1.4"

    plain = _write_pack(tmp_path / "without", signatures=[_signature()])
    assert PackLoader().load_trusted_pack(plain).rules["TRUSTED_FETCH"].taxonomy == ""


# ---------------------------------------------------------------------------
# Annotation
# ---------------------------------------------------------------------------


def test_rule_subtechnique_supplies_parent_names_and_crosswalks():
    finding = _finding()
    annotate_finding_taxonomy(finding, _registry(_rule("TEST_RULE", "AISubtech-1.1.1")))

    m = finding.metadata
    assert (m["aitech"], m["aisubtech"]) == ("AITech-1.1", "AISubtech-1.1.1")
    assert m["aitech_name"] == taxonomy.get_aitech_name("AITech-1.1")
    assert m["aisubtech_name"] == "Instruction Manipulation"
    assert m["aisubtech_mappings"] == taxonomy.get_aisubtech_framework_mappings("AISubtech-1.1.1")
    assert m["aitech_mappings"] == taxonomy.get_aitech_framework_mappings("AITech-1.1")
    assert m["framework_mappings"] == m["aisubtech_mappings"]
    assert "OWASP: LLM01:2026: Prompt Injection" in m["framework_mappings"]
    assert (m["taxonomy_status"], m["taxonomy_source"]) == ("mapped", "rule")


def test_technique_without_subtechnique_uses_technique_crosswalks():
    finding = _finding()
    annotate_finding_taxonomy(finding, _registry(_rule("TEST_RULE", "AITech-1.2")))

    m = finding.metadata
    assert (m["aitech"], m["aisubtech"], m["aisubtech_name"]) == ("AITech-1.2", None, None)
    assert m["aisubtech_mappings"] == []
    assert m["framework_mappings"] == taxonomy.get_aitech_framework_mappings("AITech-1.2")


def test_not_applicable_rule_is_explicit():
    finding = _finding("OPS_RULE")
    annotate_finding_taxonomy(finding, _registry(_rule("OPS_RULE", TAXONOMY_NOT_APPLICABLE)))

    m = finding.metadata
    assert m["taxonomy_status"] == "not_applicable"
    assert m["aitech"] is None and m["aisubtech"] is None and m["framework_mappings"] == []


def test_unknown_rule_is_unmapped_not_guessed():
    finding = _finding("NOT_REGISTERED")
    annotate_finding_taxonomy(finding, _registry())

    assert finding.metadata["taxonomy_status"] == "unmapped"
    assert finding.metadata["aitech"] is None


def test_analyzer_choice_wins_over_rule_declaration():
    finding = _finding(aitech="AITech-8.2", aisubtech="AISubtech-8.2.3")
    annotate_finding_taxonomy(finding, _registry(_rule("TEST_RULE", "AISubtech-1.1.1")))

    m = finding.metadata
    assert (m["aitech"], m["aisubtech"], m["taxonomy_source"]) == ("AITech-8.2", "AISubtech-8.2.3", "finding")


def test_subtechnique_alone_implies_its_parent():
    assert select_taxonomy(None, "AISubtech-9.1.4") == ("AITech-9.1", "AISubtech-9.1.4")


def test_subtechnique_under_another_technique_is_dropped():
    assert select_taxonomy("AITech-8.2", "AISubtech-1.1.1") == ("AITech-8.2", None)


def test_invented_analyzer_code_falls_back_to_the_rule():
    finding = _finding(aitech="AITech-99.9", aisubtech="AISubtech-99.9.9")
    annotate_finding_taxonomy(finding, _registry(_rule("TEST_RULE", "AISubtech-1.1.5")))

    m = finding.metadata
    assert (m["aitech"], m["aisubtech"], m["taxonomy_source"]) == ("AITech-1.1", "AISubtech-1.1.5", "rule")


def test_annotation_is_idempotent():
    registry = _registry(_rule("TEST_RULE", "AISubtech-1.1.1"))
    finding = _finding()
    annotate_finding_taxonomy(finding, registry)
    first = dict(finding.metadata)
    annotate_finding_taxonomy(finding, registry)

    assert finding.metadata == first
    assert finding.metadata["taxonomy_source"] == "rule"


def test_unknown_threat_mapping_has_no_invented_code():
    mapping = ThreatMapping.get_threat_mapping("static", "not a real threat")
    assert mapping["aitech"] is None and mapping["aisubtech"] is None


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def exfil_scan():
    scanner = SkillScanner(analyzers=[StaticAnalyzer(), BehavioralAnalyzer()])
    return scanner.scan_skill(EXFILTRATOR_SKILL)


def test_scanned_findings_all_carry_real_codes(exfil_scan):
    assert exfil_scan.findings
    for finding in exfil_scan.findings:
        m = finding.metadata
        assert m["taxonomy_status"] in {"mapped", "not_applicable"}, finding.rule_id
        if m["taxonomy_status"] == "mapped":
            assert taxonomy.is_valid_aitech(m["aitech"]), finding.rule_id
            assert m["aisubtech"] is None or taxonomy.get_aisubtech_parent(m["aisubtech"]) == m["aitech"]
            assert m["framework_mappings"], finding.rule_id


def test_cross_file_exfiltration_is_mapped(exfil_scan):
    crossfile = [f for f in exfil_scan.findings if f.rule_id.startswith("BEHAVIOR_CROSSFILE_")]
    assert crossfile
    for finding in crossfile:
        assert finding.metadata["aisubtech"] in set(CROSSFILE_TAXONOMY.values())
        assert finding.metadata["taxonomy_source"] == "finding"


def test_scan_metadata_records_taxonomy(exfil_scan):
    info = exfil_scan.scan_metadata["taxonomy"]
    assert info["version"] == "2.0.0"
    assert info["findings"]["unmapped"] == 0
    assert info["findings"]["mapped"] + info["findings"]["not_applicable"] == len(exfil_scan.findings)


def test_sarif_results_carry_taxonomy(exfil_scan):
    sarif = json.loads(SARIFReporter().generate_report(exfil_scan))
    results = sarif["runs"][0]["results"]
    assert results
    mapped = [r for r in results if "aitech" in r["properties"]]
    assert mapped
    for result in mapped:
        assert taxonomy.is_valid_aitech(result["properties"]["aitech"])
        assert result["properties"]["framework_mappings"]


def test_meta_missed_threats_are_annotated():
    """Meta findings are created after the scan, so the meta step annotates them itself."""
    from unittest.mock import MagicMock

    from skill_scanner.core.analyzers.meta_analyzer import MetaAnalysisResult, apply_meta_analysis_to_results
    from skill_scanner.core.models import Skill

    skill = MagicMock(spec=Skill)
    skill.name = "test-skill"
    meta = MetaAnalysisResult(
        missed_threats=[{"aitech": "AITech-8.2", "severity": "HIGH", "title": "Missed exfil", "description": "d"}]
    )

    findings = apply_meta_analysis_to_results(original_findings=[], meta_result=meta, skill=skill)

    assert len(findings) == 1
    m = findings[0].metadata
    assert (m["aitech"], m["aisubtech"], m["taxonomy_status"], m["taxonomy_source"]) == (
        "AITech-8.2",
        None,
        "mapped",
        "finding",
    )
    assert m["framework_mappings"] == taxonomy.get_aitech_framework_mappings("AITech-8.2")


def test_custom_threat_mapping_code_overrides_rule_declaration(monkeypatch, tmp_path):
    import skill_scanner.threats.threats as threats

    path = tmp_path / "mapping.json"
    path.write_text(json.dumps({"yara_threats": {"PROMPT INJECTION": {"aitech": "AITech-1.2"}}}), encoding="utf-8")
    registry = _registry(_rule("TEST_RULE", "AISubtech-1.1.1"))
    # Let monkeypatch own the variable so teardown removes it; passing the path
    # to configure_threat_mappings() would write os.environ directly.
    monkeypatch.setenv("SKILL_SCANNER_THREAT_MAPPING_PATH", str(path))
    try:
        threats.configure_threat_mappings()
        static_finding = _finding()
        static_finding.analyzer = "static"
        annotate_finding_taxonomy(static_finding, registry)
        assert (static_finding.metadata["aitech"], static_finding.metadata["taxonomy_source"]) == (
            "AITech-1.2",
            "threat_mapping",
        )

        # Other analyzers keep the rule's declaration.
        trigger_finding = _finding()
        trigger_finding.analyzer = "trigger"
        annotate_finding_taxonomy(trigger_finding, registry)
        assert trigger_finding.metadata["taxonomy_source"] == "rule"
    finally:
        monkeypatch.delenv("SKILL_SCANNER_THREAT_MAPPING_PATH", raising=False)
        threats.configure_threat_mappings()
    assert threats.get_taxonomy_override("static", "prompt_injection") is None


def test_subtechnique_whose_parent_is_not_registered_is_not_mapped(monkeypatch, tmp_path):
    payload = {
        "OB-001": {
            "ai_tech": [
                {"code": "AITech-7.7", "ai_subtech": [{"code": "AISubtech-7.7.1", "description": "No named parent"}]},
                {
                    "code": "AITech-7.8",
                    "description": "Named",
                    "ai_subtech": [{"code": "AISubtech-7.8.1", "description": "Ok"}],
                },
            ]
        }
    }
    path = tmp_path / "ob.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    try:
        taxonomy.reload_taxonomy(path)
        assert select_taxonomy(None, "AISubtech-7.7.1") == (None, None)
        assert select_taxonomy(None, "AISubtech-7.8.1") == ("AITech-7.8", "AISubtech-7.8.1")
    finally:
        monkeypatch.delenv(taxonomy.TAXONOMY_ENV_VAR, raising=False)
        taxonomy.reload_taxonomy()


def test_cli_scan_counts_match_output_after_meta_analysis(monkeypatch):
    """Counts must describe the findings actually output: meta false positives
    are stripped and meta missed threats are added after the scan."""
    from unittest.mock import AsyncMock, patch

    from skill_scanner.cli import cli
    from skill_scanner.core.analyzers.meta_analyzer import MetaAnalysisResult
    from tests.test_cli_llm_usage import _base_args

    meta_result = MetaAnalysisResult(
        false_positives=[{"_index": 0, "reason": "benign"}],
        missed_threats=[{"aitech": "AITech-8.2", "severity": "HIGH", "title": "Missed exfil", "description": "d"}],
    )
    monkeypatch.setenv("SKILL_SCANNER_LLM_API_KEY", "test-key")
    monkeypatch.setenv("SKILL_SCANNER_LLM_MODEL", "claude-3-5-sonnet-20241022")
    with (
        patch("skill_scanner.core.analyzers.llm_request_handler.acompletion", AsyncMock(side_effect=RuntimeError)),
        patch(
            "skill_scanner.core.analyzers.meta_analyzer.MetaAnalyzer.analyze_with_findings",
            AsyncMock(return_value=meta_result),
        ),
    ):
        args = _base_args(verbose=False)
        assert cli.scan_command(args) == 0

    result = args._result_or_report
    assert not any(f.metadata.get("meta_false_positive") for f in result.findings)
    missed = [f for f in result.findings if f.analyzer == "meta"]
    assert len(missed) == 1 and missed[0].metadata["taxonomy_status"] == "mapped"
    counts = result.scan_metadata["taxonomy"]["findings"]
    assert sum(counts.values()) == len(result.findings)


def test_new_technique_codes_have_a_category_fallback():
    assert ThreatMapping.get_threat_category_from_aitech("AITech-14.1") == "hardcoded_secrets"
    assert ThreatMapping.get_threat_category_from_aitech("AITech-8.4") == "data_exfiltration"
    assert ThreatMapping.get_threat_category_from_aitech("AITech-1.3") == "prompt_injection"
