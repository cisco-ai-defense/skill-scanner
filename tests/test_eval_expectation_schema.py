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

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.runners.finding_matcher import (
    EvaluationExpectationError,
    bind_label_attestation,
    fixture_sha256,
    validate_expectation_document,
)
from evals.runners.update_expected_findings import build_observation_report


def _strict_document(fixture_dir: Path) -> dict:
    document = {
        "schema_version": 2,
        "evaluation_quality": "strict",
        "case_id": "safe.fixture-001",
        "skill_name": "safe-fixture",
        "package_label": "benign",
        "expected_verdict": "safe",
        "provenance": {
            "source": "first-party-inert-fixture",
            "license": "Apache-2.0",
            "fixture_sha256": fixture_sha256(fixture_dir),
            "label_source": "agent_labeled",
            "scanner_independent": True,
            "scanner_derived_label": False,
            "sealed_hf_test_content_used_for_labeling": False,
        },
        "expected_findings": [],
    }
    bind_label_attestation(document)
    return document


def test_strict_expectation_requires_matching_fixture_provenance(tmp_path: Path):
    (tmp_path / "SKILL.md").write_text("# Safe\n", encoding="utf-8")
    document = _strict_document(tmp_path)

    validated = validate_expectation_document(document, fixture_dir=tmp_path)

    assert validated.expected_safe is True
    assert validated.package_label == "benign"
    assert validated.label_source == "agent_labeled"
    assert validated.evaluation_quality == "strict"

    (tmp_path / "SKILL.md").write_text("# Changed\n", encoding="utf-8")
    with pytest.raises(EvaluationExpectationError, match="does not match fixture contents"):
        validate_expectation_document(document, fixture_dir=tmp_path)


@pytest.mark.parametrize(
    "label_source",
    ["public_labeled", "independent_ollama", "agent_labeled", "human_reviewed"],
)
def test_strict_expectation_accepts_each_scanner_independent_label_source(
    tmp_path: Path,
    label_source: str,
) -> None:
    (tmp_path / "SKILL.md").write_text("# Fixture\n", encoding="utf-8")
    document = _strict_document(tmp_path)
    document["provenance"]["label_source"] = label_source
    bind_label_attestation(document)

    validated = validate_expectation_document(document, fixture_dir=tmp_path)

    assert validated.label_source == label_source


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda document: document["provenance"].update(label_source="scanner_derived"), "label_source"),
        (
            lambda document: document["provenance"].update(source="scanner-derived generated label"),
            "scanner-derived",
        ),
        (
            lambda document: document["provenance"].update(scanner_independent=False),
            "scanner_independent",
        ),
        (
            lambda document: document["provenance"].update(scanner_derived_label=True),
            "scanner-derived",
        ),
        (
            lambda document: document["provenance"].update(sealed_hf_test_content_used_for_labeling=True),
            "sealed Hugging Face test content",
        ),
        (
            lambda document: document["provenance"].update(label_provenance_sha256="0" * 64),
            "label_provenance_sha256",
        ),
        (
            lambda document: document["provenance"].update(label_evidence_sha256="0" * 64),
            "label_evidence_sha256",
        ),
    ],
)
def test_strict_expectation_rejects_untrusted_or_spoofed_label_attestation(
    tmp_path: Path,
    mutation,
    message: str,
) -> None:
    (tmp_path / "SKILL.md").write_text("# Fixture\n", encoding="utf-8")
    document = _strict_document(tmp_path)
    mutation(document)

    with pytest.raises(EvaluationExpectationError, match=message):
        validate_expectation_document(document, fixture_dir=tmp_path)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"unexpected": True}), "unknown key"),
        (
            lambda value: value.update(
                {
                    "expected_findings": [
                        {
                            "category": "command_injection",
                            "severity": "HIGH",
                        }
                    ]
                }
            ),
            "missing canonical identity",
        ),
    ],
)
def test_strict_expectation_rejects_unknown_or_incomplete_schema(tmp_path: Path, mutation, message: str):
    (tmp_path / "SKILL.md").write_text("# Fixture\n", encoding="utf-8")
    document = _strict_document(tmp_path)
    mutation(document)

    with pytest.raises(EvaluationExpectationError, match=message):
        validate_expectation_document(document, fixture_dir=tmp_path)


def test_legacy_expectation_must_explicitly_declare_degraded_quality():
    document = {
        "schema_version": 1,
        "skill_name": "historical",
        "expected_safe": False,
        "expected_findings": [{"category": "command_injection", "severity": "HIGH"}],
    }

    with pytest.raises(EvaluationExpectationError, match="legacy_degraded"):
        validate_expectation_document(document)

    document["evaluation_quality"] = "legacy_degraded"
    validated = validate_expectation_document(document)

    assert validated.expected_safe is False
    assert validated.package_label is None
    assert validated.evaluation_quality == "legacy_degraded"


def test_committed_golden_expectations_are_all_strict_and_cover_taxonomy():
    repository_root = Path(__file__).resolve().parents[1]
    expected_files = sorted((repository_root / "evals" / "skills").glob("**/_expected.json"))

    assert expected_files
    categories: set[str] = set()
    severities: set[str] = set()
    case_ids: set[str] = set()
    for expected_file in expected_files:
        document = json.loads(expected_file.read_text(encoding="utf-8"))
        validated = validate_expectation_document(document, fixture_dir=expected_file.parent)
        assert validated.evaluation_quality == "strict", expected_file
        assert document["case_id"] not in case_ids, expected_file
        case_ids.add(document["case_id"])
        categories.update(finding["category"] for finding in document["expected_findings"])
        severities.update(finding["severity"] for finding in document["expected_findings"])

    assert categories == {
        "autonomy_abuse",
        "command_injection",
        "data_exfiltration",
        "hardcoded_secrets",
        "harmful_content",
        "malware",
        "obfuscation",
        "policy_violation",
        "prompt_injection",
        "resource_abuse",
        "skill_discovery_abuse",
        "social_engineering",
        "supply_chain_attack",
        "tool_chaining_abuse",
        "transitive_trust_abuse",
        "unauthorized_tool_use",
        "unicode_steganography",
    }
    assert severities == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def test_historical_test_skill_expectations_remain_explicitly_degraded():
    repository_root = Path(__file__).resolve().parents[1]
    expected_files = sorted((repository_root / "evals" / "test_skills").glob("**/_expected.json"))

    assert expected_files
    for expected_file in expected_files:
        document = json.loads(expected_file.read_text(encoding="utf-8"))
        validated = validate_expectation_document(document, fixture_dir=expected_file.parent)
        assert validated.evaluation_quality == "legacy_degraded", expected_file


def test_observation_report_never_mutates_ground_truth(tmp_path: Path):
    fixture = tmp_path / "legacy"
    fixture.mkdir()
    (fixture / "SKILL.md").write_text("# Legacy\n", encoding="utf-8")
    expected_file = fixture / "_expected.json"
    expected_file.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "evaluation_quality": "legacy_degraded",
                "skill_name": "legacy",
                "expected_safe": True,
                "expected_findings": [],
            }
        ),
        encoding="utf-8",
    )
    before = expected_file.read_bytes()

    class SafeScanner:
        def scan_skill(self, _fixture_dir):
            return SimpleNamespace(
                is_safe=True,
                max_severity=SimpleNamespace(value="SAFE"),
                findings=[],
                analyzers_failed=[],
            )

    report = build_observation_report(tmp_path, scanner=SafeScanner())

    assert report["ground_truth_mutated"] is False
    assert report["attestation_policy"]["accepted_label_sources"] == [
        "agent_labeled",
        "human_reviewed",
        "independent_ollama",
        "public_labeled",
    ]
    assert report["attestation_policy"]["required_hashes"] == [
        "label_evidence_sha256",
        "label_provenance_sha256",
    ]
    assert report["attestation_policy"]["scanner_output_is_ground_truth"] is False
    assert report["error_count"] == 0
    assert expected_file.read_bytes() == before
