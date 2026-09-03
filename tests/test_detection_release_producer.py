# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from evals.datasets.materialize_malicious_skill_bench import (
    DATASET_ID,
    MaterializationError,
    _category_ids,
    _materialize_pinned_text,
    source_artifact_contract,
)
from evals.runners.produce_release_evidence import (
    _write_json_new,
    active_release_mode,
)
from evals.runners.produce_release_evidence import (
    main as release_evidence_main,
)
from evals.runners.public_dataset_benchmark import compact_release_report
from skill_scanner.core.cel.models import CelMode


def test_committed_malicious_skill_bench_source_contract_is_complete() -> None:
    lock, artifacts, profile = source_artifact_contract()

    assert profile["id"] == DATASET_ID
    assert profile["revision"] == "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
    assert profile["source_artifact_manifest_sha256"] == (
        "3d64779dc972759ede61717ac5cc7f4e87289add8feabff1e83c4289094ce300"
    )
    assert [artifact["path"] for artifact in artifacts] == [
        "primary.parquet",
        "metadata.parquet",
        "attack_taxonomy.parquet",
        "impact_taxonomy.parquet",
        "splits/random.parquet",
        "splits/source_balanced_random.parquet",
        "splits/m_structural_disjoint.parquet",
        "splits/source_disjoint.parquet",
        "package_manifest.csv",
        "schema.json",
    ]
    locked = next(dataset for dataset in lock["datasets"] if dataset["id"] == DATASET_ID)
    assert locked["integrity"]["hashes_pending"] is False
    assert locked["integrity"]["materialization"] == {
        "declared_artifact_count": 9740,
        "usable_artifact_count": 9737,
        "error_count": 3,
        "usable_artifact_manifest_sha256": "e1f54bfdfb8489b136601ab5cacdc0ae81802aa2ac3b37ebe0766afdf5cec79b",
        "quarantine_manifest_sha256": "6dcd44640fd28506eed470888272c52b43a8779988a8b8b0efda99f3d8c6ee79",
    }


def test_category_projection_matches_locked_population_contract() -> None:
    assert _category_ids({"attack_category_codes": ["z", "a", "z"]}, "malicious") == ["a", "z"]
    assert _category_ids({"attack_category_codes": []}, "benign") == ["benign"]
    assert _category_ids({"attack_category_codes": []}, "malicious") == ["unclassified_malicious"]
    with pytest.raises(MaterializationError, match="must be an array"):
        _category_ids({"attack_category_codes": "command_execution"}, "malicious")


def test_pinned_text_adapter_is_inert_and_byte_preserving(tmp_path: Path) -> None:
    destination = tmp_path / "sample"
    content = "---\nname: control\ndescription: pinned\n---\n\x02"

    _materialize_pinned_text(destination, content)

    skill = destination / "SKILL.md"
    assert skill.read_bytes() == content.encode("utf-8")
    assert stat.S_IMODE(destination.stat().st_mode) == 0o700
    assert stat.S_IMODE(skill.stat().st_mode) == 0o600
    assert not (skill.stat().st_mode & 0o111)
    with pytest.raises(MaterializationError, match="NUL"):
        _materialize_pinned_text(tmp_path / "nul", "bad\x00text")


def test_compact_release_report_retains_only_cel_and_recovered_outcomes() -> None:
    outcomes = {
        "plain": {
            "label": "benign",
            "scan_error": False,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [{"rule_id": "PLAIN", "severity": "LOW", "cel_decision": None, "category": "x"}],
        },
        "cel": {
            "label": "malicious",
            "scan_error": False,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [
                {
                    "rule_id": "CEL_RULE",
                    "severity": "HIGH",
                    "cel_decision": "keep",
                    "cel_decisions": [
                        {
                            "rule_id": "CEL_RULE",
                            "decision": "keep",
                            "reason": "expression_true",
                            "fact_schema": "v1",
                            "expression_hash": "a" * 64,
                            "pack": "core",
                            "rollout": "shadow",
                            "count": 1,
                        }
                    ],
                    "category": "x",
                }
            ],
        },
        "recovered": {
            "label": "malicious",
            "scan_error": False,
            "recovered_scan_error": True,
            "loader_fallback_code": "INVALID_FRONTMATTER",
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [
                {
                    "rule_id": "SKILL_LOAD_FALLBACK_USED",
                    "severity": "INFO",
                    "cel_decision": None,
                    "cel_decisions": [],
                    "category": "policy_violation",
                }
            ],
        },
        "rejected": {
            "label": "malicious",
            "scan_error": False,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": "SKILL_METADATA_SIZE_LIMIT_EXCEEDED",
            "cel_suppressed": [],
            "findings": [
                {
                    "rule_id": "SKILL_LOAD_REJECTED_LIMIT",
                    "severity": "HIGH",
                    "cel_decision": None,
                    "cel_decisions": [],
                    "category": "policy_violation",
                }
            ],
        },
    }
    group = {"samples": 1, "sample_outcomes": {"plain": outcomes["plain"]}}
    report = {
        "summary": {},
        "tracks": {
            "track": {
                "samples": 4,
                "sample_outcomes": outcomes,
                "per_source": {"source": dict(group)},
                "per_structural_family": {"family": dict(group)},
                "per_category": {"category": dict(group)},
            }
        },
    }

    compact = compact_release_report(report)
    track = compact["tracks"]["track"]
    assert compact["release_evidence"] == {
        "format": "compact-v3",
        "full_sample_outcomes_domain": "skill-scanner-release-sample-outcomes-v1",
        "cel_decision_identity": "track.cel.per_rule",
    }
    assert track["sample_outcomes_count"] == 4
    assert len(track["sample_outcomes_sha256"]) == 64
    assert set(track["sample_outcomes"]) == {"cel", "recovered", "rejected"}
    assert track["sample_outcomes"]["cel"]["findings"] == [
        {
            "rule_id": "CEL_RULE",
            "severity": "HIGH",
            "cel_decision": "keep",
            "cel_decisions": [{"rule_id": "CEL_RULE", "decision": "keep", "count": 1}],
        }
    ]
    assert track["sample_outcomes"]["recovered"]["loader_fallback_code"] == "INVALID_FRONTMATTER"
    assert track["sample_outcomes"]["recovered"]["findings"] == [
        {
            "rule_id": "SKILL_LOAD_FALLBACK_USED",
            "severity": "INFO",
            "cel_decision": None,
            "cel_decisions": [],
        }
    ]
    assert track["sample_outcomes"]["rejected"]["loader_rejection_code"] == ("SKILL_METADATA_SIZE_LIMIT_EXCEEDED")
    assert track["sample_outcomes"]["rejected"]["findings"] == [
        {
            "rule_id": "SKILL_LOAD_REJECTED_LIMIT",
            "severity": "HIGH",
            "cel_decision": None,
            "cel_decisions": [],
        }
    ]
    expected_outcome_fields = {
        "label",
        "scan_error",
        "recovered_scan_error",
        "loader_fallback_code",
        "loader_rejection_code",
        "cel_suppressed",
        "findings",
    }
    assert all(set(outcome) == expected_outcome_fields for outcome in track["sample_outcomes"].values())
    for dimension in ("per_source", "per_structural_family", "per_category"):
        compact_group = next(iter(track[dimension].values()))
        assert "sample_outcomes" not in compact_group
        assert compact_group["sample_outcomes_format"] == "digest-only-v1"


def test_active_release_mode_tracks_bundled_rollouts() -> None:
    mode, enforced = active_release_mode()
    assert mode in {CelMode.SHADOW, CelMode.ENFORCE}
    assert (mode is CelMode.ENFORCE) is bool(enforced)


def test_compact_v3_bounds_representative_repeated_lineage() -> None:
    samples = 1_948
    findings_per_sample = 15
    lineage = {
        "rule_id": "CEL_RULE_WITH_LONG_STABLE_IDENTIFIER",
        "decision": "would_suppress",
        "reason": "shadow_or_rule_rollout",
        "fact_schema": "v1",
        "expression_hash": "a" * 64,
        "pack": "promptguard",
        "rollout": "shadow",
        "count": 1,
    }
    finding = {
        "rule_id": lineage["rule_id"],
        "severity": "HIGH",
        "cel_decision": "would_suppress",
        "cel_decisions": [lineage],
    }
    outcomes = {
        f"sample-{index:04d}": {
            "label": "benign",
            "scan_error": False,
            "recovered_scan_error": False,
            "loader_fallback_code": None,
            "loader_rejection_code": None,
            "cel_suppressed": [],
            "findings": [finding] * findings_per_sample,
        }
        for index in range(samples)
    }
    report = {
        "summary": {},
        "tracks": {
            "representative": {
                "samples": samples,
                "sample_outcomes": outcomes,
                "per_source": {},
                "per_structural_family": {},
                "per_category": {},
            }
        },
    }
    verbose_size = len((json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    compact = compact_release_report(report)
    canonical = (json.dumps(compact, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")

    assert verbose_size > 16 * 1024 * 1024
    assert len(canonical) < 16 * 1024 * 1024
    assert len(canonical) < verbose_size // 2
    decision = compact["tracks"]["representative"]["sample_outcomes"]["sample-0000"]["findings"][0]
    assert decision["cel_decisions"] == [
        {
            "rule_id": "CEL_RULE_WITH_LONG_STABLE_IDENTIFIER",
            "decision": "would_suppress",
            "count": 1,
        }
    ]


def test_release_evidence_writer_uses_canonical_json(tmp_path: Path) -> None:
    destination = tmp_path / "evidence.json"

    _write_json_new(destination, {"z": [2, 1], "a": {"value": True}})

    assert destination.read_bytes() == b'{"a":{"value":true},"z":[2,1]}\n'


def test_release_evidence_cli_requires_attested_fixture_naming(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        release_evidence_main(["assemble", "--help"])

    help_text = capsys.readouterr().out
    assert exc_info.value.code == 0
    assert "--attested-rule-fixtures" in help_text
    assert "--reviewed-rule-fixtures" not in help_text
