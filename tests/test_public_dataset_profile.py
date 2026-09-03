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

from evals.datasets.public_datasets import (
    get_locked_dataset,
    load_dataset_lock,
    validate_quarantine_manifest,
)

PROFILE_PATH = Path(__file__).parents[1] / "evals" / "datasets" / "public-datasets.profile.json"
DATASET_README_PATH = PROFILE_PATH.with_name("README.md")


def test_public_dataset_profile_is_pinned_and_contains_no_raw_samples():
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    lock = load_dataset_lock()

    assert profile["profile_version"] == 1
    assert profile["safety"] == {
        "sample_code_executed": False,
        "raw_content_persisted": False,
        "gated_data_bypassed": False,
        "note": (
            "Public and authorized gated tables were decoded only as inert Parquet, CSV, JSONL, or text data. "
            "No sample code was executed; raw sample and model content remained outside the repository and is not "
            "recorded in this profile."
        ),
    }

    expected_ids = {
        "ProtectSkills/MaliciousSkillBench",
        "Miaow-Lab/OpenSkillRisk",
        "TrustAIRLab/HarmfulSkillBench",
        "ProtectSkills/MaliciousAgentSkillsBench",
        "OpenClaw/clawhub-security-signals",
        "LLM-LAT/harmful-dataset",
        "uiuc-kang-lab/InjecAgent",
        "SoheilKhodayari/in_page_prompt_injection_pub",
        "InjecGuard/InjecGuard",
    }
    observed = {dataset["id"]: dataset for dataset in profile["datasets"]}
    assert observed.keys() == expected_ids

    for dataset_id, dataset in observed.items():
        assert dataset["revision_verified"] is True
        assert dataset["revision"] == get_locked_dataset(dataset_id, lock)["revision"]
        assert "sample" not in dataset
        assert "raw_content" not in dataset

    malicious_skill_bench = observed["ProtectSkills/MaliciousSkillBench"]
    locked_malicious_skill_bench = get_locked_dataset("ProtectSkills/MaliciousSkillBench", lock)
    locked_track_expectations = locked_malicious_skill_bench["expected"]["track_expectations"]
    assert malicious_skill_bench["materialization"]["blocking_track_expectations"] == locked_track_expectations
    assert malicious_skill_bench["materialization"]["blocking_track_membership"] == {
        track_name: expectation["samples"] for track_name, expectation in locked_track_expectations.items()
    }
    assert locked_malicious_skill_bench["gating"]["blocking"] is True
    assert locked_malicious_skill_bench["integrity"]["hashes_pending"] is False

    harmful_skill_bench = observed["TrustAIRLab/HarmfulSkillBench"]
    locked_harmful_skill_bench = get_locked_dataset("TrustAIRLab/HarmfulSkillBench", lock)
    assert harmful_skill_bench["inspection"] == {
        "methods": [
            "Hugging Face repository API at the pinned revision",
            "authenticated pinned-snapshot acquisition after gated access approval",
            "inert JSONL, CSV, JSON metadata, and text decoding",
            "strict and lenient SkillLoader ingestion audit",
            "full-packs deterministic static diagnostic with CEL shadow",
        ],
        "raw_rows_accessed": True,
        "raw_content_persisted": False,
        "sample_code_executed": False,
    }
    assert harmful_skill_bench["ingestion_audit"] == {
        "population_denominator": 200,
        "strict": {
            "authoritative": True,
            "loaded": 180,
            "errors": 20,
            "missing_skill_document": 1,
            "malformed_or_missing_frontmatter": 19,
        },
        "lenient_supplemental": {
            "authoritative": False,
            "attempted": 20,
            "recovered": 19,
            "errors": 1,
        },
    }
    assert harmful_skill_bench["observed_snapshot"]["complete_snapshot_manifest_pending"] is False
    assert harmful_skill_bench["observed_snapshot"]["declared_evaluation_used_tree_manifest_sha256"] == (
        "5611f603419299312f90d045b843f494801f2baa44369d61c1bbf4995297e089"
    )
    assert harmful_skill_bench["observed_snapshot"]["skill_documents"]["observed"] == 199
    assert [artifact["sha256"] for artifact in harmful_skill_bench["key_artifacts"]] == [
        "e5152c9072a7520d3de99e226dd39518eb05e845b4048a0dec9ebf3fcf71cd90",
        "bc303054e118f93d1d898ddcb97e7cebfd20a94e28d880228cfe61d5876dc794",
    ]
    assert harmful_skill_bench["observed_snapshot"]["observed_repository_manifest_sha256"] == (
        "f2134ac1d911fb564e806d49e551e111440296008310a5759064a1c2ac4ea3dc"
    )
    assert harmful_skill_bench["observed_snapshot"]["evaluation_used_tree_manifest_sha256"] == (
        "3b769e4c6c2aaa63c944682a8273c9ccab1709c7fca6c34b71b5b33fe1400b42"
    )
    assert harmful_skill_bench["observed_snapshot"]["skill_metadata"]["manifest_sha256"] == (
        "18782db19f3fa043f860024d75d1121239d25a3282ca05b4ba1eb62306138748"
    )
    assert harmful_skill_bench["observed_snapshot"]["skill_documents"]["observed_manifest_sha256"] == (
        "1c6064b7ab5806ebe1e74a33ecdd6d0cfaae4a69a01faa2409a6866fc8f03725"
    )
    materialization = harmful_skill_bench["materialization"]
    assert materialization["declared_artifact_count"] == 401
    assert materialization["usable_artifact_count"] == 400
    assert materialization["error_count"] == 1
    assert materialization["denominator_preserved"] == 200
    assert (
        materialization["declared_artifact_manifest_sha256"]
        == locked_harmful_skill_bench["integrity"]["artifact_manifest_sha256"]
    )
    assert (
        materialization["usable_artifact_manifest_sha256"]
        == locked_harmful_skill_bench["integrity"]["materialization"]["usable_artifact_manifest_sha256"]
    )
    assert (
        validate_quarantine_manifest(
            "TrustAIRLab/HarmfulSkillBench",
            materialization["quarantine_records"],
            declared_artifact_manifest_sha256=materialization["declared_artifact_manifest_sha256"],
            manifest_sha256=materialization["quarantine_manifest_sha256"],
            manifest=lock,
        )
        == locked_harmful_skill_bench["integrity"]["materialization"]["quarantine_manifest_sha256"]
    )
    static_evidence = harmful_skill_bench["static_shadow_evidence"]
    assert static_evidence["report_sha256"] == ("ee1a0239b000e00708423be81340b4ddad9ed1f96c50a8d780956851e824cc62")
    assert static_evidence["denominator"] == 200
    assert static_evidence["scanned"] == 199
    assert static_evidence["scan_errors"] == 1
    assert static_evidence["signal_detected"] == 196
    assert static_evidence["actionable_detected"] == 174
    assert static_evidence["blocking_detected"] == 160
    assert static_evidence["harmful_content_detected"] == 0
    assert static_evidence["cel"] == {
        "mode": "shadow",
        "runtime": "cel-go",
        "runtime_version": "v0.32.0;helper=source-tree",
        "expression_set_sha256": "a08e30e5af284299dd10be2b85a7fc5e79c73bbe464f1f6a57f027ab5b1a868f",
        "evaluated": 3283,
        "would_suppress": 88,
        "suppressed": 0,
        "fallbacks": 0,
        "incomplete_projections": 0,
        "circuit_breaker_fallbacks": 0,
    }
    assert harmful_skill_bench["metric_policy"] == {
        "release_blocking": False,
        "authoritative_metrics_eligible": False,
        "all_positive": True,
        "population_denominator": 200,
        "prohibited_metrics": ["precision", "false_positive_rate", "true_negatives", "f1"],
    }
    assert locked_harmful_skill_bench["gating"] == {"blocking": False, "tracks": []}
    assert locked_harmful_skill_bench["integrity"]["hashes_pending"] is False

    malicious_agent_skills = observed["ProtectSkills/MaliciousAgentSkillsBench"]
    locked_malicious_agent_skills = get_locked_dataset("ProtectSkills/MaliciousAgentSkillsBench", lock)
    assert malicious_agent_skills["integrity"] == {
        "artifact_manifest_sha256": "562dfc290f167622b0660950607b054709aff6604b18500cab49662914a49e20",
        "hashes_pending": False,
        "artifact_manifest_pinned": True,
        "artifacts": [
            {
                "path": "skills_dataset.csv",
                "rows": 98380,
                "size_bytes": 10538735,
                "sha256": "76be9193805678dfa7b849c604c0616c0793ece6811c88b6663eefdcd54c7597",
            },
            {
                "path": "malicious_skills.csv",
                "rows": 157,
                "size_bytes": 27434,
                "sha256": "55a3fba6c552c69d3e007012e9a4d0310a11f2e6c8ab29d89a97a0dffcbda037",
            },
        ],
    }
    assert (
        malicious_agent_skills["integrity"]["artifact_manifest_sha256"]
        == (locked_malicious_agent_skills["integrity"]["artifact_manifest_sha256"])
    )
    assert malicious_agent_skills["taxonomy_report"] == {
        "sha256": "bbea2b3cec972d0040205e453bdcc1ccbd67b2c9d425843b427c299aa915f011",
        "size_bytes": 10123,
        "status": "completed",
        "malicious_cases": 157,
        "pattern_categories": 14,
        "pattern_instances": 632,
        "safe_rows_used_as_benign": 0,
        "malicious_skill_bench_deoverlap_status": "not_evaluated",
        "independent_metrics_eligible": False,
    }
    assert "sandbox_confirmed_recall" in locked_malicious_agent_skills["approved_uses"]


def test_malicious_skill_bench_documentation_matches_blocking_lock():
    lock = load_dataset_lock()
    dataset = get_locked_dataset("ProtectSkills/MaliciousSkillBench", lock)
    readme = DATASET_README_PATH.read_text(encoding="utf-8")

    assert dataset["gating"]["blocking"] is True
    assert dataset["integrity"]["hashes_pending"] is False
    assert dataset["integrity"]["artifact_manifest_sha256"] in readme
    for expectation in dataset["expected"]["track_expectations"].values():
        assert f"{expectation['samples']:,}" in readme
    assert "9,740-sample manifest is still pending" not in readme
    assert "dataset remains non-blocking" not in readme


def test_profile_records_verified_raw_openclaw_population_not_stale_viewer_counts():
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    dataset = next(item for item in profile["datasets"] if item["id"] == "OpenClaw/clawhub-security-signals")

    assert dataset["quality"]["total_rows"] == 67453
    assert sum(split["rows"] for split in dataset["splits"].values()) == 67453
    assert dataset["quality"]["labels"] == {
        "clean": 41743,
        "suspicious": 25504,
        "malicious": 206,
    }
    assert "supplemental drift analysis" in dataset["suitability"]["recommended"]
    assert all("nightly" not in use.casefold() for use in dataset["suitability"]["recommended"])
    assert all(len(split["sha256"]) == 64 for split in dataset["splits"].values())


def test_profile_records_pinned_github_supplementals_without_promoting_metric_authority():
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    lock = load_dataset_lock()
    observed = {dataset["id"]: dataset for dataset in profile["datasets"]}
    expected = {
        "uiuc-kang-lab/InjecAgent": {
            "manifest": "c68093ac81a3ff318acda43f959c3899f28d1c48b4cd6f545cec21e624fac9ea",
            "population": 1054,
            "sources": 2,
            "families": 34,
            "templates": 62,
        },
        "SoheilKhodayari/in_page_prompt_injection_pub": {
            "manifest": "6b262dfcf22f58866143079118e6c906cfade60a6781d52f87930127d8926459",
            "population": 15387,
            "sources": 3,
            "families": 25,
            "templates": 363,
        },
        "InjecGuard/InjecGuard": {
            "manifest": "149f7bf2298de3fa237fb6e57f193d5e796ee111046422bea73f47def79774b1",
            "population": 339,
            "sources": 3,
            "families": 12,
            "templates": 339,
        },
    }

    for dataset_id, contract in expected.items():
        dataset = observed[dataset_id]
        locked = get_locked_dataset(dataset_id, lock)
        assert dataset["integrity"]["artifact_manifest_sha256"] == contract["manifest"]
        assert dataset["integrity"]["artifact_manifest_sha256"] == locked["integrity"]["artifact_manifest_sha256"]
        assert dataset["integrity"]["hashes_pending"] is False
        assert dataset["integrity"]["artifact_manifest_pinned"] is True
        assert dataset["metric_policy"]["release_blocking"] is False
        assert dataset["metric_policy"]["authoritative_metrics_eligible"] is False
        assert dataset["grouping"]["source_groups"] == contract["sources"]
        assert dataset["grouping"]["structural_families"] == contract["families"]
        assert dataset["grouping"]["lexical_templates"] == contract["templates"]

    assert (
        observed["uiuc-kang-lab/InjecAgent"]["population"]["evaluated_rows"]
        == expected["uiuc-kang-lab/InjecAgent"]["population"]
    )
    assert (
        observed["SoheilKhodayari/in_page_prompt_injection_pub"]["population"]["validated_fp_zero_rows"]
        == expected["SoheilKhodayari/in_page_prompt_injection_pub"]["population"]
    )
    assert observed["SoheilKhodayari/in_page_prompt_injection_pub"]["grouping"]["dedup_relations"] == {
        "canonical": 1101,
        "exact_duplicate": 14267,
        "normalized_duplicate": 19,
    }
    assert observed["SoheilKhodayari/in_page_prompt_injection_pub"]["population"] == {
        "validated_fp_zero_rows": 15387,
        "unique_injection_ids": 15387,
        "unique_exact_prompts": 1120,
        "unique_upstream_normalized_field_values": 537,
        "adapter_normalized_content_groups": 1101,
        "adapter_digit_abstracted_template_groups": 1100,
    }
    assert (
        "base_control_differential_signal_recall"
        in observed["uiuc-kang-lab/InjecAgent"]["metric_policy"]["allowed_metrics"]
    )
    notinject = observed["InjecGuard/InjecGuard"]
    assert notinject["population"]["total_rows"] == expected["InjecGuard/InjecGuard"]["population"]
    assert notinject["metric_policy"]["package_benign_fpr_eligible"] is False
    assert "package_benign_false_positive_rate" in notinject["metric_policy"]["prohibited_metrics"]

    serialized = json.dumps({dataset_id: observed[dataset_id] for dataset_id in expected}, sort_keys=True)
    assert "Ignore all previous instructions" not in serialized
    assert "Can I ignore this warning" not in serialized
