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

import copy
import hashlib
import json
import stat
from pathlib import Path

import pytest

import evals.datasets.public_datasets as dataset_inputs
from evals.datasets.public_datasets import (
    LOCKED_DATASET_IDS,
    DatasetLockError,
    DatasetSchemaError,
    UnsafeSampleError,
    artifact_manifest_sha256,
    get_locked_dataset,
    load_dataset_lock,
    locked_split_protocols,
    materialize_locked_skill_row,
    materialize_skill_files,
    quarantine_manifest_sha256,
    sample_metadata_manifest_sha256,
    validate_artifact_manifest,
    validate_locked_row,
    validate_quarantine_manifest,
    validate_sample_metadata_manifest,
    validate_snapshot_metadata,
    validate_source_artifact_manifest,
    validated_portable_relative_path,
)


def _bundle(path: str, content: str = "print('static only')\n") -> dict:
    encoded = content.encode("utf-8")
    return {
        "path": path,
        "content": content,
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "sizeBytes": len(encoded),
    }


def _row_for_schema(dataset_id: str, schema_name: str) -> dict:
    manifest = load_dataset_lock()
    dataset = get_locked_dataset(dataset_id, manifest)
    fields = dataset["expected"]["schemas"][schema_name]["exact_fields"]
    return {field: None for field in fields}


def test_lock_contains_pinned_approved_datasets():
    manifest = load_dataset_lock()
    datasets = {dataset["id"]: dataset for dataset in manifest["datasets"]}

    assert LOCKED_DATASET_IDS == datasets.keys()
    assert datasets["ProtectSkills/MaliciousSkillBench"]["revision"] == ("d4b42ce5766a6e0359c987cf59c1007cb3795a90")
    malicious_skill_bench = datasets["ProtectSkills/MaliciousSkillBench"]
    assert malicious_skill_bench["gating"]["blocking"] is True
    assert malicious_skill_bench["integrity"]["artifact_manifest_sha256"] == (
        "ae542800a95a893a0ae724bdc625d5a1e19d81ff08ae1f846ddb54d77bfb0b9a"
    )
    assert malicious_skill_bench["integrity"]["hashes_pending"] is False
    assert malicious_skill_bench["integrity"]["sample_metadata_manifest_format"] == "sample-metadata-splits-v2"
    assert malicious_skill_bench["integrity"]["sample_metadata_manifest_sha256"] == (
        "6a284d9a181ae07179f2cc3ff98f64f14787dadc1ebde6c0dd86e78f4f55bc7a"
    )
    assert malicious_skill_bench["integrity"]["sample_metadata_grouping"] == {
        "protocol_contracts": {
            "m_structural_disjoint": "malicious_structural_family_partition_pure",
            "source_disjoint": "test_source_disjoint_from_non_test",
        },
        "unsupported_dimensions": [
            "actor_campaign_id",
            "lexical_template_id",
            "parent_sample_id",
            "repository_id",
        ],
        "verified_dimensions": [
            "exact_hash",
            "normalized_hash",
            "provenance",
            "source_id",
            "source_ids",
            "source_pointer",
            "structural_family_id",
            "text_origin_source_id",
        ],
    }
    assert locked_split_protocols(malicious_skill_bench) == ("m_structural_disjoint", "source_disjoint")
    assert malicious_skill_bench["expected"]["track_expectations"] == {
        "core-only-source-disjoint": {
            "samples": 1384,
            "malicious": 839,
            "benign": 545,
            "population_sha256": "e77564f010fe55ee368af237fabc89b94ca308bd0b3a8c49f052716609f89399",
        },
    }
    assert malicious_skill_bench["gating"]["tracks"] == [
        {
            "name": "core-only-source-disjoint",
            "detector_profile": "core_only",
            "protocol": "source_disjoint",
            "partition": "test",
        }
    ]
    assert datasets["ProtectSkills/MaliciousSkillBench"]["integrity"]["source_artifact_manifest_sha256"] == (
        "3d64779dc972759ede61717ac5cc7f4e87289add8feabff1e83c4289094ce300"
    )
    harmful_skill_bench = datasets["TrustAIRLab/HarmfulSkillBench"]
    assert harmful_skill_bench["revision"] == "0a30e25f20a391e1b6956c55d6806867944c2232"
    assert harmful_skill_bench["integrity"]["artifact_manifest_sha256"] == (
        "5611f603419299312f90d045b843f494801f2baa44369d61c1bbf4995297e089"
    )
    assert harmful_skill_bench["integrity"]["hashes_pending"] is False
    assert harmful_skill_bench["integrity"]["materialization"] == {
        "declared_artifact_count": 401,
        "usable_artifact_count": 400,
        "error_count": 1,
        "usable_artifact_manifest_sha256": ("3b769e4c6c2aaa63c944682a8273c9ccab1709c7fca6c34b71b5b33fe1400b42"),
        "quarantine_manifest_sha256": ("d2e17d3093dcca780bad35c49858abc77e9fba2ab32e5a0646309c345007beda"),
    }
    assert harmful_skill_bench["gating"] == {"blocking": False, "tracks": []}
    assert harmful_skill_bench["download_policy"] == "manual_research_only"
    assert {
        "automatic_download",
        "release_authoritative_metric",
        "benign_precision_or_false_positive_rate_claim",
        "f1_claim",
        "execute_samples",
    }.issubset(harmful_skill_bench["prohibited_uses"])
    assert harmful_skill_bench["expected"] == {
        "row_counts": {"default/test": 200},
        "schemas": {
            "default": {
                "exact_fields": [
                    "anon_id",
                    "platform",
                    "category",
                    "tier",
                    "name",
                    "description",
                    "selected_task",
                ]
            }
        },
    }
    assert datasets["OpenClaw/clawhub-security-signals"]["gating"]["blocking"] is False
    assert datasets["OpenClaw/clawhub-security-signals"]["download_policy"] == "scheduled_or_manual"
    assert datasets["LLM-LAT/harmful-dataset"]["download_policy"] == "prohibited"
    assert datasets["uiuc-kang-lab/InjecAgent"]["revision"] == ("f19c9f2c79a41046eb13c03c51a24c567a8ffa07")
    assert datasets["SoheilKhodayari/in_page_prompt_injection_pub"]["license"] == {
        "spdx": "CC-BY-4.0",
        "code_spdx": "AGPL-3.0-only",
        "scope": ("Sanitized public dataset is CC-BY-4.0; accompanying software and analysis code are AGPL-3.0-only."),
    }
    assert datasets["InjecGuard/InjecGuard"]["revision"] == ("cb1531f36bffb38b6493438217b36cda8875da8a")
    assert all(
        not dataset["gating"]["blocking"] for dataset in datasets.values() if dataset["access"].startswith("gated")
    )
    assert all("execute_samples" in dataset["prohibited_uses"] for dataset in datasets.values())
    pinned_supplemental_manifests = {
        "ProtectSkills/MaliciousAgentSkillsBench": ("562dfc290f167622b0660950607b054709aff6604b18500cab49662914a49e20"),
        "uiuc-kang-lab/InjecAgent": "c68093ac81a3ff318acda43f959c3899f28d1c48b4cd6f545cec21e624fac9ea",
        "SoheilKhodayari/in_page_prompt_injection_pub": (
            "6b262dfcf22f58866143079118e6c906cfade60a6781d52f87930127d8926459"
        ),
        "InjecGuard/InjecGuard": "149f7bf2298de3fa237fb6e57f193d5e796ee111046422bea73f47def79774b1",
    }
    for dataset_id, digest in pinned_supplemental_manifests.items():
        dataset = datasets[dataset_id]
        assert dataset["integrity"]["repository_commit"] == dataset["revision"]
        assert dataset["integrity"]["artifact_manifest_required"] is True
        assert dataset["integrity"]["artifact_manifest_sha256"] == digest
        assert dataset["integrity"]["hashes_pending"] is False
        assert dataset["gating"] == {"blocking": False, "tracks": []}
        assert "release_authoritative_metric" in dataset["prohibited_uses"]

    malicious_agent_skills = datasets["ProtectSkills/MaliciousAgentSkillsBench"]
    assert "sandbox_confirmed_recall" in malicious_agent_skills["approved_uses"]
    assert malicious_agent_skills["expected"]["schemas"] == {
        "skills_dataset": {
            "exact_fields": ["source", "repo", "skill_name", "classification", "url"],
        },
        "malicious_skills": {
            "exact_fields": ["source", "repo", "skill_name", "classification", "Pattern", "Severity"],
        },
    }

    still_pending = set(datasets) - {
        "ProtectSkills/MaliciousSkillBench",
        "TrustAIRLab/HarmfulSkillBench",
        *pinned_supplemental_manifests,
    }
    assert all(
        datasets[dataset_id]["integrity"]["repository_commit"] == datasets[dataset_id]["revision"]
        and datasets[dataset_id]["integrity"]["artifact_manifest_required"] is True
        and datasets[dataset_id]["integrity"]["artifact_manifest_sha256"] is None
        and datasets[dataset_id]["integrity"]["hashes_pending"] is True
        for dataset_id in still_pending
    )

    projection_fields = {
        "dataset_id",
        "sample_id",
        "source_id",
        "repository_group_id",
        "structural_family_id",
        "lexical_template_id",
        "benchmark_labels",
        "split",
        "parent_sample_id",
        "split_inherited_from",
        "dedup_parent_id",
        "dedup_relation",
        "content_sha256",
        "normalized_content_sha256",
        "lexical_template_sha256",
        "control_content_sha256",
        "trigger_count",
    }
    prompt_injection_projection_datasets = {
        "uiuc-kang-lab/InjecAgent",
        "SoheilKhodayari/in_page_prompt_injection_pub",
        "InjecGuard/InjecGuard",
    }
    for dataset_id in prompt_injection_projection_datasets:
        assert set(datasets[dataset_id]["expected"]["schemas"]["evaluation_projection"]["exact_fields"]) == (
            projection_fields
        )
    assert datasets["uiuc-kang-lab/InjecAgent"]["expected"]["row_counts"] == {
        "base/direct_harm": 510,
        "base/data_stealing": 544,
        "enhanced/direct_harm": 510,
        "enhanced/data_stealing": 544,
    }
    assert datasets["SoheilKhodayari/in_page_prompt_injection_pub"]["expected"]["row_counts"] == {
        "sanitized/dataset_tp": 15387
    }
    assert datasets["InjecGuard/InjecGuard"]["expected"]["row_counts"] == {
        "notinject/one": 113,
        "notinject/two": 113,
        "notinject/three": 113,
    }
    assert "package_level_benign_fpr_denominator" in datasets["InjecGuard/InjecGuard"]["prohibited_uses"]

    profile_path = dataset_inputs.LOCK_FILE.with_name("public-datasets.profile.json")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile_entry = next(
        dataset for dataset in profile["datasets"] if dataset["id"] == "ProtectSkills/MaliciousSkillBench"
    )
    assert (
        profile_entry["source_artifact_manifest_sha256"]
        == datasets["ProtectSkills/MaliciousSkillBench"]["integrity"]["source_artifact_manifest_sha256"]
    )
    materialization = profile_entry["materialization"]
    locked_materialization = malicious_skill_bench["integrity"]["materialization"]
    assert (
        materialization["sample_metadata_manifest_format"]
        == malicious_skill_bench["integrity"]["sample_metadata_manifest_format"]
    )
    assert (
        materialization["sample_metadata_manifest_sha256"]
        == malicious_skill_bench["integrity"]["sample_metadata_manifest_sha256"]
    )
    assert materialization["declared_artifact_count"] == locked_materialization["declared_artifact_count"] == 9740
    assert materialization["usable_artifact_count"] == locked_materialization["usable_artifact_count"] == 9737
    assert materialization["error_count"] == locked_materialization["error_count"] == 3
    assert (
        materialization["usable_artifact_manifest_sha256"] == locked_materialization["usable_artifact_manifest_sha256"]
    )
    assert (
        validate_quarantine_manifest(
            "ProtectSkills/MaliciousSkillBench",
            materialization["quarantine_records"],
            declared_artifact_manifest_sha256=materialization["declared_artifact_manifest_sha256"],
            manifest_sha256=materialization["quarantine_manifest_sha256"],
            manifest=manifest,
        )
        == locked_materialization["quarantine_manifest_sha256"]
    )
    assert all(
        record["splits"] == {"m_structural_disjoint": "train", "source_disjoint": "train"}
        for record in materialization["quarantine_records"]
    )
    assert (
        validate_source_artifact_manifest(
            "ProtectSkills/MaliciousSkillBench",
            profile_entry["source_artifacts"],
            manifest=manifest,
        )
        == datasets["ProtectSkills/MaliciousSkillBench"]["integrity"]["source_artifact_manifest_sha256"]
    )
    tampered_source_artifacts = copy.deepcopy(profile_entry["source_artifacts"])
    tampered_source_artifacts[0]["sha256"] = "0" * 64
    with pytest.raises(DatasetSchemaError, match="source artifact manifest does not match"):
        validate_source_artifact_manifest(
            "ProtectSkills/MaliciousSkillBench",
            tampered_source_artifacts,
            manifest=manifest,
        )

    harmful_profile = next(
        dataset for dataset in profile["datasets"] if dataset["id"] == "TrustAIRLab/HarmfulSkillBench"
    )
    harmful_materialization = harmful_profile["materialization"]
    assert harmful_materialization["denominator_preserved"] == 200
    assert harmful_materialization["declared_artifact_count"] == 401
    assert harmful_materialization["usable_artifact_count"] == 400
    assert harmful_materialization["error_count"] == 1
    assert (
        harmful_materialization["declared_artifact_manifest_sha256"]
        == harmful_skill_bench["integrity"]["artifact_manifest_sha256"]
    )
    assert (
        harmful_materialization["usable_artifact_manifest_sha256"]
        == harmful_skill_bench["integrity"]["materialization"]["usable_artifact_manifest_sha256"]
    )
    assert (
        harmful_materialization["quarantine_manifest_sha256"]
        == harmful_skill_bench["integrity"]["materialization"]["quarantine_manifest_sha256"]
    )
    assert (
        validate_quarantine_manifest(
            "TrustAIRLab/HarmfulSkillBench",
            harmful_materialization["quarantine_records"],
            declared_artifact_manifest_sha256=harmful_materialization["declared_artifact_manifest_sha256"],
            manifest_sha256=harmful_materialization["quarantine_manifest_sha256"],
            manifest=manifest,
        )
        == harmful_skill_bench["integrity"]["materialization"]["quarantine_manifest_sha256"]
    )
    assert harmful_materialization["quarantine_records"] == [
        {
            "benchmark_id": "clawhub_d2bee9b8",
            "path": "skills/clawhub/clawhub_d2bee9b8/SKILL.md",
            "label": "malicious",
            "source_id": "clawhub",
            "structural_family_id": "P6",
            "splits": {},
            "sha256": "f1e059a8aa4fb57b059a85918f17c577ff454638e620b9803589b6fc4841725d",
            "size_bytes": 16409,
            "error_code": "ENDPOINT_PROTECTION_QUARANTINE",
        }
    ]


def _write_lock(tmp_path: Path, manifest: dict) -> Path:
    path = tmp_path / "datasets.lock.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_lock_validation_rejects_policy_and_manifest_drift(tmp_path):
    manifest = load_dataset_lock()

    unexpected = copy.deepcopy(manifest)
    unexpected["datasets"][0]["typo_field"] = True
    with pytest.raises(DatasetLockError, match="unexpected"):
        load_dataset_lock(_write_lock(tmp_path, unexpected))

    unsafe_download_policy = copy.deepcopy(manifest)
    unsafe_download_policy["datasets"][0]["download_policy"] = "automatic_pull_request_download"
    with pytest.raises(DatasetLockError, match="download_policy must be one of"):
        load_dataset_lock(_write_lock(tmp_path, unsafe_download_policy))

    missing = copy.deepcopy(manifest)
    missing["datasets"] = [dataset for dataset in missing["datasets"] if dataset["id"] != "InjecGuard/InjecGuard"]
    with pytest.raises(DatasetLockError, match="missing approved entries"):
        load_dataset_lock(_write_lock(tmp_path, missing))

    unapproved = copy.deepcopy(manifest)
    unapproved_entry = copy.deepcopy(unapproved["datasets"][-1])
    unapproved_entry["id"] = "unreviewed/extra-dataset"
    unapproved["datasets"].append(unapproved_entry)
    with pytest.raises(DatasetLockError, match="unapproved entries"):
        load_dataset_lock(_write_lock(tmp_path, unapproved))
    with pytest.raises(DatasetLockError, match="unapproved entries"):
        get_locked_dataset("ProtectSkills/MaliciousSkillBench", unapproved)

    newly_blocking = copy.deepcopy(manifest)
    next(dataset for dataset in newly_blocking["datasets"] if dataset["id"] == "OpenClaw/clawhub-security-signals")[
        "gating"
    ]["blocking"] = True
    with pytest.raises(DatasetLockError, match="pending artifact hashes cannot block"):
        load_dataset_lock(_write_lock(tmp_path, newly_blocking))

    ready_to_block = copy.deepcopy(manifest)
    malicious_skill_bench = next(
        dataset for dataset in ready_to_block["datasets"] if dataset["id"] == "ProtectSkills/MaliciousSkillBench"
    )
    malicious_skill_bench["integrity"]["hashes_pending"] = False
    malicious_skill_bench["integrity"]["artifact_manifest_sha256"] = "a" * 64
    malicious_skill_bench["gating"]["blocking"] = True
    load_dataset_lock(_write_lock(tmp_path, ready_to_block))

    count_drift = copy.deepcopy(manifest)
    malicious_skill_bench = next(
        dataset for dataset in count_drift["datasets"] if dataset["id"] == "ProtectSkills/MaliciousSkillBench"
    )
    malicious_skill_bench["integrity"]["materialization"]["usable_artifact_count"] -= 1
    with pytest.raises(DatasetLockError, match=r"usable_artifact_count \+ error_count"):
        load_dataset_lock(_write_lock(tmp_path, count_drift))

    track_count_drift = copy.deepcopy(manifest)
    malicious_skill_bench = next(
        dataset for dataset in track_count_drift["datasets"] if dataset["id"] == "ProtectSkills/MaliciousSkillBench"
    )
    malicious_skill_bench["expected"]["track_expectations"].pop("core-only-source-disjoint")
    with pytest.raises(DatasetLockError, match="track_expectations must contain exactly"):
        load_dataset_lock(_write_lock(tmp_path, track_count_drift))

    missing_metadata_format = copy.deepcopy(manifest)
    malicious_skill_bench = next(
        dataset
        for dataset in missing_metadata_format["datasets"]
        if dataset["id"] == "ProtectSkills/MaliciousSkillBench"
    )
    malicious_skill_bench["integrity"].pop("sample_metadata_manifest_format")
    with pytest.raises(DatasetLockError, match="sample_metadata_manifest_format is required"):
        load_dataset_lock(_write_lock(tmp_path, missing_metadata_format))

    missing_metadata_digest = copy.deepcopy(manifest)
    malicious_skill_bench = next(
        dataset
        for dataset in missing_metadata_digest["datasets"]
        if dataset["id"] == "ProtectSkills/MaliciousSkillBench"
    )
    malicious_skill_bench["integrity"].pop("sample_metadata_manifest_sha256")
    with pytest.raises(DatasetLockError, match="sample_metadata_manifest_sha256 is required"):
        load_dataset_lock(_write_lock(tmp_path, missing_metadata_digest))


def test_lock_reader_rejects_symlinks_and_duplicate_json_keys(tmp_path):
    manifest = load_dataset_lock()
    regular = _write_lock(tmp_path, manifest)
    linked = tmp_path / "linked-lock.json"
    linked.symlink_to(regular)
    with pytest.raises(DatasetLockError, match="non-symlink"):
        load_dataset_lock(linked)

    duplicate = tmp_path / "duplicate-lock.json"
    original = regular.read_text(encoding="utf-8")
    duplicate.write_text(
        original.replace('"manifest_version": 1,', '"manifest_version": 1, "manifest_version": 1,'),
        encoding="utf-8",
    )
    with pytest.raises(DatasetLockError, match="duplicate key"):
        load_dataset_lock(duplicate)


def test_snapshot_metadata_rejects_revision_count_and_schema_drift():
    dataset_id = "OpenClaw/clawhub-security-signals"
    revision = "69dcbd323c155312fb000ec89ea0b1efdf6a5757"
    row = _row_for_schema(dataset_id, "default")

    validate_snapshot_metadata(
        dataset_id,
        revision=revision,
        config="default",
        split="test",
        fields=list(row),
        row_count=6747,
    )

    with pytest.raises(DatasetLockError, match="revision drift"):
        validate_snapshot_metadata(
            dataset_id,
            revision="0" * 40,
            config="default",
            split="test",
        )
    with pytest.raises(DatasetSchemaError, match="row-count drift"):
        validate_snapshot_metadata(
            dataset_id,
            revision=revision,
            config="default",
            split="test",
            row_count=1,
        )
    with pytest.raises(DatasetSchemaError, match="schema drift"):
        validate_snapshot_metadata(
            dataset_id,
            revision=revision,
            config="default",
            split="test",
            fields=[*row, "surprise"],
            row_count=6747,
        )
    with pytest.raises(DatasetSchemaError, match="no locked partition"):
        validate_snapshot_metadata(
            dataset_id,
            revision=revision,
            config="default",
            split="unexpected",
        )

    with pytest.raises(DatasetSchemaError, match="row count must be supplied"):
        validate_snapshot_metadata(
            dataset_id,
            revision=revision,
            config="default",
            split="test",
            fields=list(row),
        )
    with pytest.raises(DatasetSchemaError, match="schema fields must be supplied"):
        validate_snapshot_metadata(
            dataset_id,
            revision=revision,
            config="default",
            split="test",
            row_count=6747,
        )

    harmful_skill_fields = _row_for_schema("TrustAIRLab/HarmfulSkillBench", "default")
    validate_snapshot_metadata(
        "TrustAIRLab/HarmfulSkillBench",
        revision="0a30e25f20a391e1b6956c55d6806867944c2232",
        config="default",
        split="test",
        fields=list(harmful_skill_fields),
        row_count=200,
    )
    with pytest.raises(DatasetSchemaError, match="row-count drift"):
        validate_snapshot_metadata(
            "TrustAIRLab/HarmfulSkillBench",
            revision="0a30e25f20a391e1b6956c55d6806867944c2232",
            config="default",
            split="test",
            fields=list(harmful_skill_fields),
            row_count=199,
        )
    with pytest.raises(DatasetSchemaError, match="schema drift"):
        validate_snapshot_metadata(
            "TrustAIRLab/HarmfulSkillBench",
            revision="0a30e25f20a391e1b6956c55d6806867944c2232",
            config="default",
            split="test",
            fields=[*harmful_skill_fields, "skill_text"],
            row_count=200,
        )

    with pytest.raises(DatasetSchemaError, match="no locked row counts"):
        validate_snapshot_metadata(
            "DataDog/malicious-software-packages-dataset",
            revision="2d09839012cedc387ce438debeb77884ac2a242c",
            config="default",
            split="test",
            fields=["name"],
            row_count=1,
        )


def test_artifact_manifest_digest_is_order_independent_and_validated():
    # Use a still-pending supplemental entry so this unit exercises canonical
    # digest construction without conflicting with a reviewed pinned digest.
    dataset_id = "OpenClaw/clawhub-security-signals"
    artifacts = [
        {"path": "data/cases.json", "sha256": "a" * 64, "size_bytes": 123},
        {"path": "SKILL.md", "sha256": "b" * 64, "size_bytes": 456},
    ]

    digest = artifact_manifest_sha256(dataset_id, artifacts)

    assert artifact_manifest_sha256(dataset_id, list(reversed(artifacts))) == digest
    assert validate_artifact_manifest(dataset_id, artifacts, manifest_sha256=digest) == digest
    with pytest.raises(DatasetSchemaError, match="digest mismatch"):
        validate_artifact_manifest(dataset_id, artifacts, manifest_sha256="0" * 64)


def test_artifact_manifest_rejects_normalization_collisions_and_schema_drift():
    dataset_id = "InjecGuard/InjecGuard"
    colliding = [
        {
            "path": "data/caf\N{LATIN SMALL LETTER E WITH ACUTE}.json",
            "sha256": "a" * 64,
            "size_bytes": 1,
        },
        {
            "path": "data/cafe\N{COMBINING ACUTE ACCENT}.json",
            "sha256": "b" * 64,
            "size_bytes": 1,
        },
    ]
    with pytest.raises(DatasetSchemaError, match="normalization-colliding"):
        artifact_manifest_sha256(dataset_id, colliding)

    compatibility_colliding = [
        {"path": "data/a.json", "sha256": "a" * 64, "size_bytes": 1},
        {"path": "data/\N{FULLWIDTH LATIN SMALL LETTER A}.json", "sha256": "b" * 64, "size_bytes": 1},
    ]
    with pytest.raises(DatasetSchemaError, match="normalization-colliding"):
        artifact_manifest_sha256(dataset_id, compatibility_colliding)

    unexpected = [{"path": "data.json", "sha256": "a" * 64, "size_bytes": 1, "url": "https://x"}]
    with pytest.raises(DatasetSchemaError, match="unexpected fields"):
        artifact_manifest_sha256(dataset_id, unexpected)


@pytest.mark.parametrize("path", ["C:/primary.parquet", "aux/con.txt", "aux/name:stream"])
def test_shared_portable_path_validator_rejects_windows_escapes(path: str) -> None:
    with pytest.raises(UnsafeSampleError):
        validated_portable_relative_path(path, allow_root_skill=True, allow_binary=True)


def test_sample_metadata_manifest_binds_all_identity_and_split_fields() -> None:
    dataset_id = "ProtectSkills/MaliciousSkillBench"
    manifest = load_dataset_lock()
    dataset = get_locked_dataset(dataset_id, manifest)
    artifact_digest = dataset["integrity"]["artifact_manifest_sha256"]
    samples = [
        {
            "benchmark_id": "sample-a",
            "category_ids": ["command_execution"],
            "exact_hash": "1" * 64,
            "label": "malicious",
            "normalized_hash": "2" * 64,
            "path": "skills/sample-a",
            "provenance": "unit_test",
            "source_id": "SRC-A",
            "source_ids": ["SRC-A"],
            "source_pointer": "test://SRC-A",
            "splits": {"m_structural_disjoint": "train", "source_disjoint": "test"},
            "structural_family_id": "FAMILY-A",
            "text_origin_source_id": "SRC-A",
        },
        {
            "benchmark_id": "sample-b",
            "category_ids": ["benign"],
            "exact_hash": "3" * 64,
            "label": "benign",
            "normalized_hash": "4" * 64,
            "path": "skills/sample-b",
            "provenance": "unit_test",
            "source_id": "SRC-B",
            "source_ids": ["SRC-B"],
            "source_pointer": "test://SRC-B",
            "splits": {"m_structural_disjoint": "test", "source_disjoint": "train"},
            "structural_family_id": "FAMILY-B",
            "text_origin_source_id": "SRC-B",
        },
    ]
    digest = sample_metadata_manifest_sha256(
        dataset_id,
        samples,
        artifact_manifest_sha256=artifact_digest,
        manifest=manifest,
    )
    assert (
        sample_metadata_manifest_sha256(
            dataset_id,
            list(reversed(samples)),
            artifact_manifest_sha256=artifact_digest,
            manifest=manifest,
        )
        == digest
    )

    mutations = []
    for field, value in (
        ("label", "benign"),
        ("structural_family_id", "FAMILY-TAMPERED"),
        ("category_ids", ["data_exfiltration"]),
        ("exact_hash", "5" * 64),
        ("normalized_hash", "6" * 64),
        ("provenance", "mutated"),
        ("source_pointer", "test://mutated"),
        ("path", "skills/tampered"),
    ):
        tampered = copy.deepcopy(samples)
        tampered[0][field] = value
        mutations.append(tampered)
    tampered_source = copy.deepcopy(samples)
    tampered_source[0].update(
        source_id="SRC-TAMPERED",
        source_ids=["SRC-TAMPERED"],
        text_origin_source_id="SRC-TAMPERED",
    )
    mutations.append(tampered_source)
    tampered_split = copy.deepcopy(samples)
    split_assignments = tampered_split[0]["splits"]
    assert isinstance(split_assignments, dict)
    split_assignments["m_structural_disjoint"] = "validation"
    mutations.append(tampered_split)
    swapped_paths = copy.deepcopy(samples)
    swapped_paths[0]["path"], swapped_paths[1]["path"] = swapped_paths[1]["path"], swapped_paths[0]["path"]
    mutations.append(swapped_paths)

    for tampered in mutations:
        assert (
            sample_metadata_manifest_sha256(
                dataset_id,
                tampered,
                artifact_manifest_sha256=artifact_digest,
                manifest=manifest,
            )
            != digest
        )

    repinned = copy.deepcopy(manifest)
    get_locked_dataset(dataset_id, repinned)["integrity"]["sample_metadata_manifest_sha256"] = digest
    assert (
        validate_sample_metadata_manifest(
            dataset_id,
            samples,
            artifact_manifest_sha256=artifact_digest,
            manifest_sha256=digest,
            manifest=repinned,
        )
        == digest
    )
    with pytest.raises(DatasetSchemaError, match="digest mismatch"):
        validate_sample_metadata_manifest(
            dataset_id,
            mutations[0],
            artifact_manifest_sha256=artifact_digest,
            manifest_sha256=digest,
            manifest=repinned,
        )


def test_sample_metadata_manifest_rejects_missing_locked_split_protocol() -> None:
    manifest = load_dataset_lock()
    dataset = get_locked_dataset("ProtectSkills/MaliciousSkillBench", manifest)
    sample = {
        "benchmark_id": "sample-a",
        "category_ids": ["benign"],
        "exact_hash": "1" * 64,
        "label": "benign",
        "normalized_hash": "2" * 64,
        "path": "skills/sample-a",
        "provenance": "unit_test",
        "source_id": "SRC-A",
        "source_ids": ["SRC-A"],
        "source_pointer": "test://SRC-A",
        "splits": {"source_disjoint": "test"},
        "structural_family_id": "FAMILY-A",
        "text_origin_source_id": "SRC-A",
    }
    with pytest.raises(DatasetSchemaError, match="splits must contain exactly"):
        sample_metadata_manifest_sha256(
            "ProtectSkills/MaliciousSkillBench",
            [sample],
            artifact_manifest_sha256=dataset["integrity"]["artifact_manifest_sha256"],
            manifest=manifest,
        )

    invalid_label = copy.deepcopy(sample)
    invalid_label["splits"]["m_structural_disjoint"] = "train"
    invalid_label["label"] = []
    with pytest.raises(DatasetSchemaError, match="invalid label"):
        sample_metadata_manifest_sha256(
            "ProtectSkills/MaliciousSkillBench",
            [invalid_label],
            artifact_manifest_sha256=dataset["integrity"]["artifact_manifest_sha256"],
            manifest=manifest,
        )


def test_sample_metadata_manifest_enforces_documented_disjoint_group_contracts() -> None:
    manifest = load_dataset_lock()
    dataset = get_locked_dataset("ProtectSkills/MaliciousSkillBench", manifest)

    def sample(
        benchmark_id: str,
        *,
        source_id: str,
        family: str,
        source_split: str,
        structural_split: str,
    ) -> dict:
        return {
            "benchmark_id": benchmark_id,
            "category_ids": ["command_execution"],
            "exact_hash": hashlib.sha256(f"exact:{benchmark_id}".encode()).hexdigest(),
            "label": "malicious",
            "normalized_hash": hashlib.sha256(f"normalized:{benchmark_id}".encode()).hexdigest(),
            "path": f"skills/{benchmark_id}",
            "provenance": "unit_test",
            "source_id": source_id,
            "source_ids": [source_id],
            "source_pointer": f"test://{source_id}",
            "splits": {
                "m_structural_disjoint": structural_split,
                "source_disjoint": source_split,
            },
            "structural_family_id": family,
            "text_origin_source_id": source_id,
        }

    artifact_digest = dataset["integrity"]["artifact_manifest_sha256"]
    with pytest.raises(DatasetSchemaError, match="test sources overlap non-test"):
        sample_metadata_manifest_sha256(
            "ProtectSkills/MaliciousSkillBench",
            [
                sample("one", source_id="SRC-SHARED", family="FAM-1", source_split="test", structural_split="train"),
                sample("two", source_id="SRC-SHARED", family="FAM-2", source_split="train", structural_split="test"),
            ],
            artifact_manifest_sha256=artifact_digest,
            manifest=manifest,
        )

    with pytest.raises(DatasetSchemaError, match="malicious families span partitions"):
        sample_metadata_manifest_sha256(
            "ProtectSkills/MaliciousSkillBench",
            [
                sample("one", source_id="SRC-1", family="FAM-SHARED", source_split="test", structural_split="train"),
                sample("two", source_id="SRC-2", family="FAM-SHARED", source_split="test", structural_split="test"),
            ],
            artifact_manifest_sha256=artifact_digest,
            manifest=manifest,
        )


def test_quarantine_manifest_digest_is_order_independent_and_detects_drift():
    manifest = load_dataset_lock()
    profile_path = dataset_inputs.LOCK_FILE.with_name("public-datasets.profile.json")
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    profile_entry = next(
        dataset for dataset in profile["datasets"] if dataset["id"] == "ProtectSkills/MaliciousSkillBench"
    )
    materialization = profile_entry["materialization"]
    records = materialization["quarantine_records"]
    expected = materialization["quarantine_manifest_sha256"]

    assert (
        quarantine_manifest_sha256(
            "ProtectSkills/MaliciousSkillBench",
            list(reversed(records)),
            declared_artifact_manifest_sha256=materialization["declared_artifact_manifest_sha256"],
            manifest=manifest,
        )
        == expected
    )
    tampered = copy.deepcopy(records)
    tampered[0]["sha256"] = "0" * 64
    with pytest.raises(DatasetSchemaError, match="digest mismatch"):
        validate_quarantine_manifest(
            "ProtectSkills/MaliciousSkillBench",
            tampered,
            declared_artifact_manifest_sha256=materialization["declared_artifact_manifest_sha256"],
            manifest_sha256=expected,
            manifest=manifest,
        )


def test_locked_row_rejects_missing_or_additional_fields():
    dataset_id = "OpenClaw/clawhub-security-signals"
    row = _row_for_schema(dataset_id, "default")
    row["skill_bundle_content"] = []
    validate_locked_row(dataset_id, "default", row)

    row["new_field"] = "drift"
    with pytest.raises(DatasetSchemaError, match="unexpected"):
        validate_locked_row(dataset_id, "default", row)


def test_materialization_creates_non_executable_text_files(tmp_path):
    destination = tmp_path / "sample"
    result = materialize_skill_files(
        skill_md_content="---\nname: sample\ndescription: fixture\n---\n",
        bundle_files=[_bundle("scripts/run.py")],
        destination=destination,
    )

    assert result == destination.resolve()
    assert (destination / "scripts" / "run.py").read_text(encoding="utf-8") == "print('static only')\n"
    assert stat.S_IMODE((destination / "SKILL.md").stat().st_mode) == 0o600
    assert stat.S_IMODE((destination / "scripts" / "run.py").stat().st_mode) == 0o600


def test_materialization_accepts_observed_large_skill_but_keeps_hard_bounds(tmp_path, monkeypatch):
    assert dataset_inputs._MAX_FILE_BYTES == 32 * 1024 * 1024
    assert dataset_inputs._MAX_TOTAL_BYTES == 128 * 1024 * 1024

    observed_maximum = "x" * 21_002_040
    output = materialize_skill_files(
        skill_md_content=observed_maximum,
        bundle_files=[],
        destination=tmp_path / "observed-large-skill",
    )
    assert (output / "SKILL.md").stat().st_size == len(observed_maximum)

    with pytest.raises(DatasetSchemaError, match="file limit"):
        materialize_skill_files(
            skill_md_content="x" * (dataset_inputs._MAX_FILE_BYTES + 1),
            bundle_files=[],
            destination=tmp_path / "too-large-skill",
        )
    assert not (tmp_path / "too-large-skill").exists()

    # Exercise the aggregate boundary with small data rather than allocating
    # another 128 MiB in the pull-request test process.
    monkeypatch.setattr(dataset_inputs, "_MAX_FILE_BYTES", 64)
    monkeypatch.setattr(dataset_inputs, "_MAX_TOTAL_BYTES", 63)
    with pytest.raises(DatasetSchemaError, match="aggregate limit"):
        materialize_skill_files(
            skill_md_content="x" * 32,
            bundle_files=[_bundle("extra.txt", "y" * 32)],
            destination=tmp_path / "too-large-sample",
        )
    assert not (tmp_path / "too-large-sample").exists()


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../escape.py",
        "/absolute.py",
        "C:\\absolute.py",
        "nested\\windows.py",
        "./not-normalized.py",
        "nested//empty.py",
        "SKILL.md",
        "nested/CON.txt",
    ],
)
def test_materialization_rejects_unsafe_paths(tmp_path, unsafe_path):
    with pytest.raises(UnsafeSampleError):
        materialize_skill_files(
            skill_md_content="# Safe fixture\n",
            bundle_files=[_bundle(unsafe_path)],
            destination=tmp_path / "sample",
        )
    assert not (tmp_path / "sample").exists()


def test_materialization_rejects_symlink_metadata_and_destination(tmp_path):
    symlink_entry = {**_bundle("scripts/run.py"), "type": "symlink"}
    with pytest.raises(UnsafeSampleError, match="symlink"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[symlink_entry],
            destination=tmp_path / "sample",
        )

    target = tmp_path / "target"
    target.mkdir()
    destination = tmp_path / "linked"
    destination.symlink_to(target, target_is_directory=True)
    with pytest.raises(UnsafeSampleError, match="non-symlink"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[],
            destination=destination,
        )


def test_materialization_rejects_hash_size_and_case_collisions(tmp_path):
    bad_hash = _bundle("run.py")
    bad_hash["sha256"] = "0" * 64
    with pytest.raises(DatasetSchemaError, match="sha256"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[bad_hash],
            destination=tmp_path / "bad-hash",
        )

    with pytest.raises(UnsafeSampleError, match="case-colliding"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[_bundle("Run.py"), _bundle("run.py")],
            destination=tmp_path / "collision",
        )

    with pytest.raises(UnsafeSampleError, match="case-colliding"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[
                _bundle("caf\N{LATIN SMALL LETTER E WITH ACUTE}.py"),
                _bundle("cafe\N{COMBINING ACUTE ACCENT}.py"),
            ],
            destination=tmp_path / "unicode-collision",
        )

    with pytest.raises(UnsafeSampleError, match="case-colliding"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[
                _bundle("a.py"),
                _bundle("\N{FULLWIDTH LATIN SMALL LETTER A}.py"),
            ],
            destination=tmp_path / "compatibility-collision",
        )


@pytest.mark.parametrize(
    ("path", "content", "message"),
    [
        ("payload.zip", "not really an archive", "unexpected binary or archive"),
        ("payload.dylib", "not really a library", "unexpected binary or archive"),
        ("image.png", "not really an image", "unexpected binary or archive"),
        ("nested/control\x07.py", "text", "control characters"),
        ("nested/trailing. ", "text", "not portable"),
        ("nested/file.py", "contains\x00binary", "binary NUL"),
        ("nested/file.py", "contains\x1bbinary control", "non-text control"),
    ],
)
def test_materialization_rejects_unexpected_file_types_and_binary_content(tmp_path, path, content, message):
    with pytest.raises((DatasetSchemaError, UnsafeSampleError), match=message):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[_bundle(path, content)],
            destination=tmp_path / "sample",
        )
    assert not (tmp_path / "sample").exists()


def test_materialization_rejects_file_directory_prefix_collision(tmp_path):
    with pytest.raises(UnsafeSampleError, match="both a file and a parent"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[_bundle("scripts"), _bundle("scripts/run.py")],
            destination=tmp_path / "sample",
        )


def test_materialization_rejects_symlink_parent(tmp_path):
    real_parent = tmp_path / "real"
    (real_parent / "nested").mkdir(parents=True)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(UnsafeSampleError, match="ancestor must not be a symlink"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[],
            destination=linked_parent / "nested" / "sample",
        )
    assert not (real_parent / "nested" / "sample").exists()


def test_materialization_cleans_partial_destination_on_write_failure(tmp_path, monkeypatch):
    original_write = dataset_inputs._write_new_text
    write_count = 0

    def flaky_write(path, content):
        nonlocal write_count
        write_count += 1
        if write_count == 2:
            raise OSError("simulated filesystem failure")
        original_write(path, content)

    monkeypatch.setattr(dataset_inputs, "_write_new_text", flaky_write)
    destination = tmp_path / "partial"
    with pytest.raises(OSError, match="simulated filesystem failure"):
        materialize_skill_files(
            skill_md_content="# Fixture\n",
            bundle_files=[_bundle("scripts/run.py")],
            destination=destination,
        )
    assert not destination.exists()


def test_locked_openclaw_row_materializes_without_executing(tmp_path):
    dataset_id = "OpenClaw/clawhub-security-signals"
    row = _row_for_schema(dataset_id, "default")
    row["skill_md_content"] = "---\nname: sample\ndescription: fixture\n---\n"
    row["skill_bundle_content"] = [_bundle("scripts/run.py")]

    output = materialize_locked_skill_row(dataset_id, row, tmp_path / "openclaw")

    assert (output / "SKILL.md").is_file()
    assert (output / "scripts" / "run.py").is_file()


def test_locked_malicious_skill_bench_row_requires_typed_text_metadata(tmp_path):
    dataset_id = "ProtectSkills/MaliciousSkillBench"
    row = _row_for_schema(dataset_id, "primary")
    row.update(
        {
            "skill_text": "# Inert benchmark text\n",
            "public_skill_text": None,
            "public_text_sha256": None,
            "text_available": True,
            "text_redacted": False,
            "original_text_withheld": False,
        }
    )

    output = materialize_locked_skill_row(dataset_id, row, tmp_path / "msb")
    assert (output / "SKILL.md").read_text(encoding="utf-8") == "# Inert benchmark text\n"

    malformed = copy.deepcopy(row)
    malformed["text_available"] = "true"
    with pytest.raises(DatasetSchemaError, match="text_available must be boolean"):
        materialize_locked_skill_row(dataset_id, malformed, tmp_path / "malformed-msb")

    inconsistent = copy.deepcopy(row)
    inconsistent["public_text_sha256"] = "0" * 64
    with pytest.raises(DatasetSchemaError, match="must be null without public text"):
        materialize_locked_skill_row(dataset_id, inconsistent, tmp_path / "inconsistent-msb")


def test_unapproved_materializer_is_rejected(tmp_path):
    with pytest.raises(DatasetLockError, match="no approved static materializer"):
        materialize_locked_skill_row("LLM-LAT/harmful-dataset", {}, tmp_path / "excluded")
