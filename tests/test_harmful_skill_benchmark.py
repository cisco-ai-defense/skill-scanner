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
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from evals.datasets.harmful_skill_bench import (
    DATASET_ID,
    DEV_SELECTION,
    EXPECTED_CATEGORIES,
    EXPECTED_PLATFORM_COUNTS,
    EXPECTED_POPULATION,
    HELD_BACK_SELECTION,
    HarmfulSkillBenchError,
    audit_ingestion,
    load_harmful_skill_snapshot,
)
from evals.datasets.public_datasets import (
    get_locked_dataset,
    load_dataset_lock,
    validate_quarantine_manifest,
)
from evals.runners.harmful_skill_benchmark import (
    CLASSIFIER_SCHEMA,
    CLASSIFIER_SYSTEM,
    META_SYSTEM,
    LocalOllamaClient,
    ModelResponse,
    PolicyBenchmarkError,
    StructuredOutputError,
    _invoke_structured,
    loopback_network_guard,
    main,
    run_harmful_skill_benchmark,
    run_lenient_static_scan,
)


def _revision() -> str:
    return get_locked_dataset(DATASET_ID, load_dataset_lock())["revision"]


def test_pinned_supplemental_contract_preserves_the_all_positive_denominator():
    lock = load_dataset_lock()
    dataset = get_locked_dataset(DATASET_ID, lock)
    profile_path = Path(__file__).parents[1] / "evals" / "datasets" / "public-datasets.profile.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    observed = next(item for item in profile["datasets"] if item["id"] == DATASET_ID)

    assert dataset["integrity"]["artifact_manifest_sha256"] == (
        "5611f603419299312f90d045b843f494801f2baa44369d61c1bbf4995297e089"
    )
    assert dataset["integrity"]["hashes_pending"] is False
    assert dataset["integrity"]["materialization"]["declared_artifact_count"] == 401
    assert dataset["integrity"]["materialization"]["usable_artifact_count"] == 400
    assert dataset["integrity"]["materialization"]["error_count"] == 1
    assert dataset["gating"] == {"blocking": False, "tracks": []}
    assert dataset["download_policy"] == "manual_research_only"
    assert dataset["expected"]["row_counts"] == {"default/test": EXPECTED_POPULATION}
    assert dataset["expected"]["schemas"]["default"]["exact_fields"] == [
        "anon_id",
        "platform",
        "category",
        "tier",
        "name",
        "description",
        "selected_task",
    ]
    assert {
        "release_authoritative_metric",
        "benign_precision_or_false_positive_rate_claim",
        "f1_claim",
        "automatic_download",
        "execute_samples",
    } <= set(dataset["prohibited_uses"])

    materialization = observed["materialization"]
    assert materialization["denominator_preserved"] == EXPECTED_POPULATION
    assert (
        validate_quarantine_manifest(
            DATASET_ID,
            materialization["quarantine_records"],
            declared_artifact_manifest_sha256=materialization["declared_artifact_manifest_sha256"],
            manifest_sha256=materialization["quarantine_manifest_sha256"],
            manifest=lock,
        )
        == dataset["integrity"]["materialization"]["quarantine_manifest_sha256"]
    )
    assert observed["static_shadow_evidence"]["denominator"] == EXPECTED_POPULATION
    assert observed["static_shadow_evidence"]["scan_errors"] == 1
    assert observed["metric_policy"] == {
        "release_blocking": False,
        "authoritative_metrics_eligible": False,
        "all_positive": True,
        "population_denominator": EXPECTED_POPULATION,
        "prohibited_metrics": ["precision", "false_positive_rate", "true_negatives", "f1"],
    }


def _snapshot(tmp_path: Path) -> Path:
    root = tmp_path / "hsb"
    skills = root / "skills"
    tasks_dir = root / "eval_tasks"
    skills.mkdir(parents=True)
    tasks_dir.mkdir()

    selected = dict([*DEV_SELECTION, *HELD_BACK_SELECTION])
    identifiers: list[tuple[str, str]] = []
    for category in EXPECTED_CATEGORIES:
        identifiers.append((category, selected[category]))
        identifiers.extend((category, f"{category.lower()}-fixture-{index}") for index in range(1, 10))
    assert len(identifiers) == EXPECTED_POPULATION

    platforms = [
        *("clawhub" for _ in range(EXPECTED_PLATFORM_COUNTS["clawhub"])),
        *("original" for _ in range(EXPECTED_PLATFORM_COUNTS["original"])),
        *("skillsrest" for _ in range(EXPECTED_PLATFORM_COUNTS["skillsrest"])),
    ]
    task_rows = []
    for (category, anon_id), platform in zip(identifiers, platforms, strict=True):
        tier = "tier2" if category.startswith("H") else "tier1"
        directory = skills / platform / anon_id
        directory.mkdir(parents=True)
        metadata = {"anon_id": anon_id, "platform": platform, "category": category, "tier": tier}
        (directory / "_meta.json").write_text(json.dumps(metadata), encoding="utf-8")
        (directory / "SKILL.md").write_text(
            f"---\nname: {anon_id}\ndescription: inert fixture {anon_id}\n---\nDocumentation only.\n",
            encoding="utf-8",
        )
        task_rows.append(
            {
                **metadata,
                "name": anon_id,
                "description": f"fixture description {anon_id}",
                "selected_task": f"PRIVATE_TASK_MARKER_{anon_id}",
            }
        )
    (tasks_dir / "reviewed_tasks.jsonl").write_text(
        "".join(json.dumps(row) + "\n" for row in task_rows),
        encoding="utf-8",
    )
    return root


class _PassLoader:
    def load_skill(self, skill_directory: Path, *, lenient: bool = False):
        if not (skill_directory / "SKILL.md").exists():
            raise ValueError("SKILL.md unavailable")
        return object()


class _LocalReviewClient:
    model = "qwen3.5:test"

    def __init__(self):
        self.users: list[str] = []

    def version(self) -> str:
        assert not any(
            os.environ.get(name)
            for name in (
                "OPENAI_API_KEY",
                "ANTHROPIC_API_KEY",
                "SKILL_SCANNER_LLM_API_KEY",
                "SKILL_SCANNER_META_LLM_API_KEY",
            )
        )
        return "test-local"

    def chat(self, *, system, user, schema, seed):
        self.users.append(user)
        if system == CLASSIFIER_SYSTEM:
            value = {
                "decision": "REVIEW",
                "risk_level": "HIGH",
                "harmful_capability": True,
                "policy_domains": ["high_stakes_harm"],
                "confidence": "HIGH",
                "required_safeguards": ["qualified_human_review", "ai_disclosure"],
                "rationale": "PRIVATE_MODEL_REASONING_MUST_NOT_PERSIST",
                "evidence_signals": ["high impact"],
            }
        elif system == META_SYSTEM:
            value = {
                "final_decision": "REVIEW",
                "risk_level": "HIGH",
                "agrees_with_classifier": True,
                "confidence": "HIGH",
                "required_safeguards": ["qualified_human_review", "ai_disclosure"],
                "rationale": "PRIVATE_META_REASONING_MUST_NOT_PERSIST",
            }
        else:  # pragma: no cover - protects the test double contract
            raise AssertionError("unexpected prompt")
        return ModelResponse(
            content=json.dumps(value),
            model=self.model,
            done_reason="stop",
            prompt_tokens=10,
            output_tokens=5,
            elapsed_seconds=0.01,
        )


def test_snapshot_adapter_fixes_disjoint_dev_and_held_back_partitions(tmp_path):
    root = _snapshot(tmp_path)
    snapshot = load_harmful_skill_snapshot(root, revision=_revision())

    assert len(snapshot.samples) == EXPECTED_POPULATION
    assert [(sample.category, sample.anon_id) for sample in snapshot.selected("dev")] == list(DEV_SELECTION)
    assert [(sample.category, sample.anon_id) for sample in snapshot.selected("held-back")] == list(HELD_BACK_SELECTION)
    assert {sample.anon_id for sample in snapshot.selected("dev")}.isdisjoint(
        sample.anon_id for sample in snapshot.selected("held-back")
    )


def test_snapshot_rejects_revision_drift_and_symlinks(tmp_path):
    root = _snapshot(tmp_path)
    with pytest.raises(HarmfulSkillBenchError, match="revision drift"):
        load_harmful_skill_snapshot(root, revision="0" * 40)

    outside = tmp_path / "outside"
    outside.write_text("outside", encoding="utf-8")
    (root / "skills" / "escape").symlink_to(outside)
    with pytest.raises(HarmfulSkillBenchError, match="symbolic link"):
        load_harmful_skill_snapshot(root, revision=_revision())


def test_ingestion_keeps_strict_errors_when_lenient_recovers(tmp_path):
    root = _snapshot(tmp_path)
    snapshot = load_harmful_skill_snapshot(root, revision=_revision())
    recover_id = snapshot.samples[0].anon_id
    missing_id = snapshot.samples[1].anon_id
    (snapshot.samples[1].skill_path).unlink()

    class RecoveringLoader(_PassLoader):
        def load_skill(self, skill_directory: Path, *, lenient: bool = False):
            if not (skill_directory / "SKILL.md").exists():
                raise ValueError("SKILL.md unavailable")
            if skill_directory.name == recover_id and not lenient:
                raise ValueError("malformed frontmatter")
            return object()

    report = audit_ingestion(snapshot, loader=RecoveringLoader())

    assert report["population"] == EXPECTED_POPULATION
    assert report["strict"]["authoritative"] is True
    assert report["strict"]["error_count"] == 2
    assert {item["anon_id"] for item in report["strict"]["errors"]} == {recover_id, missing_id}
    assert report["lenient_supplemental"]["authoritative"] is False
    assert report["lenient_supplemental"]["recovered_count"] == 1
    assert report["lenient_supplemental"]["recovered"][0]["anon_id"] == recover_id
    assert report["lenient_supplemental"]["unresolved_count"] == 1
    assert report["strict"]["loaded"] == 198

    class StaticScanner:
        def scan_skill(self, skill_directory: Path, *, lenient: bool = False):
            assert lenient is True
            finding = SimpleNamespace(
                rule_id="TEST_RULE",
                category=SimpleNamespace(value="harmful_content"),
                severity=SimpleNamespace(value="HIGH"),
                analyzer="static",
                file_path="SKILL.md",
                line_number=1,
            )
            return SimpleNamespace(findings=[finding], analyzers_failed=[])

    static = run_lenient_static_scan(snapshot, report, scanner=StaticScanner())
    assert static["strict_failure_denominator"] == 2
    assert static["scanned"] == 1
    assert static["scan_errors"] == 1
    assert static["actionable_detected"] == 1
    assert static["harmful_content_detected"] == 1


def test_structured_output_gets_one_bounded_compact_repair():
    valid = {
        "decision": "BLOCK",
        "risk_level": "HIGH",
        "harmful_capability": True,
        "policy_domains": ["cyber_abuse"],
        "confidence": "HIGH",
        "required_safeguards": ["none"],
        "rationale": "non-operational classification",
        "evidence_signals": ["prohibited intent"],
    }

    class RepairClient:
        model = "local-test"

        def __init__(self):
            self.calls = 0
            self.users: list[str] = []

        def version(self):
            return "test"

        def chat(self, *, system, user, schema, seed):
            self.calls += 1
            self.users.append(user)
            return (
                ModelResponse(
                    content='{"decision":',
                    model=self.model,
                    done_reason="length",
                    prompt_tokens=1,
                    output_tokens=1,
                    elapsed_seconds=0.01,
                )
                if self.calls == 1
                else ModelResponse(
                    content=json.dumps(valid),
                    model=self.model,
                    done_reason="stop",
                    prompt_tokens=2,
                    output_tokens=2,
                    elapsed_seconds=0.02,
                )
            )

    client = RepairClient()
    parsed, telemetry = _invoke_structured(
        client,
        system=CLASSIFIER_SYSTEM,
        user="UNTRUSTED_DATA = {}",
        schema=CLASSIFIER_SCHEMA,
        seed=1,
    )

    assert parsed == valid
    assert client.calls == 2
    assert "OUTPUT_REPAIR" in client.users[1]
    assert telemetry == {
        "attempts": 2,
        "repair_applied": True,
        "prompt_tokens": 3,
        "output_tokens": 3,
        "elapsed_seconds": 0.03,
        "done_reasons": ["length", "stop"],
    }


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("required_safeguards", ["none", "qualified_human_review"], "mixes 'none'"),
        ("policy_domains", ["none", "cyber_abuse"], "mixes 'none'"),
        ("evidence_signals", ["signal", "signal"], "duplicate items"),
        ("evidence_signals", ["one", "two", "three", "four"], "too many items"),
    ],
)
def test_structured_output_rejects_ambiguous_or_unbounded_arrays(field, value, error):
    invalid = {
        "decision": "BLOCK",
        "risk_level": "HIGH",
        "harmful_capability": True,
        "policy_domains": ["cyber_abuse"],
        "confidence": "HIGH",
        "required_safeguards": ["none"],
        "rationale": "non-operational classification",
        "evidence_signals": ["prohibited intent"],
    }
    invalid[field] = value

    class InvalidClient:
        model = "local-test"

        def chat(self, **_kwargs):
            return ModelResponse(
                content=json.dumps(invalid),
                model=self.model,
                done_reason="stop",
                prompt_tokens=1,
                output_tokens=1,
                elapsed_seconds=0.01,
            )

    with pytest.raises(StructuredOutputError, match=error):
        _invoke_structured(
            InvalidClient(),
            system=CLASSIFIER_SYSTEM,
            user="UNTRUSTED_DATA = {}",
            schema=CLASSIFIER_SCHEMA,
            seed=1,
        )


def test_structured_output_rejects_review_without_safeguards_and_harmful_allow():
    base = {
        "decision": "REVIEW",
        "risk_level": "HIGH",
        "harmful_capability": False,
        "policy_domains": ["high_stakes_harm"],
        "confidence": "HIGH",
        "required_safeguards": ["none"],
        "rationale": "requires review",
        "evidence_signals": ["high impact"],
    }

    class SequenceClient:
        model = "local-test"

        def __init__(self, value):
            self.value = value

        def chat(self, **_kwargs):
            return ModelResponse(
                content=json.dumps(self.value),
                model=self.model,
                done_reason="stop",
                prompt_tokens=1,
                output_tokens=1,
                elapsed_seconds=0.01,
            )

    with pytest.raises(StructuredOutputError, match="must name a real safeguard"):
        _invoke_structured(
            SequenceClient(base),
            system=CLASSIFIER_SYSTEM,
            user="UNTRUSTED_DATA = {}",
            schema=CLASSIFIER_SCHEMA,
            seed=1,
        )

    harmful_allow = {**base, "decision": "ALLOW", "harmful_capability": True, "required_safeguards": ["none"]}
    with pytest.raises(StructuredOutputError, match="cannot assert harmful capability"):
        _invoke_structured(
            SequenceClient(harmful_allow),
            system=CLASSIFIER_SYSTEM,
            user="UNTRUSTED_DATA = {}",
            schema=CLASSIFIER_SCHEMA,
            seed=1,
        )


def test_task_conditioned_runner_is_local_sanitized_and_does_not_persist_raw_content(tmp_path, monkeypatch):
    root = _snapshot(tmp_path)
    for name in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "SKILL_SCANNER_LLM_API_KEY",
        "SKILL_SCANNER_META_LLM_API_KEY",
    ):
        monkeypatch.setenv(name, "must-be-cleared")
    client = _LocalReviewClient()

    report = run_harmful_skill_benchmark(
        root,
        revision=_revision(),
        phase="dev",
        client=client,
        loader=_PassLoader(),
    )

    assert report["status"] == "complete"
    assert report["population_denominator"] == EXPECTED_POPULATION
    assert report["summary"]["samples"] == 5
    assert report["summary"]["classifier_tier_appropriate_recall"] == 1.0
    assert report["summary"]["meta_tier_appropriate_recall"] == 1.0
    assert report["runtime"]["endpoint_scope"] == "loopback-only"
    assert report["runtime"]["hosted_credentials_present_during_run"] is False
    assert len(client.users) == 10
    assert all("UNTRUSTED_DATA" in user for user in client.users)
    rendered = json.dumps(report)
    assert "PRIVATE_TASK_MARKER" not in rendered
    assert "PRIVATE_MODEL_REASONING" not in rendered
    assert "PRIVATE_META_REASONING" not in rendered
    assert "raw_response" not in rendered


def test_ollama_client_and_network_guard_reject_non_loopback():
    with pytest.raises(PolicyBenchmarkError, match="loopback"):
        LocalOllamaClient(base_url="https://api.example.com", model="qwen")

    original = __import__("socket").getaddrinfo
    with loopback_network_guard():
        with pytest.raises(PermissionError, match="non-loopback"):
            __import__("socket").getaddrinfo("example.com", 443)
    assert __import__("socket").getaddrinfo is original


def test_missing_gated_snapshot_is_a_non_blocking_skip(tmp_path):
    output = tmp_path / "report.json"
    assert main(["--snapshot", str(tmp_path / "absent"), "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["status"] == "skipped"
    assert report["non_blocking_supplemental"] is True
    assert "no download was attempted" in report["reason"]
