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

"""Assemble one exact-revision public detection-release evidence artifact."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# Permit direct execution from the repository checkout.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from evals.runners.benchmark_comparison import (  # noqa: E402
    BenchmarkComparisonError,
    compare_repeated_benchmark_reports,
)
from evals.runners.release_gate import (  # noqa: E402
    REQUIRED_REPEATED_RUNS,
    ReleaseGateError,
    _current_bundled_cel_generation,
    _read_json,
    _validate_attested_rule_fixtures,
    _validate_controlled_generation,
    _validate_golden_corpus,
    _validate_report,
    stable_release_output_sha256,
)
from skill_scanner.core.cel.models import CelMode  # noqa: E402

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class EvidenceProductionError(ValueError):
    """Raised when scan outputs cannot form trusted release evidence."""


def active_release_mode() -> tuple[CelMode, tuple[str, ...]]:
    """Use enforce only when at least one bundled CEL rule is promoted."""

    generation = _current_bundled_cel_generation()
    enforced = tuple(sorted(rule_id for rule_id, rollout in generation["rollouts"].items() if rollout == "enforce"))
    return (CelMode.ENFORCE if enforced else CelMode.SHADOW), enforced


def _write_json_new(path: Path, value: Mapping[str, Any]) -> None:
    # Release evidence is content-addressed and machine-consumed.  Canonical
    # separators avoid making bounded artifacts larger solely because the same
    # indentation is repeated across thousands of sample decision references.
    payload = (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _load_report(path: Path, *, label: str) -> Mapping[str, Any]:
    value = _read_json(path, label=label)
    return _validate_report(value, location=label)


def _timestamp(path: Path, previous: datetime | None) -> datetime:
    value = datetime.fromtimestamp(path.stat(follow_symlinks=False).st_mtime, tz=UTC)
    if previous is not None and value <= previous:
        value = previous + timedelta(microseconds=1)
    return value


def assemble_release_evidence(
    *,
    baseline_path: Path,
    candidate_paths: Sequence[Path],
    golden_path: Path,
    output_dir: Path,
    source_revision: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    repository: str,
    artifact_name: str,
    attested_rule_fixtures: Path | None = None,
) -> Mapping[str, Any]:
    """Validate and assemble OFF + exactly five active release-profile runs."""

    if _SHA_RE.fullmatch(source_revision) is None:
        raise EvidenceProductionError("source_revision must be a full lowercase Git commit SHA")
    if len(candidate_paths) != REQUIRED_REPEATED_RUNS:
        raise EvidenceProductionError(f"exactly {REQUIRED_REPEATED_RUNS} active candidate reports are required")
    if not workflow_run_id or not workflow_run_attempt or not repository or not artifact_name:
        raise EvidenceProductionError("workflow run identity and artifact name are required")

    baseline = _load_report(Path(baseline_path), label="producer.baseline")
    candidates = [
        _load_report(Path(path), label=f"producer.candidate[{index}]") for index, path in enumerate(candidate_paths)
    ]
    if baseline["status"] != "passed" or baseline["errors"] or baseline["cel_mode"] != CelMode.OFF.value:
        raise EvidenceProductionError("baseline must be a clean release-profile cel_mode=off report")
    if baseline["profile"] != "release":
        raise EvidenceProductionError("baseline must use the release profile")

    mode, enforced_rule_ids = active_release_mode()
    for index, candidate in enumerate(candidates):
        if candidate["status"] != "passed" or candidate["errors"]:
            raise EvidenceProductionError(f"candidate[{index}] is not a clean completed report")
        if candidate["profile"] != "release" or candidate["cel_mode"] != mode.value:
            raise EvidenceProductionError(f"candidate[{index}] did not use active release mode {mode.value!r}")
        if candidate["producer"]["source_revision"] != source_revision:
            raise EvidenceProductionError(f"candidate[{index}] is not bound to source_revision")
    if baseline["producer"]["source_revision"] != source_revision:
        raise EvidenceProductionError("baseline is not bound to source_revision")

    first_generation, baseline_generation = _validate_controlled_generation(
        candidates[0],
        baseline,
        location="producer",
    )
    first_identity = dict(candidates[0]["evidence_identity"])
    first_producer = dict(candidates[0]["producer"])
    output_digest = stable_release_output_sha256(candidates[0])
    for index, candidate in enumerate(candidates[1:], start=1):
        generation, compared_baseline = _validate_controlled_generation(
            candidate,
            baseline,
            location=f"producer[{index}]",
        )
        if generation != first_generation or compared_baseline != baseline_generation:
            raise EvidenceProductionError(f"candidate[{index}] changes the controlled evidence generation")
        if candidate["evidence_identity"] != first_identity or candidate["producer"] != first_producer:
            raise EvidenceProductionError(f"candidate[{index}] changes evidence or producer identity")
        if stable_release_output_sha256(candidate) != output_digest:
            raise EvidenceProductionError(f"candidate[{index}] changes normalized detection output")

    golden = _validate_golden_corpus(
        _read_json(Path(golden_path), label="producer exact-golden evidence"),
        location="producer.golden-corpus.json",
    )
    rule_fixture_document: Mapping[str, Any] | None = None
    comparison_fixture_rules: Mapping[str, Any] | None = None
    if enforced_rule_ids:
        if attested_rule_fixtures is None:
            raise EvidenceProductionError(
                "enforced bundled rules require committed attested rule-fixture-evidence.json"
            )
        rule_fixture_document = _read_json(attested_rule_fixtures, label="attested rule fixture evidence")
        comparison_fixture_rules = _validate_attested_rule_fixtures(
            rule_fixture_document,
            enforced_rule_ids=set(enforced_rule_ids),
            rules_sha256=first_generation["rules_sha256"],
            expression_set_hash=first_generation["expression_set_hash"],
            golden_manifest_sha256=golden["manifest_sha256"],
        )

    comparison = compare_repeated_benchmark_reports(
        baseline,
        candidates,
        rule_fixture_evidence=comparison_fixture_rules,
        promoted_rule_ids=enforced_rule_ids,
        require_rule_promotion_evidence=bool(enforced_rule_ids),
    )
    if enforced_rule_ids and comparison["status"] != "passed":
        raise EvidenceProductionError("enforced rules do not have passing five-run promotion evidence")

    output_dir = Path(output_dir)
    if output_dir.exists() or output_dir.is_symlink():
        raise EvidenceProductionError("output_dir must be a new non-symlink path")
    if not output_dir.parent.is_dir() or output_dir.parent.is_symlink():
        raise EvidenceProductionError("output_dir parent must be an existing non-symlink directory")
    output_dir = output_dir.parent.resolve(strict=True) / output_dir.name
    output_dir.mkdir(mode=0o700)
    try:
        _write_json_new(output_dir / "baseline.json", baseline)
        _write_json_new(output_dir / "candidate.json", candidates[0])
        _write_json_new(output_dir / "golden-corpus.json", golden)

        runs: list[dict[str, Any]] = []
        previous: datetime | None = None
        for index, (path, candidate) in enumerate(zip(candidate_paths, candidates, strict=True), start=1):
            completed = _timestamp(Path(path), previous)
            previous = completed
            runs.append(
                {
                    "run_id": f"{workflow_run_id}.{workflow_run_attempt}.{index}",
                    "completed_at": completed.isoformat().replace("+00:00", "Z"),
                    "status": candidate["status"],
                    "evidence_identity": dict(candidate["evidence_identity"]),
                    "golden_manifest_sha256": golden["manifest_sha256"],
                    "output_sha256": stable_release_output_sha256(candidate),
                }
            )
        _write_json_new(output_dir / "repeated-runs.json", {"schema_version": 1, "runs": runs})
        _write_json_new(output_dir / "repeated-comparison.json", comparison)

        if rule_fixture_document is not None:
            _write_json_new(output_dir / "rule-fixture-evidence.json", rule_fixture_document)
        promotion = {
            "schema_version": 1,
            "active_mode": mode.value,
            "active_runs": REQUIRED_REPEATED_RUNS,
            "enforced_rule_ids": list(enforced_rule_ids),
            "rule_fixture_attestation_required": bool(enforced_rule_ids),
            "rule_fixture_attestation_present": rule_fixture_document is not None,
            "repeated_comparison_status": comparison["status"],
        }
        _write_json_new(output_dir / "promotion-status.json", promotion)
        provenance = {
            "schema_version": 1,
            "status": "release_evidence",
            "shipping": True,
            "analyzer_profile": "static-core-no-llm-no-osv",
            "network_policy": "os-egress-denied-ipv4-ipv6",
            "credentials_present": False,
            "artifact_name": artifact_name,
            "repository": repository,
            "source_revision": source_revision,
            "workflow_run_id": workflow_run_id,
            "workflow_run_attempt": workflow_run_attempt,
            "dataset_id": candidates[0]["dataset"]["id"],
            "dataset_revision": candidates[0]["dataset"]["revision"],
            "source_artifact_manifest_sha256": candidates[0]["dataset"]["source_artifact_manifest_sha256"],
            "snapshot_sha256": candidates[0]["evidence_identity"]["snapshot_sha256"],
            "build_sha256": candidates[0]["producer"]["build_sha256"],
            "rules_sha256": candidates[0]["producer"]["rules_sha256"],
            "expression_set_hash": candidates[0]["evidence_identity"]["expression_set_hash"],
            "cel_mode": mode.value,
            "normalized_output_sha256": output_digest,
            "golden_manifest_sha256": golden["manifest_sha256"],
        }
        _write_json_new(output_dir / "evidence-provenance.json", provenance)
    except BaseException:
        shutil.rmtree(output_dir)
        raise
    return provenance


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble exact-SHA detection release evidence")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("active-mode", help="print shadow or enforce for the bundled generation")
    assemble = subparsers.add_parser("assemble", help="validate and assemble one release artifact")
    assemble.add_argument("--baseline", type=Path, required=True)
    assemble.add_argument("--candidate", type=Path, action="append", required=True)
    assemble.add_argument("--golden", type=Path, required=True)
    assemble.add_argument("--output-dir", type=Path, required=True)
    assemble.add_argument("--source-revision", required=True)
    assemble.add_argument("--workflow-run-id", required=True)
    assemble.add_argument("--workflow-run-attempt", required=True)
    assemble.add_argument("--repository", required=True)
    assemble.add_argument("--artifact-name", required=True)
    assemble.add_argument("--attested-rule-fixtures", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "active-mode":
            print(active_release_mode()[0].value)
            return 0
        provenance = assemble_release_evidence(
            baseline_path=args.baseline,
            candidate_paths=args.candidate,
            golden_path=args.golden,
            output_dir=args.output_dir,
            source_revision=args.source_revision,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            repository=args.repository,
            artifact_name=args.artifact_name,
            attested_rule_fixtures=args.attested_rule_fixtures,
        )
    except (BenchmarkComparisonError, EvidenceProductionError, ReleaseGateError, OSError) as exc:
        print(f"release evidence production failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(provenance, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
