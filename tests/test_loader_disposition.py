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
from types import SimpleNamespace

import pytest

from evals.runners.loader_fallback import (
    LoaderFallbackValidationError,
    recognize_loader_disposition,
)
from skill_scanner.core.cel.models import CelMode
from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner


def _metadata() -> dict[str, object]:
    return {
        "rejection_used": True,
        "rejection_mode": "hard_size_limit",
        "strict_error_type": "SkillLoadError",
        "strict_error_code": "SKILL_METADATA_SIZE_LIMIT_EXCEEDED",
        "manifest_complete": False,
        "capability_facts_trusted": False,
        "content_scanned": False,
        "size_bytes": 21_002_040,
        "limit_bytes": 10 * 1024 * 1024,
    }


def _result() -> SimpleNamespace:
    metadata = _metadata()
    return SimpleNamespace(
        analyzers_failed=[],
        findings=[
            {
                "id": "SKILL_LOAD_REJECTED_LIMIT",
                "rule_id": "SKILL_LOAD_REJECTED_LIMIT",
                "category": "policy_violation",
                "severity": "HIGH",
                "analyzer": "skill_loader",
                "file_path": "SKILL.md",
                "metadata": dict(metadata),
            }
        ],
        scan_metadata={
            "loader": dict(metadata),
            "cel": {
                "mode": "off",
                "runtime": "cel-go",
                "runtime_version": "v0.32.0;helper=test",
                "fact_schema": "v1",
                "expression_set_hash": "a" * 64,
                "evaluated": 0,
                "retained": 1,
                "would_suppress": 0,
                "suppressed": 0,
                "fallbacks": 0,
                "projection_incomplete": 0,
                "errors": [],
            },
        },
    )


def test_exact_closed_loader_rejection_is_recognized() -> None:
    disposition = recognize_loader_disposition(_result())

    assert disposition.recovery is None
    assert disposition.rejection is not None
    assert disposition.rejection.error_code == "SKILL_METADATA_SIZE_LIMIT_EXCEEDED"
    assert disposition.rejection.size_bytes == 21_002_040
    assert disposition.rejection.limit_bytes == 10 * 1024 * 1024


def test_real_scanner_closed_rejection_satisfies_evaluator_contract(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill = tmp_path / "oversized"
    skill.mkdir()
    skill_file = skill / "SKILL.md"
    skill_file.write_bytes(b"x" * 129)
    policy = ScanPolicy.default()
    policy.cel.mode = CelMode.OFF
    policy.file_limits.max_loader_file_size_bytes = 128
    scanner = SkillScanner(
        analyzers=[],
        policy=policy,
        rule_registry=PackLoader().build_registry(),
    )

    def fail_if_read(*_args, **_kwargs):
        raise AssertionError("closed rejection must not read oversized content")

    monkeypatch.setattr(scanner.loader, "load_skill", fail_if_read)
    with scanner:
        result = scanner.scan_skill(skill)

    disposition = recognize_loader_disposition(result)
    assert disposition.recovery is None
    assert disposition.rejection is not None
    assert disposition.rejection.size_bytes == skill_file.stat().st_size
    assert disposition.rejection.limit_bytes == 128


@pytest.mark.parametrize(
    "mutation",
    [
        "analyzer_failure",
        "duplicate_marker",
        "wrong_rule_id",
        "wrong_category",
        "wrong_severity",
        "unsafe_path",
        "content_scanned",
        "size_not_over_limit",
        "metadata_mismatch",
        "cel_evaluated",
        "cel_fallback",
        "cel_identity",
        "cel_retained",
        "conflicting_fallback",
    ],
)
def test_closed_loader_rejection_spoofs_fail_closed(mutation: str) -> None:
    result = _result()
    marker = result.findings[0]
    if mutation == "analyzer_failure":
        result.analyzers_failed = [{"analyzer": "skill_loader", "error": "unexpected"}]
    elif mutation == "duplicate_marker":
        result.findings.append(copy.deepcopy(marker))
    elif mutation == "wrong_rule_id":
        marker["rule_id"] = "OTHER"
    elif mutation == "wrong_category":
        marker["category"] = "command_execution"
    elif mutation == "wrong_severity":
        marker["severity"] = "INFO"
    elif mutation == "unsafe_path":
        marker["file_path"] = "../SKILL.md"
    elif mutation == "content_scanned":
        result.scan_metadata["loader"]["content_scanned"] = True
    elif mutation == "size_not_over_limit":
        result.scan_metadata["loader"]["size_bytes"] = result.scan_metadata["loader"]["limit_bytes"]
    elif mutation == "metadata_mismatch":
        marker["metadata"]["limit_bytes"] = 1
    elif mutation == "cel_evaluated":
        result.scan_metadata["cel"]["evaluated"] = 1
    elif mutation == "cel_fallback":
        result.scan_metadata["cel"]["fallbacks"] = 1
    elif mutation == "cel_identity":
        result.scan_metadata["cel"]["runtime"] = "unavailable"
    elif mutation == "cel_retained":
        result.scan_metadata["cel"]["retained"] = 0
    else:
        marker["metadata"]["fallback_used"] = True

    with pytest.raises(LoaderFallbackValidationError):
        recognize_loader_disposition(result)
