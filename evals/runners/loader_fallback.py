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

"""Recognize narrowly bounded loader recovery and closed rejection outcomes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

_FALLBACK_RULE_ID = "SKILL_LOAD_FALLBACK_USED"
_REJECTION_RULE_ID = "SKILL_LOAD_REJECTED_LIMIT"
_LOADER_ANALYZER = "skill_loader"
_RECOGNIZED_ERROR_CODES = frozenset(
    {
        "MALFORMED_YAML_FRONTMATTER",
        "MISSING_REQUIRED_MANIFEST_FIELD",
    }
)
_REJECTION_ERROR_CODE = "SKILL_METADATA_SIZE_LIMIT_EXCEEDED"
_REJECTION_METADATA_KEYS = frozenset(
    {
        "rejection_used",
        "rejection_mode",
        "content_scanned",
        "size_bytes",
        "limit_bytes",
    }
)


class LoaderFallbackValidationError(ValueError):
    """Raised when scanner output does not prove an allowed loader disposition."""


@dataclass(frozen=True)
class LoaderFallbackRecovery:
    """A validated, bounded loader recovery retained by an evaluator."""

    error_code: str


@dataclass(frozen=True)
class LoaderClosedRejection:
    """A validated closed policy verdict emitted without reading content."""

    error_code: str
    size_bytes: int
    limit_bytes: int


@dataclass(frozen=True)
class LoaderDisposition:
    """The mutually exclusive, validated loader outcome for one scan."""

    recovery: LoaderFallbackRecovery | None = None
    rejection: LoaderClosedRejection | None = None


def _result_value(result: Any, field: str, default: Any) -> Any:
    if isinstance(result, Mapping):
        return result.get(field, default)
    return getattr(result, field, default)


def _finding_value(finding: Any, field: str, default: Any = None) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(field, default)
    return getattr(finding, field, default)


def _enum_string(value: Any) -> str | None:
    value = getattr(value, "value", value)
    return value if isinstance(value, str) else None


def _expected_loader_metadata(error_code: str) -> dict[str, Any]:
    return {
        "fallback_used": True,
        "fallback_mode": "bounded_inert_raw_body",
        "strict_error_type": "SkillLoadError",
        "strict_error_code": error_code,
        "manifest_complete": False,
        "capability_facts_trusted": False,
        "projection_complete": False,
        "projection_error_code": "MANIFEST_METADATA_INCOMPLETE",
    }


def _metadata_matches(value: Any, expected: Mapping[str, Any], *, exact_fields: bool) -> bool:
    if not isinstance(value, Mapping):
        return False
    if exact_fields and set(value) != set(expected):
        return False
    return all(
        field in value and type(value[field]) is type(expected_value) and value[field] == expected_value
        for field, expected_value in expected.items()
    )


def _sequence_value(result: Any, field: str) -> list[Any]:
    value = _result_value(result, field, [])
    if value is None:
        value = []
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Sequence):
        raise LoaderFallbackValidationError(f"{field} must be an array")
    return list(value)


def _loader_metadata(result: Any) -> tuple[bool, Any]:
    scan_metadata = _result_value(result, "scan_metadata", None)
    present = isinstance(scan_metadata, Mapping) and "loader" in scan_metadata
    return present, scan_metadata.get("loader") if present else None


def _has_rejection_signal(findings: Sequence[Any], loader_metadata: Any) -> bool:
    if isinstance(loader_metadata, Mapping) and set(loader_metadata) & _REJECTION_METADATA_KEYS:
        return True
    for finding in findings:
        if (
            _finding_value(finding, "id") == _REJECTION_RULE_ID
            or _finding_value(finding, "rule_id") == _REJECTION_RULE_ID
        ):
            return True
        metadata = _finding_value(finding, "metadata", {})
        if isinstance(metadata, Mapping) and set(metadata) & _REJECTION_METADATA_KEYS:
            return True
    return False


def _validate_rejection_cel_identity(result: Any) -> None:
    scan_metadata = _result_value(result, "scan_metadata", None)
    if not isinstance(scan_metadata, Mapping):
        raise LoaderFallbackValidationError("closed loader rejection requires scan metadata")
    cel = scan_metadata.get("cel")
    if not isinstance(cel, Mapping):
        raise LoaderFallbackValidationError("closed loader rejection requires CEL runtime identity")
    if (
        cel.get("mode") not in {"off", "shadow", "enforce"}
        or cel.get("runtime") != "cel-go"
        or not isinstance(cel.get("runtime_version"), str)
        or not cel["runtime_version"]
        or cel.get("fact_schema") != "v1"
    ):
        raise LoaderFallbackValidationError("closed loader rejection has invalid CEL runtime identity")
    expression_hash = cel.get("expression_set_hash")
    if (
        not isinstance(expression_hash, str)
        or len(expression_hash) != 64
        or any(character not in "0123456789abcdef" for character in expression_hash)
    ):
        raise LoaderFallbackValidationError("closed loader rejection has invalid CEL expression identity")
    for field in (
        "evaluated",
        "would_suppress",
        "suppressed",
        "fallbacks",
        "projection_incomplete",
    ):
        if cel.get(field) != 0 or type(cel.get(field)) is not int:
            raise LoaderFallbackValidationError(f"closed loader rejection must report zero CEL {field}")
    if cel.get("retained") != 1 or type(cel.get("retained")) is not int:
        raise LoaderFallbackValidationError("closed loader rejection must retain exactly its deterministic marker")
    if cel.get("errors") != []:
        raise LoaderFallbackValidationError("closed loader rejection must not report CEL errors")


def _recognize_closed_rejection(
    result: Any,
    *,
    failures: Sequence[Any],
    findings: Sequence[Any],
    loader_metadata: Any,
) -> LoaderClosedRejection:
    if failures:
        raise LoaderFallbackValidationError("closed loader rejection must not report analyzer failures")
    marker_identities = [
        finding
        for finding in findings
        if _finding_value(finding, "id") == _REJECTION_RULE_ID
        or _finding_value(finding, "rule_id") == _REJECTION_RULE_ID
    ]
    if len(findings) != 1 or len(marker_identities) != 1:
        raise LoaderFallbackValidationError(
            "closed loader rejection requires exactly one SKILL_LOAD_REJECTED_LIMIT finding"
        )
    marker = marker_identities[0]
    category = _enum_string(_finding_value(marker, "category"))
    severity = _enum_string(_finding_value(marker, "severity"))
    file_path = _finding_value(marker, "file_path")
    if (
        _finding_value(marker, "id") != _REJECTION_RULE_ID
        or _finding_value(marker, "rule_id") != _REJECTION_RULE_ID
        or _finding_value(marker, "analyzer") != _LOADER_ANALYZER
        or category is None
        or category.lower() != "policy_violation"
        or severity is None
        or severity.upper() != "HIGH"
        or not isinstance(file_path, str)
        or not file_path
        or file_path in {".", ".."}
        or "/" in file_path
        or "\\" in file_path
    ):
        raise LoaderFallbackValidationError("closed loader rejection has an invalid marker identity")

    if not isinstance(loader_metadata, Mapping):
        raise LoaderFallbackValidationError("closed loader rejection lacks loader metadata")
    size_bytes = loader_metadata.get("size_bytes")
    limit_bytes = loader_metadata.get("limit_bytes")
    if type(size_bytes) is not int or type(limit_bytes) is not int or limit_bytes <= 0 or size_bytes <= limit_bytes:
        raise LoaderFallbackValidationError("closed loader rejection has invalid size bounds")
    expected_metadata = {
        "rejection_used": True,
        "rejection_mode": "hard_size_limit",
        "strict_error_type": "SkillLoadError",
        "strict_error_code": _REJECTION_ERROR_CODE,
        "manifest_complete": False,
        "capability_facts_trusted": False,
        "content_scanned": False,
        "size_bytes": size_bytes,
        "limit_bytes": limit_bytes,
    }
    if not _metadata_matches(loader_metadata, expected_metadata, exact_fields=True):
        raise LoaderFallbackValidationError("closed loader rejection metadata is invalid")
    if not _metadata_matches(
        _finding_value(marker, "metadata", {}),
        expected_metadata,
        exact_fields=False,
    ):
        raise LoaderFallbackValidationError("closed loader rejection finding metadata does not match scan metadata")
    _validate_rejection_cel_identity(result)
    return LoaderClosedRejection(
        error_code=_REJECTION_ERROR_CODE,
        size_bytes=size_bytes,
        limit_bytes=limit_bytes,
    )


def _recognize_recovery(
    *,
    failures: Sequence[Any],
    findings: Sequence[Any],
    loader_metadata_present: bool,
    loader_metadata: Any,
) -> LoaderFallbackRecovery | None:
    marker_identities = [
        finding
        for finding in findings
        if _finding_value(finding, "id") == _FALLBACK_RULE_ID or _finding_value(finding, "rule_id") == _FALLBACK_RULE_ID
    ]
    if not failures and not marker_identities and not loader_metadata_present:
        return None
    if len(failures) != 1:
        raise LoaderFallbackValidationError("bounded loader recovery requires exactly one analyzer failure")

    failure = failures[0]
    if not isinstance(failure, Mapping) or set(failure) != {"analyzer", "error"}:
        raise LoaderFallbackValidationError("loader analyzer failure has invalid fields")
    if failure.get("analyzer") != _LOADER_ANALYZER:
        raise LoaderFallbackValidationError("only the skill_loader analyzer failure can be recovered")

    raw_error = failure.get("error")
    prefix = "SkillLoadError:"
    if not isinstance(raw_error, str) or not raw_error.startswith(prefix):
        raise LoaderFallbackValidationError("loader analyzer failure has an invalid error identity")
    error_code = raw_error.removeprefix(prefix)
    if error_code not in _RECOGNIZED_ERROR_CODES:
        raise LoaderFallbackValidationError(f"unrecognized loader fallback error code: {error_code}")

    if len(marker_identities) != 1:
        raise LoaderFallbackValidationError(
            "bounded loader recovery requires exactly one SKILL_LOAD_FALLBACK_USED finding"
        )
    marker = marker_identities[0]
    category = _enum_string(_finding_value(marker, "category"))
    severity = _enum_string(_finding_value(marker, "severity"))
    if (
        _finding_value(marker, "id") != _FALLBACK_RULE_ID
        or _finding_value(marker, "rule_id") != _FALLBACK_RULE_ID
        or _finding_value(marker, "analyzer") != _LOADER_ANALYZER
        or category is None
        or category.lower() != "policy_violation"
        or severity is None
        or severity.upper() != "INFO"
    ):
        raise LoaderFallbackValidationError("loader fallback finding has an invalid marker identity")

    expected_metadata = _expected_loader_metadata(error_code)
    if not _metadata_matches(loader_metadata, expected_metadata, exact_fields=True):
        raise LoaderFallbackValidationError("scan_metadata.loader does not match the loader failure")

    marker_metadata = _finding_value(marker, "metadata", {})
    if not _metadata_matches(marker_metadata, expected_metadata, exact_fields=False):
        raise LoaderFallbackValidationError("loader fallback finding metadata does not match scan_metadata.loader")

    return LoaderFallbackRecovery(error_code=error_code)


def recognize_loader_disposition(result: Any) -> LoaderDisposition:
    """Validate and classify the scanner's mutually exclusive loader outcome.

    Ordinary scans return an empty disposition. A partial, contradictory, or
    spoofed fallback/rejection proof raises instead of becoming a successful
    benchmark sample.
    """

    failures = _sequence_value(result, "analyzers_failed")
    findings = _sequence_value(result, "findings")
    loader_metadata_present, loader_metadata = _loader_metadata(result)
    rejection_signal = _has_rejection_signal(findings, loader_metadata)
    fallback_signal = bool(failures) or any(
        _finding_value(finding, "id") == _FALLBACK_RULE_ID
        or _finding_value(finding, "rule_id") == _FALLBACK_RULE_ID
        or (
            isinstance(_finding_value(finding, "metadata", {}), Mapping)
            and bool({"fallback_used", "fallback_mode"} & set(_finding_value(finding, "metadata", {})))
        )
        for finding in findings
    )
    if isinstance(loader_metadata, Mapping):
        fallback_signal = fallback_signal or bool({"fallback_used", "fallback_mode"} & set(loader_metadata))
    if rejection_signal and fallback_signal:
        raise LoaderFallbackValidationError("loader recovery and closed rejection proofs conflict")
    if rejection_signal:
        rejection = _recognize_closed_rejection(
            result,
            failures=failures,
            findings=findings,
            loader_metadata=loader_metadata,
        )
        return LoaderDisposition(rejection=rejection)
    recovery = _recognize_recovery(
        failures=failures,
        findings=findings,
        loader_metadata_present=loader_metadata_present,
        loader_metadata=loader_metadata,
    )
    return LoaderDisposition(recovery=recovery)


def recognize_loader_fallback(result: Any) -> LoaderFallbackRecovery | None:
    """Return a validated bounded recovery, or ``None`` for another disposition."""

    return recognize_loader_disposition(result).recovery


def recognize_loader_rejection(result: Any) -> LoaderClosedRejection | None:
    """Return a validated closed size-limit rejection, or ``None``."""

    return recognize_loader_disposition(result).rejection
