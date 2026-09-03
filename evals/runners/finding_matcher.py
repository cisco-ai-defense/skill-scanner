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

"""Evaluation expectation validation and deterministic finding matching.

Expected findings may progressively adopt the complete finding identity.  A
field omitted from an older expectation is a wildcard; every field that is
present must match exactly.  Regardless of expectation specificity, one actual
finding can satisfy at most one expected finding.

Schema-v2 expectations are release-grade ground truth and must provide the
complete canonical identity.  Existing schema-v1 expectations are accepted
only when they explicitly identify themselves as ``legacy_degraded``.  This
keeps historical labels useful without presenting category-only matching as a
stronger source of truth than it is.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

IDENTITY_FIELDS = (
    "rule_id",
    "category",
    "severity",
    "file_path",
    "line_number",
    "evidence_id",
    "analyzer",
)

STRICT_IDENTITY_FIELDS = frozenset({"rule_id", "category", "severity", "file_path", "analyzer"})
LOCATION_IDENTITY_FIELDS = ("line_number", "evidence_id")

_ROOT_KEYS = frozenset(
    {
        "schema_version",
        "evaluation_quality",
        "case_id",
        "skill_name",
        "package_label",
        "expected_verdict",
        "expected_safe",
        "is_malicious",
        "expected_severity",
        "expected_findings",
        "provenance",
        "notes",
        "threat_patterns",
    }
)
_FINDING_KEYS = frozenset((*IDENTITY_FIELDS, "description"))
_PROVENANCE_KEYS = frozenset(
    {
        "source",
        "license",
        "fixture_sha256",
        "label_source",
        "scanner_independent",
        "label_provenance_sha256",
        "label_evidence_sha256",
    }
)
LABEL_SOURCES = frozenset(
    {
        "public_labeled",
        "independent_ollama",
        "agent_labeled",
        "human_reviewed",
    }
)
_PACKAGE_LABELS = frozenset({"benign", "malicious", "contextual_risk"})
_EXPECTED_VERDICTS = frozenset({"safe", "unsafe"})
_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "SAFE"})
_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_CATEGORIES = frozenset(
    {
        "prompt_injection",
        "command_injection",
        "data_exfiltration",
        "unauthorized_tool_use",
        "obfuscation",
        "hardcoded_secrets",
        "social_engineering",
        "resource_abuse",
        "policy_violation",
        "malware",
        "harmful_content",
        "skill_discovery_abuse",
        "transitive_trust_abuse",
        "autonomy_abuse",
        "tool_chaining_abuse",
        "unicode_steganography",
        "supply_chain_attack",
    }
)
_CASE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{2,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_LABEL_PROVENANCE_DOMAIN = b"skill-scanner-golden-label-provenance-v1\0"
_LABEL_EVIDENCE_DOMAIN = b"skill-scanner-golden-label-evidence-v1\0"


class FindingExpectationError(ValueError):
    """Raised when an expected-finding identity is malformed."""


class EvaluationExpectationError(FindingExpectationError):
    """Raised when an evaluation expectation document is malformed."""


@dataclass(frozen=True)
class ValidatedExpectation:
    """Validated view of an evaluation expectation document."""

    document: Mapping[str, Any]
    schema_version: int
    evaluation_quality: str
    skill_name: str
    expected_safe: bool
    package_label: str | None
    label_source: str | None
    expected_findings: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class FindingMatchResult:
    """Result of a maximum-cardinality one-to-one finding match."""

    matched_pairs: tuple[tuple[int, int], ...]
    unmatched_expected_indices: tuple[int, ...]
    unmatched_actual_indices: tuple[int, ...]

    @property
    def matched_count(self) -> int:
        return len(self.matched_pairs)


def _enum_value(value: Any) -> Any:
    return getattr(value, "value", value)


def _actual_value(finding: Any, field: str) -> Any:
    actual_field = "id" if field == "evidence_id" else field
    if isinstance(finding, Mapping):
        if field == "evidence_id" and "id" not in finding:
            return finding.get("evidence_id")
        return finding.get(actual_field)
    return getattr(finding, actual_field, None)


def _normalize_path(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise FindingExpectationError("file_path must be a string or null")
    normalized = value.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return PurePosixPath(normalized).as_posix()


def _require_nonempty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvaluationExpectationError(f"{field} must be a non-empty string")
    return value


def _reject_unknown_keys(value: Mapping[str, Any], known: frozenset[str], location: str) -> None:
    unknown = sorted(set(value) - known)
    if unknown:
        raise EvaluationExpectationError(f"{location} contains unknown key(s): {', '.join(unknown)}")


def fixture_sha256(fixture_dir: Path) -> str:
    """Return the canonical SHA-256 for files in an evaluation fixture.

    ``_expected.json`` is excluded so reviewers can update labels without
    changing the hash of the sample being labeled.  Relative path, byte length,
    and content are framed to avoid concatenation ambiguities.
    """

    fixture_dir = fixture_dir.resolve()
    files: list[Path] = []
    for path in fixture_dir.rglob("*"):
        if path.is_symlink():
            raise EvaluationExpectationError(f"fixture contains a symlink: {path.relative_to(fixture_dir)}")
        if path.is_file() and path.name != "_expected.json":
            files.append(path)
    if not files:
        raise EvaluationExpectationError("fixture contains no package files to hash")

    digest = hashlib.sha256(b"skill-scanner-eval-fixture-v1\0")
    for path in sorted(files, key=lambda item: item.relative_to(fixture_dir).as_posix()):
        relative = path.relative_to(fixture_dir).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _validate_finding(expected: Mapping[str, Any], index: int, *, strict: bool) -> None:
    location = f"expected_findings[{index}]"
    _reject_unknown_keys(expected, _FINDING_KEYS, location)

    specified = [field for field in IDENTITY_FIELDS if field in expected]
    if not specified:
        raise EvaluationExpectationError(
            f"{location} must specify at least one identity field: {', '.join(IDENTITY_FIELDS)}"
        )

    if strict:
        missing = sorted(STRICT_IDENTITY_FIELDS - set(expected))
        if missing:
            raise EvaluationExpectationError(f"{location} is missing canonical identity field(s): {', '.join(missing)}")
        if not any(expected.get(field) is not None for field in LOCATION_IDENTITY_FIELDS):
            raise EvaluationExpectationError(f"{location} must provide line_number or evidence_id")

    for field in specified:
        _normalize(field, expected[field])

    if "rule_id" in expected:
        _require_nonempty_string(expected["rule_id"], f"{location}.rule_id")
    if "category" in expected and expected["category"] not in _CATEGORIES:
        raise EvaluationExpectationError(f"{location}.category is not a known threat category")
    if "severity" in expected and expected["severity"] not in _SEVERITIES - {"SAFE"}:
        raise EvaluationExpectationError(f"{location}.severity is not a finding severity")
    if "analyzer" in expected:
        _require_nonempty_string(expected["analyzer"], f"{location}.analyzer")
    if "file_path" in expected:
        file_path = _require_nonempty_string(expected["file_path"], f"{location}.file_path")
        path = PurePosixPath(file_path.replace("\\", "/"))
        if path.is_absolute() or path.as_posix() == "." or ".." in path.parts:
            raise EvaluationExpectationError(f"{location}.file_path must be a fixture-relative path")
    if "line_number" in expected:
        if expected["line_number"] is None:
            raise EvaluationExpectationError(f"{location}.line_number must be omitted or positive")
        if expected["line_number"] < 1:
            raise EvaluationExpectationError(f"{location}.line_number must be positive")
    if "evidence_id" in expected:
        if expected["evidence_id"] is None:
            raise EvaluationExpectationError(f"{location}.evidence_id must be omitted or non-empty")
        _require_nonempty_string(expected["evidence_id"], f"{location}.evidence_id")
    if "description" in expected:
        _require_nonempty_string(expected["description"], f"{location}.description")


def _canonical_sha256(domain: bytes, value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def label_provenance_sha256(provenance: Mapping[str, Any]) -> str:
    """Hash the bounded, scanner-independent origin of one golden label."""

    return _canonical_sha256(
        _LABEL_PROVENANCE_DOMAIN,
        {
            "fixture_sha256": provenance.get("fixture_sha256"),
            "label_source": provenance.get("label_source"),
            "license": provenance.get("license"),
            "scanner_independent": provenance.get("scanner_independent"),
            "source": provenance.get("source"),
        },
    )


def label_evidence_sha256(document: Mapping[str, Any]) -> str:
    """Hash only the asserted label and exact expected finding identities."""

    return _canonical_sha256(
        _LABEL_EVIDENCE_DOMAIN,
        {
            "case_id": document.get("case_id"),
            "expected_findings": document.get("expected_findings"),
            "expected_severity": document.get("expected_severity"),
            "expected_verdict": document.get("expected_verdict"),
            "package_label": document.get("package_label"),
            "skill_name": document.get("skill_name"),
        },
    )


def bind_label_attestation(document: dict[str, Any]) -> None:
    """Populate recomputable label hashes after a strict document is assembled."""

    provenance = document.get("provenance")
    if not isinstance(provenance, dict):
        raise EvaluationExpectationError("provenance must be an object")
    provenance["label_provenance_sha256"] = label_provenance_sha256(provenance)
    provenance["label_evidence_sha256"] = label_evidence_sha256(document)


def _validate_provenance(value: Any, fixture_dir: Path | None, document: Mapping[str, Any]) -> str:
    if not isinstance(value, Mapping):
        raise EvaluationExpectationError("provenance must be an object")
    _reject_unknown_keys(value, _PROVENANCE_KEYS, "provenance")
    for field in sorted(_PROVENANCE_KEYS):
        if field not in value:
            raise EvaluationExpectationError(f"provenance is missing required key: {field}")
    for field in (
        "source",
        "license",
        "fixture_sha256",
        "label_source",
        "label_provenance_sha256",
        "label_evidence_sha256",
    ):
        _require_nonempty_string(value[field], f"provenance.{field}")
    fixture_hash = value["fixture_sha256"]
    if not _SHA256_RE.fullmatch(fixture_hash):
        raise EvaluationExpectationError("provenance.fixture_sha256 must be a lowercase SHA-256")
    if fixture_dir is not None:
        actual_hash = fixture_sha256(fixture_dir)
        if fixture_hash != actual_hash:
            raise EvaluationExpectationError(
                "provenance.fixture_sha256 does not match fixture contents "
                f"(expected {fixture_hash}, calculated {actual_hash})"
            )
    label_source = value["label_source"]
    if not isinstance(label_source, str) or label_source not in LABEL_SOURCES:
        raise EvaluationExpectationError("provenance.label_source must be one of: " + ", ".join(sorted(LABEL_SOURCES)))
    if value["scanner_independent"] is not True:
        raise EvaluationExpectationError("provenance.scanner_independent must be true")
    normalized_source = re.sub(r"[^a-z0-9]+", "-", value["source"].casefold()).strip("-")
    if "scanner-derived" in normalized_source or "scanner-generated" in normalized_source:
        raise EvaluationExpectationError("provenance.source must not identify scanner-derived labels")
    for field in ("label_provenance_sha256", "label_evidence_sha256"):
        if not _SHA256_RE.fullmatch(value[field]):
            raise EvaluationExpectationError(f"provenance.{field} must be a lowercase SHA-256")
    expected_provenance_hash = label_provenance_sha256(value)
    if value["label_provenance_sha256"] != expected_provenance_hash:
        raise EvaluationExpectationError("provenance.label_provenance_sha256 does not match label provenance")
    expected_evidence_hash = label_evidence_sha256(document)
    if value["label_evidence_sha256"] != expected_evidence_hash:
        raise EvaluationExpectationError("provenance.label_evidence_sha256 does not match label evidence")
    return label_source


def validate_expectation_document(
    document: Any,
    *,
    fixture_dir: Path | None = None,
) -> ValidatedExpectation:
    """Validate a strict or explicitly degraded evaluation expectation."""

    if not isinstance(document, Mapping):
        raise EvaluationExpectationError("evaluation expectation root must be a JSON object")
    _reject_unknown_keys(document, _ROOT_KEYS, "evaluation expectation")

    schema_version = document.get("schema_version")
    quality = document.get("evaluation_quality")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        raise EvaluationExpectationError("schema_version must be an integer")
    if schema_version == 1 and quality == "legacy_degraded":
        strict = False
    elif schema_version == 2 and quality == "strict":
        strict = True
    else:
        raise EvaluationExpectationError(
            "expectation must declare schema_version=1/evaluation_quality='legacy_degraded' "
            "or schema_version=2/evaluation_quality='strict'"
        )

    skill_name = _require_nonempty_string(document.get("skill_name"), "skill_name")
    findings = document.get("expected_findings")
    if not isinstance(findings, list):
        raise EvaluationExpectationError("expected_findings must be a JSON array")

    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise EvaluationExpectationError(f"expected_findings[{index}] must be an object")
        _validate_finding(finding, index, strict=strict)

    package_label: str | None = None
    label_source: str | None = None
    if strict:
        for legacy_key in ("expected_safe", "is_malicious"):
            if legacy_key in document:
                raise EvaluationExpectationError(f"strict expectations must use expected_verdict, not {legacy_key}")
        case_id = _require_nonempty_string(document.get("case_id"), "case_id")
        if not _CASE_ID_RE.fullmatch(case_id):
            raise EvaluationExpectationError("case_id must be a stable lowercase identifier")
        package_label = document.get("package_label")
        if package_label not in _PACKAGE_LABELS:
            raise EvaluationExpectationError(f"package_label must be one of: {', '.join(sorted(_PACKAGE_LABELS))}")
        expected_verdict = document.get("expected_verdict")
        if expected_verdict not in _EXPECTED_VERDICTS:
            raise EvaluationExpectationError(
                f"expected_verdict must be one of: {', '.join(sorted(_EXPECTED_VERDICTS))}"
            )
        if package_label == "benign" and expected_verdict != "safe":
            raise EvaluationExpectationError("benign packages must have expected_verdict='safe'")
        if package_label == "malicious" and expected_verdict != "unsafe":
            raise EvaluationExpectationError("malicious packages must have expected_verdict='unsafe'")
        actionable_findings = [finding for finding in findings if finding.get("severity") in {"CRITICAL", "HIGH"}]
        if expected_verdict == "unsafe" and not actionable_findings:
            raise EvaluationExpectationError(
                "unsafe expectations must include at least one CRITICAL or HIGH expected finding"
            )
        if expected_verdict == "safe" and actionable_findings:
            raise EvaluationExpectationError("safe expectations cannot include CRITICAL or HIGH expected findings")
        label_source = _validate_provenance(document.get("provenance"), fixture_dir, document)
        expected_safe = expected_verdict == "safe"
    else:
        strict_only = sorted(
            key for key in ("case_id", "package_label", "expected_verdict", "provenance") if key in document
        )
        if strict_only:
            raise EvaluationExpectationError(
                "legacy_degraded expectations cannot claim partial strict metadata: " + ", ".join(strict_only)
            )
        has_expected_safe = "expected_safe" in document
        has_is_malicious = "is_malicious" in document
        if has_expected_safe == has_is_malicious:
            raise EvaluationExpectationError(
                "legacy_degraded expectations must provide exactly one of expected_safe or is_malicious"
            )
        if has_expected_safe:
            expected_safe_value = document["expected_safe"]
            if not isinstance(expected_safe_value, bool):
                raise EvaluationExpectationError("expected_safe must be a JSON boolean")
            expected_safe = expected_safe_value
        else:
            is_malicious = document["is_malicious"]
            if not isinstance(is_malicious, bool):
                raise EvaluationExpectationError("is_malicious must be a JSON boolean")
            expected_safe = not is_malicious

    if "expected_severity" in document:
        severity = document["expected_severity"]
        if severity not in _SEVERITIES:
            raise EvaluationExpectationError(f"expected_severity must be one of: {', '.join(sorted(_SEVERITIES))}")
        if strict:
            finding_severities = {finding.get("severity") for finding in findings}
            calculated_severity = next(
                (candidate for candidate in _SEVERITY_ORDER if candidate in finding_severities),
                "SAFE",
            )
            if severity != calculated_severity:
                raise EvaluationExpectationError(
                    "expected_severity does not match the maximum expected finding severity "
                    f"({severity} != {calculated_severity})"
                )
    if "notes" in document:
        _require_nonempty_string(document["notes"], "notes")
    if "threat_patterns" in document:
        patterns = document["threat_patterns"]
        if not isinstance(patterns, list) or not all(isinstance(item, str) and item for item in patterns):
            raise EvaluationExpectationError("threat_patterns must be an array of non-empty strings")

    return ValidatedExpectation(
        document=document,
        schema_version=schema_version,
        evaluation_quality=quality,
        skill_name=skill_name,
        expected_safe=expected_safe,
        package_label=package_label,
        label_source=label_source,
        expected_findings=tuple(findings),
    )


def _normalize(field: str, value: Any) -> Any:
    value = _enum_value(value)
    if field == "file_path":
        return _normalize_path(value)
    if field == "line_number":
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise FindingExpectationError("line_number must be an integer or null")
        return value
    if field == "severity" and isinstance(value, str):
        return value.upper()
    if field == "category" and isinstance(value, str):
        return value.lower()
    if field == "analyzer" and isinstance(value, str):
        return value.lower()
    return value


def _validate_expectation(expected: Mapping[str, Any], index: int) -> None:
    specified = [field for field in IDENTITY_FIELDS if field in expected]
    if not specified:
        raise FindingExpectationError(
            f"expected_findings[{index}] must specify at least one identity field: {', '.join(IDENTITY_FIELDS)}"
        )
    for field in specified:
        _normalize(field, expected[field])


def _matches(expected: Mapping[str, Any], actual: Any) -> bool:
    for field in IDENTITY_FIELDS:
        if field not in expected:
            continue
        if _normalize(field, expected[field]) != _normalize(field, _actual_value(actual, field)):
            return False
    return True


def match_findings(
    expected_findings: Sequence[Mapping[str, Any]],
    actual_findings: Sequence[Any],
) -> FindingMatchResult:
    """Return a deterministic maximum-cardinality one-to-one match.

    More-specific expectations are assigned first so legacy wildcard entries
    cannot consume an actual finding needed by a fully-qualified expectation.
    The augmenting-path matcher still finds the maximum number of pairs.
    """

    for index, expected in enumerate(expected_findings):
        if not isinstance(expected, Mapping):
            raise FindingExpectationError(f"expected_findings[{index}] must be an object")
        _validate_expectation(expected, index)

    adjacency = [
        [actual_index for actual_index, actual in enumerate(actual_findings) if _matches(expected, actual)]
        for expected in expected_findings
    ]
    specificity_order = sorted(
        range(len(expected_findings)),
        key=lambda index: (-sum(field in expected_findings[index] for field in IDENTITY_FIELDS), index),
    )

    actual_to_expected: dict[int, int] = {}

    def assign(expected_index: int, seen_actual: set[int]) -> bool:
        for actual_index in adjacency[expected_index]:
            if actual_index in seen_actual:
                continue
            seen_actual.add(actual_index)
            previous_expected = actual_to_expected.get(actual_index)
            if previous_expected is None or assign(previous_expected, seen_actual):
                actual_to_expected[actual_index] = expected_index
                return True
        return False

    for expected_index in specificity_order:
        assign(expected_index, set())

    matched_pairs = tuple(
        sorted((expected_index, actual_index) for actual_index, expected_index in actual_to_expected.items())
    )
    matched_expected = {expected_index for expected_index, _ in matched_pairs}
    matched_actual = {actual_index for _, actual_index in matched_pairs}

    return FindingMatchResult(
        matched_pairs=matched_pairs,
        unmatched_expected_indices=tuple(
            index for index in range(len(expected_findings)) if index not in matched_expected
        ),
        unmatched_actual_indices=tuple(index for index in range(len(actual_findings)) if index not in matched_actual),
    )
