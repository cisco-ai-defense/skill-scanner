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

"""Scoped rule suppressions for named skills or paths.

Entries require a selector and retain audit metadata for hidden or re-rated
findings.
"""

from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field
from datetime import date
from typing import TYPE_CHECKING

from .models import Severity

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .models import Finding

logger = logging.getLogger(__name__)

# Keep aggregate audit metadata bounded; report overflow as truncated rather
# than failing the scan.
_MAX_SUMMARY_ENTRIES = 4096

# Severities a scoped entry may re-rate a finding to, in either direction.  SAFE
# is excluded: it is a "no findings" sentinel, not a finding severity.
_ASSIGNABLE_SEVERITIES = frozenset(
    {
        Severity.CRITICAL.value,
        Severity.HIGH.value,
        Severity.MEDIUM.value,
        Severity.LOW.value,
        Severity.INFO.value,
    }
)

# Cross-skill findings carry this literal instead of a real path and have no
# owning skill, so scoped selectors cannot meaningfully apply to them.
CROSS_SKILL_PATH = "(cross-skill analysis)"


class SuppressionConfigError(ValueError):
    """Raised when a ``suppressions`` policy entry is malformed."""


@dataclass(frozen=True)
class SuppressionRule:
    """One scoped suppression entry.

    Attributes:
        rule_id: The rule this entry applies to.
        skills: Globs matched against the skill name.  Empty means "any skill".
        paths: Globs matched against the skill-relative file path.  Empty means
            "any file".
        reason: Free-text justification, surfaced in SARIF and in the summary.
        severity: When set, the finding is re-rated to this severity — lower or
            higher — and kept instead of being suppressed.
        expires: Last day the entry is active.  An expired entry is inert.
    """

    rule_id: str
    skills: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    reason: str = ""
    severity: str | None = None
    expires: date | None = None

    def is_active(self, today: date) -> bool:
        """Return whether the entry is still within its expiry window."""
        return self.expires is None or today <= self.expires

    def to_dict(self) -> dict[str, object]:
        """Serialize back to the policy YAML shape."""
        data: dict[str, object] = {"rule_id": self.rule_id}
        if self.skills:
            data["skills"] = list(self.skills)
        if self.paths:
            data["paths"] = list(self.paths)
        if self.severity:
            data["severity"] = self.severity
        if self.reason:
            data["reason"] = self.reason
        if self.expires is not None:
            data["expires"] = self.expires.isoformat()
        return data


def _as_pattern_tuple(value: object, *, rule_id: str, key: str) -> tuple[str, ...]:
    """Coerce a selector value to a tuple of non-empty glob strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        candidates = [value]
    elif isinstance(value, (list, tuple)):
        candidates = list(value)
    else:
        raise SuppressionConfigError(f"suppressions entry for {rule_id!r}: {key!r} must be a string or a list")

    patterns: list[str] = []
    for candidate in candidates:
        if not isinstance(candidate, str) or not candidate.strip():
            raise SuppressionConfigError(f"suppressions entry for {rule_id!r}: {key!r} contains a non-string pattern")
        patterns.append(candidate.strip())
    return tuple(patterns)


def _parse_expiry(value: object, *, rule_id: str) -> date | None:
    """Parse ``expires`` from a ``date`` or an ISO ``YYYY-MM-DD`` string."""
    if value is None:
        return None
    if isinstance(value, date):
        # PyYAML already parses unquoted YYYY-MM-DD into datetime.date.
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value.strip())
        except ValueError as exc:
            raise SuppressionConfigError(
                f"suppressions entry for {rule_id!r}: 'expires' must be an ISO date (YYYY-MM-DD), got {value!r}"
            ) from exc
    raise SuppressionConfigError(f"suppressions entry for {rule_id!r}: 'expires' must be an ISO date (YYYY-MM-DD)")


def suppression_from_dict(entry: object) -> SuppressionRule:
    """Build a :class:`SuppressionRule` from one raw policy mapping.

    Unknown keys are rejected rather than ignored: the policy loader has no
    schema, so a typo such as ``skill:`` instead of ``skills:`` would otherwise
    silently widen or void the suppression.
    """
    if not isinstance(entry, dict):
        raise SuppressionConfigError(f"suppressions entries must be mappings, got {type(entry).__name__}")

    known = {"rule_id", "skills", "paths", "reason", "severity", "expires"}
    unknown = sorted(set(entry) - known)
    rule_id_raw = entry.get("rule_id")
    rule_id = rule_id_raw.strip() if isinstance(rule_id_raw, str) else ""
    if unknown:
        raise SuppressionConfigError(
            f"suppressions entry for {rule_id or '<missing rule_id>'!r}: unknown key(s) "
            f"{', '.join(repr(k) for k in unknown)}; expected any of {', '.join(sorted(known))}"
        )
    if not rule_id:
        raise SuppressionConfigError("suppressions entry is missing a non-empty 'rule_id'")

    skills = _as_pattern_tuple(entry.get("skills"), rule_id=rule_id, key="skills")
    paths = _as_pattern_tuple(entry.get("paths"), rule_id=rule_id, key="paths")
    if not skills and not paths:
        raise SuppressionConfigError(
            f"suppressions entry for {rule_id!r} has no selector; add 'skills' and/or 'paths', "
            "or use 'disabled_rules' to disable the rule everywhere"
        )

    severity_raw = entry.get("severity")
    severity: str | None = None
    if severity_raw is not None:
        if not isinstance(severity_raw, str) or severity_raw.strip().upper() not in _ASSIGNABLE_SEVERITIES:
            raise SuppressionConfigError(
                f"suppressions entry for {rule_id!r}: 'severity' must be one of "
                f"{', '.join(sorted(_ASSIGNABLE_SEVERITIES))}"
            )
        severity = severity_raw.strip().upper()

    reason_raw = entry.get("reason", "")
    if reason_raw is not None and not isinstance(reason_raw, str):
        raise SuppressionConfigError(f"suppressions entry for {rule_id!r}: 'reason' must be a string")

    return SuppressionRule(
        rule_id=rule_id,
        skills=skills,
        paths=paths,
        reason=(reason_raw or "").strip(),
        severity=severity,
        expires=_parse_expiry(entry.get("expires"), rule_id=rule_id),
    )


def normalize_path(value: str | None) -> str:
    """Normalize a finding path for matching.

    ``SkillFile.relative_path`` is built with ``str(...)`` so it carries OS
    separators; Windows scans therefore produce ``scripts\\run.py``.  Matching is
    case-insensitive, consistent with the finding dedupe keys elsewhere in the
    scanner.
    """
    if not value:
        return ""
    normalized = value.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lower()


def glob_match(pattern: str, value: str) -> bool:
    """Match *value* against a ``/``-aware glob *pattern*.

    Matching is segment-wise: ``*`` and ``?`` never cross a ``/``, and ``**``
    consumes any number of segments.  Plain :func:`fnmatch.fnmatch` is
    deliberately not used on the whole path, because its ``*`` spans separators
    and ``assets/*.pdf`` would then also silence ``assets/nested/evil.pdf``.
    """
    pattern_parts = [part for part in pattern.replace("\\", "/").lower().split("/") if part not in ("", ".")]
    value_parts = [part for part in value.split("/") if part not in ("", ".")]
    return _match_segments(pattern_parts, value_parts)


def _match_segments(pattern_parts: list[str], value_parts: list[str]) -> bool:
    """Recursive segment matcher backing :func:`glob_match`."""
    if not pattern_parts:
        return not value_parts
    head, rest = pattern_parts[0], pattern_parts[1:]
    if head == "**":
        # '**' may consume zero or more segments.
        for index in range(len(value_parts) + 1):
            if _match_segments(rest, value_parts[index:]):
                return True
        return False
    if not value_parts:
        return False
    if not fnmatch.fnmatchcase(value_parts[0], head):
        return False
    return _match_segments(rest, value_parts[1:])


def _matched_selectors(rule: SuppressionRule, skill_name: str, file_path: str) -> dict[str, str] | None:
    """Return the concrete patterns that matched, or ``None`` when they do not.

    Selector kinds are ANDed; patterns within one kind are ORed.
    """
    matched: dict[str, str] = {}
    if rule.skills:
        hit = next((p for p in rule.skills if fnmatch.fnmatchcase(skill_name.lower(), p.lower())), None)
        if hit is None:
            return None
        matched["matched_skill"] = hit
    if rule.paths:
        if not file_path:
            return None
        hit = next((p for p in rule.paths if glob_match(p, file_path)), None)
        if hit is None:
            return None
        matched["matched_path"] = hit
    return matched


@dataclass
class SuppressionOutcome:
    """Result of applying scoped suppressions to one batch of findings."""

    kept: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    expired_suppressions: list[tuple[int, SuppressionRule]] = field(default_factory=list)


def apply_suppressions(
    findings: list[Finding],
    rules: list[SuppressionRule],
    skill_name: str,
    *,
    today: date | None = None,
) -> SuppressionOutcome:
    """Apply the first matching active suppression to each finding.

    A severity match re-rates the finding; other matches suppress it. Findings
    with existing suppression metadata and cross-skill findings pass through
    unchanged, preventing double application across scan phases.

    Args:
        findings: Findings to evaluate.
        rules: Scoped suppression rules.
        skill_name: Name matched by skill selectors.
        today: Date used to evaluate expiry.

    Returns:
        Kept, suppressed, and expired-rule results.
    """
    outcome = SuppressionOutcome()
    if not rules:
        outcome.kept = findings
        return outcome

    current_day = today or date.today()
    by_rule_id: dict[str, list[SuppressionRule]] = {}
    for index, rule in enumerate(rules):
        if not rule.is_active(current_day):
            outcome.expired_suppressions.append((index, rule))
            continue
        by_rule_id.setdefault(rule.rule_id, []).append(rule)

    for finding in findings:
        candidates = by_rule_id.get(finding.rule_id)
        already_applied = "suppression" in (finding.metadata or {})
        if not candidates or finding.file_path == CROSS_SKILL_PATH or already_applied:
            outcome.kept.append(finding)
            continue

        normalized = normalize_path(finding.file_path)
        for rule in candidates:
            matched = _matched_selectors(rule, skill_name, normalized)
            if matched is None:
                continue
            record: dict[str, object] = {"rule_id": rule.rule_id, "reason": rule.reason, **matched}
            if rule.expires is not None:
                record["expires"] = rule.expires.isoformat()
            if rule.severity:
                record["previous_severity"] = finding.severity.value
                record["severity"] = rule.severity
                finding.metadata["suppression"] = record
                finding.severity = Severity(rule.severity)
                outcome.kept.append(finding)
            else:
                finding.metadata["suppression"] = record
                outcome.suppressed.append(finding)
            break
        else:
            outcome.kept.append(finding)

    return outcome


def build_suppression_summary(suppressed: list[Finding]) -> dict[str, object]:
    """Build bounded audit metadata for suppressed findings.

    Distinct entries are capped at ``_MAX_SUMMARY_ENTRIES``; overflow sets
    ``truncated`` instead of failing the scan.
    """
    per_entry: dict[tuple[str, str, str, str], int] = {}
    truncated = False
    for finding in suppressed:
        record = finding.metadata.get("suppression") or {}
        key = (
            str(record.get("rule_id", finding.rule_id)),
            str(record.get("reason", "")),
            str(record.get("matched_skill", "")),
            str(record.get("matched_path", "")),
        )
        if key not in per_entry and len(per_entry) >= _MAX_SUMMARY_ENTRIES:
            truncated = True
            continue
        per_entry[key] = per_entry.get(key, 0) + 1

    entries = [
        {
            "rule_id": rule_id,
            "reason": reason,
            "matched_skill": matched_skill,
            "matched_path": matched_path,
            "count": count,
        }
        for (rule_id, reason, matched_skill, matched_path), count in sorted(per_entry.items())
    ]
    summary: dict[str, object] = {"suppressed": len(suppressed), "entries": entries}
    if truncated:
        summary["truncated"] = True
    return summary
