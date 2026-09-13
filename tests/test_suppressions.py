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

"""Unit tests for scoped suppression parsing and matching."""

from datetime import date

import pytest

from skill_scanner.core.models import Finding, Severity, ThreatCategory
from skill_scanner.core.suppressions import (
    CROSS_SKILL_PATH,
    SuppressionConfigError,
    apply_suppressions,
    build_suppression_summary,
    glob_match,
    normalize_path,
    suppression_from_dict,
)


def _finding(rule_id: str = "NOISY_RULE", file_path: str = "scripts/run.py") -> Finding:
    return Finding(
        id=f"{rule_id}-1",
        rule_id=rule_id,
        category=ThreatCategory.POLICY_VIOLATION,
        severity=Severity.HIGH,
        title="Noisy rule",
        description="Something the operator has already reviewed",
        file_path=file_path,
    )


class TestGlobMatch:
    """Path globs must not silently widen a suppression."""

    def test_single_star_does_not_cross_a_separator(self):
        assert glob_match("assets/*.pdf", "assets/report.pdf")
        assert not glob_match("assets/*.pdf", "assets/nested/evil.pdf")

    def test_double_star_matches_any_depth(self):
        assert glob_match("**/fixtures/**/*.zip", "tests/fixtures/data/sample.zip")
        assert glob_match("**/fixtures/**/*.zip", "fixtures/sample.zip")
        assert not glob_match("**/fixtures/**/*.zip", "tests/data/sample.zip")

    def test_double_star_consumes_zero_segments(self):
        assert glob_match("scripts/**/run.py", "scripts/run.py")

    def test_question_mark_matches_one_character(self):
        assert glob_match("v?.py", "v1.py")
        assert not glob_match("v?.py", "v10.py")

    def test_exact_path_matches_itself(self):
        assert glob_match("SKILL.md", "skill.md")


class TestNormalizePath:
    def test_windows_separators_are_normalized(self):
        assert normalize_path("scripts\\run.py") == "scripts/run.py"

    def test_leading_dot_slash_is_stripped(self):
        assert normalize_path("./scripts/run.py") == "scripts/run.py"

    def test_matching_is_case_insensitive(self):
        assert normalize_path("Scripts/Run.PY") == "scripts/run.py"

    def test_missing_path_normalizes_to_empty(self):
        assert normalize_path(None) == ""


class TestSuppressionFromDict:
    def test_minimal_skill_selector(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["docs-*"], "reason": "reviewed"})
        assert rule.rule_id == "NOISY_RULE"
        assert rule.skills == ("docs-*",)
        assert rule.paths == ()
        assert rule.reason == "reviewed"

    def test_string_selector_is_accepted(self):
        assert suppression_from_dict({"rule_id": "R", "paths": "a/b.py"}).paths == ("a/b.py",)

    def test_entry_without_selector_is_rejected(self):
        with pytest.raises(SuppressionConfigError, match="no selector"):
            suppression_from_dict({"rule_id": "NOISY_RULE", "reason": "everywhere"})

    def test_unknown_key_is_rejected(self):
        with pytest.raises(SuppressionConfigError, match="unknown key"):
            suppression_from_dict({"rule_id": "NOISY_RULE", "skill": ["typo"]})

    def test_missing_rule_id_is_rejected(self):
        with pytest.raises(SuppressionConfigError, match="rule_id"):
            suppression_from_dict({"skills": ["a"]})

    def test_invalid_severity_is_rejected(self):
        with pytest.raises(SuppressionConfigError, match="severity"):
            suppression_from_dict({"rule_id": "R", "skills": ["a"], "severity": "NOPE"})

    def test_safe_is_not_an_assignable_severity(self):
        with pytest.raises(SuppressionConfigError, match="severity"):
            suppression_from_dict({"rule_id": "R", "skills": ["a"], "severity": "SAFE"})

    def test_invalid_expiry_is_rejected(self):
        with pytest.raises(SuppressionConfigError, match="ISO date"):
            suppression_from_dict({"rule_id": "R", "skills": ["a"], "expires": "next tuesday"})

    def test_expiry_accepts_iso_string_and_date(self):
        assert suppression_from_dict({"rule_id": "R", "skills": ["a"], "expires": "2030-01-31"}).expires == date(
            2030, 1, 31
        )
        # PyYAML parses an unquoted YYYY-MM-DD into datetime.date already.
        assert suppression_from_dict({"rule_id": "R", "skills": ["a"], "expires": date(2030, 1, 31)}).expires == date(
            2030, 1, 31
        )

    def test_round_trip_to_dict_omits_empty_fields(self):
        rule = suppression_from_dict({"rule_id": "R", "skills": ["a"]})
        assert rule.to_dict() == {"rule_id": "R", "skills": ["a"]}


class TestApplySuppressions:
    def test_skill_selector_suppresses_only_the_named_skill(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["docs-translator"], "reason": "prose"})

        matched = apply_suppressions([_finding()], [rule], "docs-translator")
        assert matched.kept == []
        assert len(matched.suppressed) == 1
        assert matched.suppressed[0].metadata["suppression"]["matched_skill"] == "docs-translator"

        other = apply_suppressions([_finding()], [rule], "aws-cost-report")
        assert len(other.kept) == 1
        assert other.suppressed == []

    def test_selectors_are_anded(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["alpha"], "paths": ["scripts/*.py"]})

        assert apply_suppressions([_finding()], [rule], "alpha").suppressed
        assert not apply_suppressions([_finding(file_path="docs/run.py")], [rule], "alpha").suppressed
        assert not apply_suppressions([_finding()], [rule], "beta").suppressed

    def test_other_rules_are_untouched(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["alpha"]})
        outcome = apply_suppressions([_finding(rule_id="OTHER_RULE")], [rule], "alpha")
        assert len(outcome.kept) == 1

    def test_severity_entry_re_rates_instead_of_hiding(self):
        rule = suppression_from_dict(
            {"rule_id": "NOISY_RULE", "skills": ["alpha"], "severity": "LOW", "reason": "reviewed"}
        )
        outcome = apply_suppressions([_finding()], [rule], "alpha")

        assert outcome.suppressed == []
        assert len(outcome.kept) == 1
        kept = outcome.kept[0]
        assert kept.severity == Severity.LOW
        assert kept.metadata["suppression"]["previous_severity"] == "HIGH"

    def test_severity_entry_can_raise_as_well_as_lower(self):
        """The field re-rates in either direction; the docs say so."""
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["alpha"], "severity": "CRITICAL"})
        outcome = apply_suppressions([_finding()], [rule], "alpha")

        assert outcome.kept[0].severity == Severity.CRITICAL
        assert outcome.kept[0].metadata["suppression"]["previous_severity"] == "HIGH"

    def test_an_entry_applies_at_most_once_to_a_finding(self):
        """The scanner runs this twice per skill; the second pass must not re-apply.

        Rewriting the record on the second pass would read the already re-rated
        severity and destroy the only copy of the original rating.
        """
        rule = suppression_from_dict(
            {"rule_id": "NOISY_RULE", "skills": ["alpha"], "severity": "LOW", "reason": "reviewed"}
        )
        first = apply_suppressions([_finding()], [rule], "alpha")
        second = apply_suppressions(first.kept, [rule], "alpha")

        kept = second.kept[0]
        assert kept.severity == Severity.LOW
        assert kept.metadata["suppression"]["previous_severity"] == "HIGH"

    def test_second_pass_does_not_re_rate_an_adjudicator_demotion(self):
        """The adjudicator runs between the two passes and its verdict must hold."""
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["alpha"], "severity": "LOW"})
        first = apply_suppressions([_finding()], [rule], "alpha")

        demoted = first.kept[0]
        demoted.severity = Severity.INFO
        demoted.metadata["adjudication"] = {"demoted_to": "INFO"}

        second = apply_suppressions([demoted], [rule], "alpha")
        assert second.kept[0].severity == Severity.INFO

    def test_second_pass_does_not_re_suppress_an_already_suppressed_finding(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["alpha"], "reason": "reviewed"})
        first = apply_suppressions([_finding()], [rule], "alpha")
        assert len(first.suppressed) == 1

        second = apply_suppressions(first.suppressed, [rule], "alpha")
        assert second.suppressed == []
        assert len(second.kept) == 1

    def test_expired_entry_is_inert_and_reported(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["alpha"], "expires": "2020-01-01"})
        outcome = apply_suppressions([_finding()], [rule], "alpha", today=date(2026, 1, 1))

        assert outcome.suppressed == []
        assert len(outcome.kept) == 1
        assert outcome.expired_rule_ids == {"NOISY_RULE"}

    def test_entry_expiring_today_is_still_active(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["alpha"], "expires": "2026-01-01"})
        outcome = apply_suppressions([_finding()], [rule], "alpha", today=date(2026, 1, 1))
        assert len(outcome.suppressed) == 1

    def test_cross_skill_findings_are_never_suppressed(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["*"]})
        outcome = apply_suppressions([_finding(file_path=CROSS_SKILL_PATH)], [rule], "alpha")
        assert outcome.suppressed == []
        assert len(outcome.kept) == 1

    def test_path_selector_requires_a_path(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "paths": ["*.py"]})
        outcome = apply_suppressions([_finding(file_path=None)], [rule], "alpha")
        assert outcome.suppressed == []

    def test_no_rules_returns_findings_unchanged(self):
        findings = [_finding()]
        assert apply_suppressions(findings, [], "alpha").kept is findings

    def test_windows_style_path_is_matched(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "paths": ["scripts/*.py"]})
        outcome = apply_suppressions([_finding(file_path="scripts\\run.py")], [rule], "alpha")
        assert len(outcome.suppressed) == 1


class TestSuppressionSummary:
    def test_summary_counts_identical_entries(self):
        rule = suppression_from_dict({"rule_id": "NOISY_RULE", "skills": ["alpha"], "reason": "reviewed"})
        outcome = apply_suppressions([_finding(), _finding()], [rule], "alpha")

        summary = build_suppression_summary(outcome.suppressed)
        assert summary["suppressed"] == 2
        assert summary["entries"] == [
            {
                "rule_id": "NOISY_RULE",
                "reason": "reviewed",
                "matched_skill": "alpha",
                "matched_path": "",
                "count": 2,
            }
        ]

    def test_empty_summary_has_no_entries(self):
        assert build_suppression_summary([]) == {"suppressed": 0, "entries": []}
