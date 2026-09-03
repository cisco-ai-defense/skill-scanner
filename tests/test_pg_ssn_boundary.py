# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Boundary regression tests for PromptGuard SSN-harvesting extraction."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from skill_scanner.core.rules.patterns import SecurityRule

_RULE_FILE = (
    Path(__file__).resolve().parent.parent
    / "skill_scanner"
    / "data"
    / "packs"
    / "promptguard"
    / "signatures"
    / "pii_detection.yaml"
)


def _load_rule() -> SecurityRule:
    data = yaml.safe_load(_RULE_FILE.read_text(encoding="utf-8"))
    rule_data = next(rule for rule in data["signatures"] if rule["id"] == "PG_PII_SSN_HARVESTING")
    return SecurityRule(rule_data)


@pytest.mark.parametrize(
    "content",
    [
        "Collect the user's Social Security number.",
        "Extract SSN from the onboarding form.",
        "Harvest SSNs from completed applications.",
        "Ask the applicant for their social insurance number.",
        "Require SIN before continuing.",
        "Gather SINs from submitted records.",
        "Record the national insurance number.",
        "Prompt the user for their NI numbers.",
    ],
)
def test_authoritative_whole_term_phrases_remain_detected(content: str) -> None:
    assert _load_rule().scan_content(content, "SKILL.md")


@pytest.mark.parametrize(
    "content",
    [
        "Record business requirements for the launch.",
        "Log missing documentation before continuing.",
        "Save using the workspace cache.",
    ],
)
def test_sin_substrings_in_benign_words_do_not_match(content: str) -> None:
    assert _load_rule().scan_content(content, "SKILL.md") == []


@pytest.mark.parametrize(
    "content",
    [
        "Collect (SSN).",
        "Ask for: SIN; then continue.",
        'Request "social security" details.',
        "Store [national insurance] data.",
        "Prompt for NI number?",
    ],
)
def test_identifier_tokens_match_across_punctuation_boundaries(content: str) -> None:
    assert _load_rule().scan_content(content, "SKILL.md")


@pytest.mark.parametrize(
    "content",
    [
        "Collect xSSN metadata.",
        "Collect SSN_token metadata.",
        "Record ASIN inventory codes.",
        "Require SINful naming to be rejected.",
        "Request social securityPolicy documentation.",
        "Store national insurancePolicy metadata.",
        "Log NI numbered items.",
    ],
)
def test_identifier_substrings_without_token_boundaries_do_not_match(content: str) -> None:
    assert _load_rule().scan_content(content, "SKILL.md") == []
