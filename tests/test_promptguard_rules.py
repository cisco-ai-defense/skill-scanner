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

"""Regression tests for bundled PromptGuard signature rules."""

from pathlib import Path

import pytest

from skill_scanner.core.rules.patterns import RuleLoader, SecurityRule
from skill_scanner.data import DATA_DIR


@pytest.fixture(scope="module")
def pii_detection_rules() -> list[SecurityRule]:
    signatures = DATA_DIR / "packs" / "promptguard" / "signatures" / "pii_detection.yaml"
    return RuleLoader(rules_file=signatures).load_rules()


@pytest.fixture(scope="module")
def ssn_harvesting_rule(pii_detection_rules: list[SecurityRule]) -> SecurityRule:
    return next(rule for rule in pii_detection_rules if rule.id == "PG_PII_SSN_HARVESTING")


@pytest.fixture(scope="module")
def credit_card_rule(pii_detection_rules: list[SecurityRule]) -> SecurityRule:
    return next(rule for rule in pii_detection_rules if rule.id == "PG_PII_CREDIT_CARD")


@pytest.mark.parametrize(
    "sentence",
    [
        "Ask the user for any missing fields.",
        "Request a single configuration value.",
        "Prompt the user while using the setup wizard.",
        "Save the parsed casing information.",
    ],
)
def test_ssn_harvesting_acronyms_do_not_match_inside_words(
    ssn_harvesting_rule: SecurityRule,
    sentence: str,
) -> None:
    assert ssn_harvesting_rule.scan_content(sentence, "SKILL.md") == []


@pytest.mark.parametrize(
    "sentence",
    [
        "Ask the user for their SIN.",
        "Request the customer's SSN.",
        "Collect social security information.",
        "Require a national insurance identifier.",
        "Prompt them for an NI number.",
    ],
)
def test_ssn_harvesting_identifiers_still_match_at_word_boundaries(
    ssn_harvesting_rule: SecurityRule,
    sentence: str,
) -> None:
    matches = ssn_harvesting_rule.scan_content(sentence, "SKILL.md")
    assert len(matches) == 1
    assert Path(matches[0]["file_path"]).name == "SKILL.md"


@pytest.mark.parametrize(
    "sentence",
    [
        # A 16+ significant-digit float repr can contain a run that matches
        # a card-number pattern once it is read starting after the ".".
        "weights = [2.5399666666666668, 7.25, 12.5]",
        "x = 0.4111111111111111",
        "ratio = 3.4123456789012345",
    ],
)
def test_credit_card_does_not_match_inside_decimal_fractions(
    credit_card_rule: SecurityRule,
    sentence: str,
) -> None:
    assert credit_card_rule.scan_content(sentence, "weights.py") == []


@pytest.mark.parametrize(
    "sentence",
    [
        "card: 5105 1051 0510 5100",
        "4012-8888-8888-1881",
        "3782 822463 10005",
        "6011 0009 9013 9424",
        "The card number is 4012888888881881.",
        "4012888888881881, exp 12/30",
    ],
)
def test_credit_card_still_matches_real_numbers(
    credit_card_rule: SecurityRule,
    sentence: str,
) -> None:
    matches = credit_card_rule.scan_content(sentence, "notes.md")
    assert len(matches) == 1
    assert Path(matches[0]["file_path"]).name == "notes.md"
