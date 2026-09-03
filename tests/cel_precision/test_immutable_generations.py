# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Immutable identity checks for the bundled core CEL generation."""

from __future__ import annotations

import pytest

from skill_scanner.core.cel.models import CelRule, expression_set_hash

from .expressions import BUNDLED_SCANNER_OWNED_SHADOW_GATES, SCANNER_OWNED_SHADOW_GATES

BUNDLED_EXPRESSION_SET_HASH = "f26459b8f4a46a974d7ab0aaae34127b5b6a40d693e266e12fca03a69a6d26aa"


def _hash(expressions) -> str:
    return expression_set_hash(
        CelRule(rule_id=rule_id, expression=expression, pack_name="core") for rule_id, expression in expressions.items()
    )


def test_reviewed_core_generation_hash_is_exact() -> None:
    assert _hash(BUNDLED_SCANNER_OWNED_SHADOW_GATES) == BUNDLED_EXPRESSION_SET_HASH


def test_scanner_owned_generation_has_exact_bundled_shadow_subset() -> None:
    assert set(BUNDLED_SCANNER_OWNED_SHADOW_GATES) == {
        "ALLOWED_TOOLS_NETWORK_USAGE",
        "COMPOUND_FIND_EXEC",
        "FIND_EXEC_PATTERN",
        "GLOB_HIDDEN_FILE_TARGETING",
        "HIDDEN_EXECUTABLE_SCRIPT",
        "UNANALYZABLE_BINARY",
        "YARA_SUSP_Multi_RemoteMiner_AcquireExec_Sep26",
        "YARA_embedded_shebang_in_binary",
    }
    assert set(BUNDLED_SCANNER_OWNED_SHADOW_GATES) < set(SCANNER_OWNED_SHADOW_GATES)


def test_generations_are_runtime_immutable() -> None:
    with pytest.raises(TypeError):
        BUNDLED_SCANNER_OWNED_SHADOW_GATES["UNREVIEWED"] = "true"  # type: ignore[index]
    with pytest.raises(TypeError):
        SCANNER_OWNED_SHADOW_GATES["UNREVIEWED"] = "true"  # type: ignore[index]
