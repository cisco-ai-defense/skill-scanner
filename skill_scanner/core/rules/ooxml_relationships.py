# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Normalize OleID's Office macro indicators without truthiness bugs."""

from __future__ import annotations

VBA_MACRO = "vba"
XLM_MACRO = "xlm"
INCONCLUSIVE_MACRO_ANALYSIS = "inconclusive"


def classify_oleid_macro_indicator(indicator_id: object, value: object) -> str | None:
    """Normalize real OleID macro IDs and their string-valued states.

    OleID emits ``vba`` and ``xlm`` with values such as ``Yes`` and ``No``;
    treating those strings as booleans would make both truthy.  Legacy aliases
    are accepted for compatibility with older test doubles.  Unknown states
    remain actionable rather than being mistaken for a clean result.
    """

    aliases = {
        "vba": VBA_MACRO,
        "vba_macros": VBA_MACRO,
        "xlm": XLM_MACRO,
        "xlm_macros": XLM_MACRO,
    }
    kind = aliases.get(str(indicator_id))
    if kind is None:
        return None
    if isinstance(value, bool):
        return kind if value else None
    if isinstance(value, (int, float)):
        return kind if value != 0 else None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized.startswith("yes") or normalized in {"detected", "present", "true"}:
            return kind
        if normalized in {"0", "absent", "false", "no", "none"}:
            return None
    return INCONCLUSIVE_MACRO_ANALYSIS


__all__ = [
    "INCONCLUSIVE_MACRO_ANALYSIS",
    "VBA_MACRO",
    "XLM_MACRO",
    "classify_oleid_macro_indicator",
]
