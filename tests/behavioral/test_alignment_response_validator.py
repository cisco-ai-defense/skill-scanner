# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Tests for AlignmentResponseValidator."""

import logging

from skill_scanner.core.analyzers.behavioral.alignment.alignment_response_validator import (
    AlignmentResponseValidator,
)


def test_fenced_json_is_validated_without_invalid_json_warning(caplog):
    """A successful markdown fallback must not emit a misleading warning."""
    response = '```json\n{"mismatch_detected": false}\n```'

    with caplog.at_level(logging.WARNING):
        result = AlignmentResponseValidator().validate(response)

    assert result == {"mismatch_detected": False}
    assert "Invalid JSON response" not in caplog.text
