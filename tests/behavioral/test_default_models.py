# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Regression: the behavioral analyzer's fallback model must not be a retired Gemini model."""

import inspect

import pytest

from skill_scanner.core.analyzers.behavioral.alignment.alignment_llm_client import AlignmentLLMClient
from skill_scanner.core.analyzers.behavioral.alignment.alignment_orchestrator import AlignmentOrchestrator
from skill_scanner.core.analyzers.behavioral.alignment.threat_vulnerability_classifier import (
    ThreatVulnerabilityClassifier,
)

EXPECTED_DEFAULT = "gemini/gemini-3.8-flash"


@pytest.mark.parametrize(
    ("cls", "param"),
    [
        (AlignmentLLMClient, "model"),
        (AlignmentOrchestrator, "llm_model"),
        (ThreatVulnerabilityClassifier, "model"),
    ],
)
def test_alignment_default_model_is_current(cls, param):
    default = inspect.signature(cls.__init__).parameters[param].default
    assert default == EXPECTED_DEFAULT


def test_behavioral_analyzer_env_fallback_is_current(monkeypatch, tmp_path):
    from unittest.mock import patch

    from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer

    monkeypatch.delenv("SKILL_SCANNER_LLM_MODEL", raising=False)
    monkeypatch.delenv("SKILL_SCANNER_LLM_PROVIDER", raising=False)
    monkeypatch.setenv("SKILL_SCANNER_LLM_API_KEY", "test-key")
    with patch("skill_scanner.core.analyzers.behavioral.alignment.AlignmentOrchestrator") as orchestrator:
        BehavioralAnalyzer(use_alignment_verification=True)
    assert orchestrator.call_args.kwargs["llm_model"] == EXPECTED_DEFAULT
