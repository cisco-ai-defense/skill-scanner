# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests for reference-document source discovery."""

from scripts.generate_reference_docs import (
    _collect_env_variables,
    _extract_python_env_variables,
    _render_api_reference,
    _render_cli_reference,
    _render_configuration_reference,
)


def test_environment_discovery_ignores_comments_and_docstrings() -> None:
    source = '''
import os

ENV_NAME = "CONSTANT_ENV"
"""Example only: os.getenv("DOCSTRING_ENV")"""
# Example only: os.environ.get("COMMENT_ENV")
direct = os.getenv("DIRECT_ENV")
constant = os.environ.get(ENV_NAME)
'''

    assert _extract_python_env_variables(source) == {"CONSTANT_ENV", "DIRECT_ENV"}


def test_reasoning_environment_variables_map_to_runtime_resolver() -> None:
    env_map = _collect_env_variables()

    for variable in (
        "SKILL_SCANNER_LLM_REASONING_EFFORT",
        "SKILL_SCANNER_META_LLM_REASONING_EFFORT",
    ):
        assert "skill_scanner/llm_reasoning.py" in env_map[variable]


def test_generated_references_document_google_reasoning_limitation() -> None:
    expected = "Direct Google GenAI SDK requests reject configured controls"

    assert expected in _render_cli_reference()
    assert expected in _render_api_reference()
    assert expected in _render_configuration_reference()
