# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Tests for reference-document source discovery."""

from scripts.generate_reference_docs import _extract_python_env_variables


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
