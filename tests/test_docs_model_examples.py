# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Regression: copy-paste model examples must not name models the provider has shut down."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Model ids that the provider no longer serves; a user who copies them gets a 404.
RETIRED_MODEL_EXAMPLES = [
    (".env.example", "vertex_ai/gemini-1.5-pro"),
    ("docs/architecture/analyzers/llm-analyzer.md", "claude-opus-4-20250514"),
    ("docs/architecture/analyzers/llm-analyzer.md", "gpt-4-turbo"),
    ("docs/architecture/analyzers/llm-analyzer.md", "gemini-2.0-flash-exp"),
    ("docs/reference/dependencies-and-llm-providers.md", "vertex_ai/gemini-2.5-pro"),
    ("docs/reference/dependencies-and-llm-providers.md", "gemini/gemini-2.5-flash"),
]


@pytest.mark.parametrize(("relative_path", "retired_model"), RETIRED_MODEL_EXAMPLES)
def test_examples_do_not_name_retired_models(relative_path, retired_model):
    text = (ROOT / relative_path).read_text(encoding="utf-8")
    assert retired_model not in text
