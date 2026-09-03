# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Regression coverage for the policy configurator's Textual contract."""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version

from skill_scanner.cli.policy_tui import PolicyConfigApp

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_textual_dependency_accepts_supported_seven_and_eight_lines() -> None:
    """Downstream Textual 8 applications must resolve with Skill Scanner."""

    document = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    textual = next(
        Requirement(value) for value in document["project"]["dependencies"] if Requirement(value).name == "textual"
    )

    assert Version("7.0.0") in textual.specifier
    assert Version("8.2.8") in textual.specifier
    assert Version("9.0.0") not in textual.specifier


@pytest.mark.asyncio
async def test_policy_configurator_mounts_on_locked_textual() -> None:
    """Boot the real TUI so dependency-only changes cannot mask API drift."""

    app = PolicyConfigApp(output_path="unused.yaml")
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        assert app.query_one("#policy-name-input").value == app.policy.policy_name == "default"
        assert app.query_one("#preset-balanced").value is True
