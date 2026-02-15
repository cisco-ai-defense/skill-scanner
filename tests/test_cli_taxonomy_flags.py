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

"""Tests for taxonomy and threat-mapping CLI flags."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest


def run_cli(args: list[str], timeout: int = 60) -> tuple[str, str, int]:
    """Run the skill-scanner CLI and return stdout, stderr, return code."""
    cmd = [sys.executable, "-m", "skill_scanner.cli.cli"] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=Path(__file__).parent.parent,
    )
    return result.stdout, result.stderr, result.returncode


class TestTaxonomyFlagRegistration:
    """Verify CLI help includes runtime taxonomy flags."""

    def test_scan_help_includes_taxonomy_flags(self):
        stdout, _, code = run_cli(["scan", "--help"])
        assert code == 0
        assert "--taxonomy" in stdout
        assert "--threat-mapping" in stdout

    def test_scan_all_help_includes_taxonomy_flags(self):
        stdout, _, code = run_cli(["scan-all", "--help"])
        assert code == 0
        assert "--taxonomy" in stdout
        assert "--threat-mapping" in stdout


class TestTaxonomyFlagWiring:
    """Verify runtime configuration helper wiring."""

    def test_configure_helper_forwards_cli_paths(self):
        from skill_scanner.cli.cli import _configure_taxonomy_and_threat_mapping

        args = argparse.Namespace(
            taxonomy="/tmp/custom_taxonomy.json",
            threat_mapping="/tmp/custom_mapping.json",
        )
        status_messages: list[str] = []

        with (
            patch("skill_scanner.threats.cisco_ai_taxonomy.reload_taxonomy") as mock_reload,
            patch("skill_scanner.threats.threats.configure_threat_mappings") as mock_configure,
        ):
            mock_reload.return_value = "/tmp/custom_taxonomy.json"
            mock_configure.return_value = "/tmp/custom_mapping.json"
            _configure_taxonomy_and_threat_mapping(args, status_messages.append)

        mock_reload.assert_called_once_with("/tmp/custom_taxonomy.json")
        mock_configure.assert_called_once_with("/tmp/custom_mapping.json")
        assert any("custom taxonomy profile" in msg for msg in status_messages)
        assert any("custom threat mapping profile" in msg for msg in status_messages)

    def test_configure_helper_builtin_no_status(self):
        from skill_scanner.cli.cli import _configure_taxonomy_and_threat_mapping

        args = argparse.Namespace(taxonomy=None, threat_mapping=None)
        status_messages: list[str] = []

        with (
            patch("skill_scanner.threats.cisco_ai_taxonomy.reload_taxonomy", return_value="builtin") as mock_reload,
            patch("skill_scanner.threats.threats.configure_threat_mappings", return_value="builtin") as mock_configure,
        ):
            _configure_taxonomy_and_threat_mapping(args, status_messages.append)

        mock_reload.assert_called_once_with(None)
        mock_configure.assert_called_once_with(None)
        assert status_messages == []


class TestTaxonomyFlagRuntimeErrors:
    """Verify scanner command fails cleanly on invalid taxonomy path."""

    @pytest.fixture
    def safe_skill_dir(self):
        return Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"

    def test_invalid_taxonomy_path_returns_error(self, safe_skill_dir):
        _, stderr, code = run_cli(
            [
                "scan",
                str(safe_skill_dir),
                "--format",
                "json",
                "--taxonomy",
                "/nonexistent/custom_taxonomy.json",
            ]
        )
        assert code == 1
        assert "Error loading taxonomy configuration" in stderr
