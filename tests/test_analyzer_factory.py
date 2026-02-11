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

"""
Tests for the centralized analyzer factory (``skill_scanner.core.analyzer_factory``).

These tests verify the root-cause fix for Bug 7 and Bug 8: that every
entry point builds the same core analyzers with the same policy.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from skill_scanner.core.analyzer_factory import build_analyzers, build_core_analyzers
from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.scan_policy import ScanPolicy


class TestBuildCoreAnalyzers:
    """Tests for ``build_core_analyzers()``."""

    def test_default_policy_returns_three_analyzers(self):
        """Default policy enables static, bytecode, pipeline."""
        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy)
        names = sorted(a.get_name() for a in analyzers)
        assert names == ["bytecode", "pipeline", "static_analyzer"]

    def test_disable_static(self):
        """Disabling static in policy removes StaticAnalyzer."""
        policy = ScanPolicy.default()
        policy.analyzers.static = False
        analyzers = build_core_analyzers(policy)
        names = [a.get_name() for a in analyzers]
        assert "static_analyzer" not in names
        assert "bytecode" in names
        assert "pipeline" in names

    def test_disable_bytecode(self):
        """Disabling bytecode in policy removes BytecodeAnalyzer."""
        policy = ScanPolicy.default()
        policy.analyzers.bytecode = False
        analyzers = build_core_analyzers(policy)
        names = [a.get_name() for a in analyzers]
        assert "bytecode" not in names
        assert "static_analyzer" in names

    def test_disable_pipeline(self):
        """Disabling pipeline in policy removes PipelineAnalyzer."""
        policy = ScanPolicy.default()
        policy.analyzers.pipeline = False
        analyzers = build_core_analyzers(policy)
        names = [a.get_name() for a in analyzers]
        assert "pipeline" not in names
        assert "static_analyzer" in names

    def test_disable_all(self):
        """Disabling all analyzers returns empty list."""
        policy = ScanPolicy.default()
        policy.analyzers.static = False
        policy.analyzers.bytecode = False
        policy.analyzers.pipeline = False
        analyzers = build_core_analyzers(policy)
        assert analyzers == []

    def test_all_analyzers_receive_policy(self):
        """Every analyzer returned by the factory must have self.policy == policy."""
        policy = ScanPolicy.from_preset("strict")
        analyzers = build_core_analyzers(policy)
        for analyzer in analyzers:
            assert hasattr(analyzer, "policy"), f"{analyzer.get_name()} missing .policy"
            assert analyzer.policy is policy, (
                f"{analyzer.get_name()}.policy is not the same object as the factory input"
            )

    def test_custom_yara_rules_forwarded_to_static(self, tmp_path):
        """custom_yara_rules_path must be forwarded to StaticAnalyzer."""
        rules_dir = tmp_path / "custom_rules"
        rules_dir.mkdir()
        # Create a minimal YARA file so StaticAnalyzer accepts the path
        (rules_dir / "test.yara").write_text("rule test_rule { condition: false }")

        policy = ScanPolicy.default()
        analyzers = build_core_analyzers(policy, custom_yara_rules_path=str(rules_dir))

        static = [a for a in analyzers if a.get_name() == "static_analyzer"]
        assert len(static) == 1
        assert static[0].custom_yara_rules_path == rules_dir


class TestBuildAnalyzers:
    """Tests for the full ``build_analyzers()`` function."""

    def test_core_only_by_default(self):
        """With no optional flags, only core analyzers are returned."""
        policy = ScanPolicy.default()
        analyzers = build_analyzers(policy)
        names = sorted(a.get_name() for a in analyzers)
        assert names == ["bytecode", "pipeline", "static_analyzer"]

    def test_optional_flags_extend(self):
        """Optional flags add analyzers without removing core ones."""
        policy = ScanPolicy.default()
        analyzers = build_analyzers(policy, use_trigger=True)
        names = [a.get_name() for a in analyzers]
        assert "static_analyzer" in names
        assert "trigger_analyzer" in names


class TestAllSitesUseFactory:
    """Meta-test: verify production code does not instantiate core analyzers
    outside the factory.

    Direct construction of StaticAnalyzer/BytecodeAnalyzer/PipelineAnalyzer
    outside ``analyzer_factory.py`` is a code smell that re-introduces the
    duplication bug.
    """

    # Files that are ALLOWED to instantiate core analyzers directly:
    _ALLOWED_FILES = {
        "analyzer_factory.py",  # the factory itself
        "test_",  # test files (prefix match)
        "conftest.py",  # test config
    }

    @staticmethod
    def _is_allowed(filepath: str) -> bool:
        name = Path(filepath).name
        if name == "analyzer_factory.py":
            return True
        if name.startswith("test_") or name == "conftest.py":
            return True
        return False

    def test_no_direct_static_analyzer_construction(self):
        """StaticAnalyzer() must not be called outside the factory in prod code."""
        self._check_pattern("StaticAnalyzer(")

    def test_no_direct_bytecode_analyzer_construction(self):
        """BytecodeAnalyzer() must not be called outside the factory in prod code."""
        self._check_pattern("BytecodeAnalyzer(")

    def test_no_direct_pipeline_analyzer_construction(self):
        """PipelineAnalyzer() must not be called outside the factory in prod code."""
        self._check_pattern("PipelineAnalyzer(")

    def _check_pattern(self, pattern: str):
        """Grep for *pattern* in production Python files and fail if found.

        Skips comments, imports, class definitions, and the analyzer's own
        source file (where the class is *defined*).
        """
        import re

        # Derive the class name from the pattern (e.g. "StaticAnalyzer(" -> "StaticAnalyzer")
        class_name = pattern.rstrip("(")

        project_root = Path(__file__).parent.parent
        violations = []

        # Only scan production code (skill_scanner/ and evals/)
        for search_dir in (project_root / "skill_scanner", project_root / "evals"):
            if not search_dir.exists():
                continue
            for py_file in search_dir.rglob("*.py"):
                if self._is_allowed(str(py_file)):
                    continue
                content = py_file.read_text(errors="ignore")
                for i, line in enumerate(content.splitlines(), 1):
                    stripped = line.strip()
                    # Skip comments, imports, class definitions, type hints
                    if stripped.startswith("#"):
                        continue
                    if stripped.startswith(("import ", "from ")):
                        continue
                    if stripped.startswith("class "):
                        continue
                    # Skip type annotations / docstrings / string literals
                    if re.match(r'^\s*("""|\'\'\'|"[^"]*"|\'[^\']*\')', stripped):
                        continue
                    if pattern in line:
                        rel = py_file.relative_to(project_root)
                        violations.append(f"  {rel}:{i}: {stripped}")

        if violations:
            msg = (
                f"Found direct {class_name}() construction outside the factory.\n"
                "These should use build_core_analyzers() or build_analyzers() instead:\n" + "\n".join(violations)
            )
            pytest.fail(msg)
