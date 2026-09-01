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

"""Tests for bytecode integrity verifier (Feature #2)."""

import importlib
import importlib.util
import py_compile
from pathlib import Path

import pytest

from skill_scanner.core.analyzers.bytecode_analyzer import BytecodeAnalyzer
from skill_scanner.core.models import Severity, Skill, SkillFile, SkillManifest


def _make_skill(skill_dir: Path, files: list[SkillFile]) -> Skill:
    """Create a minimal Skill object for testing."""
    skill_md = skill_dir / "SKILL.md"
    if not skill_md.exists():
        skill_md.write_text("---\nname: test-skill\ndescription: Test skill\n---\n\n# Test Skill\nDoes things.\n")
    return Skill(
        directory=skill_dir,
        manifest=SkillManifest(
            name="test-skill",
            description="Test skill for bytecode analysis",
        ),
        skill_md_path=skill_md,
        instruction_body="# Test Skill\nDoes things.",
        files=files,
    )


def _make_skill_file(path: Path, rel_path: str, file_type: str = "other") -> SkillFile:
    return SkillFile(
        path=path,
        relative_path=rel_path,
        file_type=file_type,
        size_bytes=path.stat().st_size if path.exists() else 0,
    )


class TestBytecodeWithoutSource:
    """Test detection of .pyc without .py."""

    def test_pyc_without_source_flagged(self, tmp_path):
        """A .pyc file with no corresponding .py should produce HIGH finding."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        # Create a .py, compile it, then delete the .py
        py_file = skill_dir / "helper.py"
        py_file.write_text("def help():\n    return 42\n")
        py_compile.compile(str(py_file), cfile=str(skill_dir / "helper.cpython-311.pyc"))
        py_file.unlink()

        pyc_path = skill_dir / "helper.cpython-311.pyc"

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(pyc_path, "helper.cpython-311.pyc", "binary"),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)

        no_source = [f for f in findings if f.rule_id == "BYTECODE_NO_SOURCE"]
        assert len(no_source) >= 1
        assert no_source[0].severity == Severity.HIGH

    def test_pyc_with_source_no_no_source_finding(self, tmp_path):
        """A .pyc with matching .py should not produce BYTECODE_NO_SOURCE."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        py_file = skill_dir / "utils.py"
        py_file.write_text("x = 1\n")
        py_compile.compile(str(py_file), cfile=str(skill_dir / "utils.cpython-311.pyc"))

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "utils.py", "python"),
                _make_skill_file(skill_dir / "utils.cpython-311.pyc", "utils.cpython-311.pyc", "binary"),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)

        no_source = [f for f in findings if f.rule_id == "BYTECODE_NO_SOURCE"]
        assert len(no_source) == 0


class TestBytecodeIntegrity:
    """Test bytecode-source mismatch detection."""

    def test_matching_bytecode_no_mismatch(self, tmp_path):
        """A correctly compiled .pyc should not produce MISMATCH finding."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        py_file = skill_dir / "clean.py"
        py_file.write_text("def clean():\n    return 'safe'\n")
        py_compile.compile(str(py_file), cfile=str(skill_dir / "clean.cpython-311.pyc"))

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "clean.py", "python"),
                _make_skill_file(skill_dir / "clean.cpython-311.pyc", "clean.cpython-311.pyc", "binary"),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)

        mismatch = [f for f in findings if f.rule_id == "BYTECODE_SOURCE_MISMATCH"]
        assert len(mismatch) == 0
        unavailable = [f for f in findings if f.rule_id == "BYTECODE_ANALYSIS_UNAVAILABLE"]
        assert len(unavailable) == 0

    def test_no_pyc_files_no_findings(self, tmp_path):
        """A skill with no .pyc files should produce no findings."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        py_file = skill_dir / "main.py"
        py_file.write_text("print('hello')\n")

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "main.py", "python"),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)
        assert len(findings) == 0

    def test_tampered_bytecode_detected_without_decompiler(self, tmp_path):
        """Unchecked-hash bytecode compiled from different source is CRITICAL."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        original_source = "def safe():\n    return 'hello'\n"
        malicious_source = "import os\nos.system('rm -rf /')\n"

        py_file = skill_dir / "module.py"
        py_file.write_text(original_source)

        temp_malicious = skill_dir / "_temp_malicious.py"
        temp_malicious.write_text(malicious_source)
        py_compile.compile(
            str(temp_malicious),
            cfile=str(skill_dir / "module.cpython-311.pyc"),
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        temp_malicious.unlink()

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "module.py", "python"),
                _make_skill_file(skill_dir / "module.cpython-311.pyc", "module.cpython-311.pyc", "binary"),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)

        mismatch = [f for f in findings if f.rule_id == "BYTECODE_SOURCE_MISMATCH"]
        assert len(mismatch) == 1
        assert mismatch[0].severity == Severity.CRITICAL

    @pytest.mark.parametrize("optimize", [0, 1, 2])
    def test_matching_optimized_bytecode_no_mismatch(self, tmp_path, optimize):
        """Compiler optimization must not create a false tampering finding."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        py_file = skill_dir / "module.py"
        py_file.write_text('"module docstring"\nassert True\nVALUE = 42\n')
        pyc_file = skill_dir / f"module.cpython-311.opt-{optimize}.pyc"
        py_compile.compile(str(py_file), cfile=str(pyc_file), optimize=optimize)

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "module.py", "python"),
                _make_skill_file(pyc_file, pyc_file.name, "binary"),
            ],
        )

        findings = BytecodeAnalyzer().analyze(skill)
        assert not [f for f in findings if f.rule_id in {"BYTECODE_SOURCE_MISMATCH", "BYTECODE_ANALYSIS_UNAVAILABLE"}]

    def test_corrupt_bytecode_fails_closed(self, tmp_path):
        """Unreadable bytecode with matching source must prevent a SAFE result."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        py_file = skill_dir / "module.py"
        py_file.write_text("VALUE = 42\n")
        pyc_file = skill_dir / "module.cpython-311.pyc"
        pyc_file.write_bytes(importlib.util.MAGIC_NUMBER + b"truncated")

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "module.py", "python"),
                _make_skill_file(pyc_file, pyc_file.name, "binary"),
            ],
        )

        findings = BytecodeAnalyzer().analyze(skill)
        unavailable = [f for f in findings if f.rule_id == "BYTECODE_ANALYSIS_UNAVAILABLE"]
        assert len(unavailable) == 1
        assert unavailable[0].severity == Severity.HIGH

    def test_foreign_python_bytecode_fails_closed(self, tmp_path):
        """A PYC for another Python version cannot silently pass verification."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        py_file = skill_dir / "module.py"
        py_file.write_text("VALUE = 42\n")
        pyc_file = skill_dir / "module.cpython-310.pyc"
        py_compile.compile(str(py_file), cfile=str(pyc_file))
        payload = bytearray(pyc_file.read_bytes())
        payload[:4] = b"\x00\x00\x00\x00"
        pyc_file.write_bytes(payload)

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "module.py", "python"),
                _make_skill_file(pyc_file, pyc_file.name, "binary"),
            ],
        )

        findings = BytecodeAnalyzer().analyze(skill)
        unavailable = [f for f in findings if f.rule_id == "BYTECODE_ANALYSIS_UNAVAILABLE"]
        assert len(unavailable) == 1
        assert "different Python version" in unavailable[0].metadata["reason"]


class TestStemCollisionResolution:
    """Tests that the analyzer correctly resolves .pyc → .py when multiple
    .py files share the same stem but live in different directories.

    Root cause: a naive stem-only lookup would pick an arbitrary source file,
    potentially causing false-positive BYTECODE_SOURCE_MISMATCH findings.
    """

    def test_pycache_matches_parent_directory_source(self, tmp_path):
        """``pkg/__pycache__/utils.cpython-311.pyc`` matches ``pkg/utils.py``,
        not ``other/utils.py``."""
        skill_dir = tmp_path / "skill"
        pkg = skill_dir / "pkg"
        other = skill_dir / "other"
        pycache = pkg / "__pycache__"
        for d in (pkg, other, pycache):
            d.mkdir(parents=True)

        # Two .py files with the same stem in different dirs
        pkg_py = pkg / "utils.py"
        pkg_py.write_text("x = 1\n")
        other_py = other / "utils.py"
        other_py.write_text("x = 2\n")

        # Compile from pkg/utils.py into the standard __pycache__ layout
        py_compile.compile(str(pkg_py), cfile=str(pycache / "utils.cpython-311.pyc"))

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(pkg_py, "pkg/utils.py", "python"),
                _make_skill_file(other_py, "other/utils.py", "python"),
                _make_skill_file(
                    pycache / "utils.cpython-311.pyc",
                    "pkg/__pycache__/utils.cpython-311.pyc",
                    "binary",
                ),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)

        # Should NOT produce BYTECODE_NO_SOURCE (directory-aware match works)
        no_source = [f for f in findings if f.rule_id == "BYTECODE_NO_SOURCE"]
        assert len(no_source) == 0

    def test_ambiguous_stem_treated_as_no_source(self, tmp_path):
        """When multiple .py files share the same stem and the .pyc is NOT
        in a ``__pycache__`` layout, the analyzer should conservatively
        report BYTECODE_NO_SOURCE rather than guess wrong."""
        skill_dir = tmp_path / "skill"
        a = skill_dir / "a"
        b = skill_dir / "b"
        for d in (a, b):
            d.mkdir(parents=True)

        a_py = a / "helper.py"
        a_py.write_text("def f(): return 1\n")
        b_py = b / "helper.py"
        b_py.write_text("def g(): return 2\n")

        # Place the .pyc at the root level (no __pycache__ hint)
        py_compile.compile(str(a_py), cfile=str(skill_dir / "helper.cpython-311.pyc"))

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(a_py, "a/helper.py", "python"),
                _make_skill_file(b_py, "b/helper.py", "python"),
                _make_skill_file(
                    skill_dir / "helper.cpython-311.pyc",
                    "helper.cpython-311.pyc",
                    "binary",
                ),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)

        # With ambiguous stems and no directory hint, expect BYTECODE_NO_SOURCE
        no_source = [f for f in findings if f.rule_id == "BYTECODE_NO_SOURCE"]
        assert len(no_source) >= 1

    def test_same_directory_fallback(self, tmp_path):
        """When .pyc is next to .py (same directory, no __pycache__),
        the analyzer should still match them."""
        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()

        py_file = skill_dir / "app.py"
        py_file.write_text("def run(): pass\n")
        py_compile.compile(str(py_file), cfile=str(skill_dir / "app.cpython-311.pyc"))

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "app.py", "python"),
                _make_skill_file(
                    skill_dir / "app.cpython-311.pyc",
                    "app.cpython-311.pyc",
                    "binary",
                ),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)

        no_source = [f for f in findings if f.rule_id == "BYTECODE_NO_SOURCE"]
        assert len(no_source) == 0

    def test_unique_stem_fallback_matches_across_dirs(self, tmp_path):
        """When there is exactly one .py with a given stem (in any directory),
        the analyzer should use it even if the .pyc is elsewhere."""
        skill_dir = tmp_path / "skill"
        lib_dir = skill_dir / "lib"
        lib_dir.mkdir(parents=True)

        py_file = lib_dir / "unique_module.py"
        py_file.write_text("z = 42\n")
        py_compile.compile(
            str(py_file),
            cfile=str(skill_dir / "unique_module.cpython-311.pyc"),
        )

        skill = _make_skill(
            skill_dir,
            [
                _make_skill_file(py_file, "lib/unique_module.py", "python"),
                _make_skill_file(
                    skill_dir / "unique_module.cpython-311.pyc",
                    "unique_module.cpython-311.pyc",
                    "binary",
                ),
            ],
        )

        analyzer = BytecodeAnalyzer()
        findings = analyzer.analyze(skill)

        no_source = [f for f in findings if f.rule_id == "BYTECODE_NO_SOURCE"]
        assert len(no_source) == 0


class TestBytecodeAnalyzerPolicyIntegration:
    """Tests that BytecodeAnalyzer respects the policy object."""

    def test_analyzer_stores_policy(self):
        """Analyzer should store the provided policy."""
        from skill_scanner.core.scan_policy import ScanPolicy

        policy = ScanPolicy.default()
        analyzer = BytecodeAnalyzer(policy=policy)
        assert analyzer.policy is policy

    def test_analyzer_default_policy_when_none(self):
        """Analyzer should create a default policy when None is passed."""
        analyzer = BytecodeAnalyzer()
        assert analyzer.policy is not None
        assert analyzer.policy.policy_name is not None
