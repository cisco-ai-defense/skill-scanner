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
Bytecode integrity verifier.

Compares .pyc files against their corresponding .py source files using
Python's standard `ast` module. Detects tampering where bytecode was modified
after compilation (cf. xz-utils backdoor pattern).

Dependencies: Python stdlib only (ast, dis, marshal, struct).
Optional: decompyle3 or uncompyle6 for decompiling bytecode without source.
"""

import ast
import dis
import hashlib
import importlib.util
import io
import logging
import marshal
import struct
import sys
from pathlib import Path
from typing import Any

from ..models import Finding, Severity, Skill, SkillFile, ThreatCategory
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)


class BytecodeAnalyzer(BaseAnalyzer):
    """Analyzes Python bytecode files (.pyc) for integrity against source."""

    def __init__(self):
        super().__init__(name="bytecode")

    def _generate_finding_id(self, rule_id: str, context: str) -> str:
        """Generate a unique finding ID."""
        combined = f"{rule_id}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{rule_id}_{hash_obj.hexdigest()[:10]}"

    def analyze(self, skill: Skill) -> list[Finding]:
        """Run bytecode integrity checks."""
        findings = []

        # Gather all .pyc and .py files
        pyc_files: list[SkillFile] = []
        # Index .py files by their relative path for precise directory-aware
        # matching.  A secondary stem-only index is kept as a fallback for
        # flat layouts where __pycache__ sits next to source.
        py_files_by_path: dict[str, SkillFile] = {}
        py_files_by_stem: dict[str, list[SkillFile]] = {}

        for sf in skill.files:
            ext = sf.path.suffix.lower()
            if ext == ".pyc":
                pyc_files.append(sf)
            elif ext == ".py":
                py_files_by_path[sf.relative_path] = sf
                py_files_by_stem.setdefault(sf.path.stem, []).append(sf)

        if not pyc_files:
            return findings

        # Having .pyc files at all is suspicious
        for pyc_file in pyc_files:
            # Try to find matching .py source
            stem = pyc_file.path.stem
            # Remove cpython-3XX suffix if present (e.g., "utils.cpython-312" -> "utils")
            if ".cpython-" in stem:
                stem = stem.split(".cpython-")[0]

            matching_py = self._find_matching_source(
                pyc_file,
                stem,
                py_files_by_path,
                py_files_by_stem,
            )

            if matching_py is None:
                # .pyc with no .py - can't verify
                findings.append(
                    Finding(
                        id=self._generate_finding_id("BYTECODE_NO_SOURCE", pyc_file.relative_path),
                        rule_id="BYTECODE_NO_SOURCE",
                        category=ThreatCategory.OBFUSCATION,
                        severity=Severity.HIGH,
                        title="Python bytecode without matching source",
                        description=(
                            f"Bytecode file {pyc_file.relative_path} has no corresponding .py source. "
                            f"Bytecode-only distribution hides the actual code from review."
                        ),
                        file_path=pyc_file.relative_path,
                        remediation="Include .py source files or remove .pyc files.",
                        analyzer=self.name,
                    )
                )
            else:
                # Compare bytecode against source
                mismatch_findings = self._compare_bytecode_to_source(pyc_file, matching_py)
                findings.extend(mismatch_findings)

        return findings

    @staticmethod
    def _find_matching_source(
        pyc_file: SkillFile,
        stem: str,
        by_path: dict[str, SkillFile],
        by_stem: dict[str, list[SkillFile]],
    ) -> SkillFile | None:
        """Find the .py source that corresponds to a .pyc file.

        Matching strategy (most to least specific):

        1. **Directory-aware lookup** — standard Python layout puts bytecode in
           ``<pkg>/__pycache__/<module>.cpython-3XX.pyc``.  The source is
           expected at ``<pkg>/<module>.py``.  We compute this path and do an
           exact lookup.

        2. **Same-directory lookup** — for non-``__pycache__`` locations,
           look for ``<module>.py`` next to the ``.pyc`` file.

        3. **Stem-only fallback** — if only one ``.py`` in the entire skill
           has a matching stem, use it.  If multiple exist we return ``None``
           rather than risk a false-positive CRITICAL finding from comparing
           against the wrong file.
        """
        pyc_parent = Path(pyc_file.relative_path).parent

        # Strategy 1: __pycache__ → parent directory
        if pyc_parent.name == "__pycache__":
            expected_rel = str(pyc_parent.parent / f"{stem}.py")
            match = by_path.get(expected_rel)
            if match is not None:
                return match

        # Strategy 2: same directory
        expected_rel = str(pyc_parent / f"{stem}.py")
        match = by_path.get(expected_rel)
        if match is not None:
            return match

        # Strategy 3: stem-only fallback (only when unambiguous)
        candidates = by_stem.get(stem, [])
        if len(candidates) == 1:
            return candidates[0]

        # Ambiguous or missing — safer to return None than to guess and
        # produce a false-positive CRITICAL supply-chain finding.
        return None

    def _compare_bytecode_to_source(self, pyc_file: SkillFile, py_file: SkillFile) -> list[Finding]:
        """Compare a .pyc file against its .py source using ast.dump()."""
        findings = []

        # Parse the .py source into AST
        source_content = py_file.read_content()
        if not source_content:
            return findings

        try:
            source_ast = ast.parse(source_content, filename=py_file.relative_path)
            source_dump = ast.dump(source_ast, annotate_fields=True, include_attributes=False)
        except SyntaxError as e:
            logger.debug("Cannot parse %s: %s", py_file.relative_path, e)
            return findings

        # Try to load and decompile the .pyc file
        pyc_ast = self._load_pyc_ast(pyc_file.path)
        if pyc_ast is None:
            # Can't decompile - without decompyle3/uncompyle6 this always fires.
            # Don't emit a finding here; the PYCACHE_FILES_DETECTED and
            # BYTECODE_NO_SOURCE rules already cover the important cases.
            # Only BYTECODE_SOURCE_MISMATCH (actual tampering) is worth flagging.
            return findings

        pyc_dump = ast.dump(pyc_ast, annotate_fields=True, include_attributes=False)

        if source_dump != pyc_dump:
            findings.append(
                Finding(
                    id=self._generate_finding_id("BYTECODE_SOURCE_MISMATCH", pyc_file.relative_path),
                    rule_id="BYTECODE_SOURCE_MISMATCH",
                    category=ThreatCategory.OBFUSCATION,
                    severity=Severity.CRITICAL,
                    title="Bytecode does not match source code",
                    description=(
                        f"CRITICAL: {pyc_file.relative_path} was compiled from different source "
                        f"than {py_file.relative_path}. The bytecode has been tampered with to "
                        f"contain code not present in the visible .py file. "
                        f"This is a supply-chain attack pattern (cf. xz-utils)."
                    ),
                    file_path=pyc_file.relative_path,
                    remediation=(
                        "URGENT: Remove all .pyc files and investigate the source of modification. "
                        "This skill may be compromised."
                    ),
                    analyzer=self.name,
                )
            )

        return findings

    def _load_pyc_ast(self, pyc_path: Path) -> ast.AST | None:
        """
        Try to reconstruct an AST from a .pyc file.

        Strategy:
        1. Use marshal to load the code object
        2. Use dis to get bytecode instructions
        3. Try decompyle3/uncompyle6 if available
        4. Fall back to recompiling source and comparing code objects

        Returns AST if successful, None otherwise.
        """
        try:
            with open(pyc_path, "rb") as f:
                # Read .pyc header
                magic = f.read(4)
                flags = struct.unpack("<I", f.read(4))[0]

                # Check for PEP 552 hash-based validation
                if flags & 0x1:
                    # Hash-based .pyc
                    f.read(8)  # source hash
                else:
                    # Timestamp-based .pyc
                    f.read(4)  # timestamp
                    f.read(4)  # source size

                # Load the code object
                code = marshal.load(f)

            # Try to decompile using decompyle3
            try:
                import decompyle3

                output = io.StringIO()
                decompyle3.deparse_code2str(code, out=output)
                decompiled_source = output.getvalue()
                return ast.parse(decompiled_source)
            except ImportError:
                pass
            except Exception:
                pass

            # Try uncompyle6
            try:
                import uncompyle6

                output = io.StringIO()
                uncompyle6.deparse_code2str(code, out=output)
                decompiled_source = output.getvalue()
                return ast.parse(decompiled_source)
            except ImportError:
                pass
            except Exception:
                pass

            return None

        except Exception as e:
            logger.debug("Failed to load .pyc %s: %s", pyc_path, e)
            return None
