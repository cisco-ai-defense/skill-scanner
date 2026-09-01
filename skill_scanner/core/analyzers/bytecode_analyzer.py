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

Dependencies: Python stdlib only (ast, marshal, struct).
Optional: decompyle3 or uncompyle6 for decompiling bytecode without source.
"""

import hashlib
import importlib.util
import logging
import marshal
import re
import struct
from pathlib import Path
from types import CodeType

from ..models import Finding, Severity, Skill, SkillFile, ThreatCategory
from ..scan_policy import ScanPolicy
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)


class BytecodeAnalyzer(BaseAnalyzer):
    """Analyzes Python bytecode files (.pyc) for integrity against source."""

    def __init__(self, policy: ScanPolicy | None = None):
        super().__init__(name="bytecode", policy=policy)

    def _generate_finding_id(self, rule_id: str, context: str) -> str:
        """Generate a unique finding ID."""
        combined = f"{rule_id}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{rule_id}_{hash_obj.hexdigest()[:10]}"

    def analyze(self, skill: Skill) -> list[Finding]:
        """Run bytecode integrity checks."""
        findings: list[Finding] = []

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
        """Compare a .pyc file against equivalently compiled Python source."""
        findings: list[Finding] = []

        # Compile the .py source with the running interpreter.  Comparing code
        # objects avoids optional decompiler dependencies and works for the
        # Python versions supported by this scanner.
        source_content = py_file.read_content()
        optimization = self._pyc_optimization_level(pyc_file)
        if optimization is None:
            return [self._unverifiable_finding(pyc_file, py_file, "unsupported-optimization-level")]
        try:
            source_code = compile(
                source_content,
                py_file.relative_path,
                "exec",
                dont_inherit=True,
                optimize=optimization,
            )
        except (SyntaxError, ValueError, TypeError) as e:
            logger.debug("Cannot parse %s: %s", py_file.relative_path, e)
            return [self._unverifiable_finding(pyc_file, py_file, type(e).__name__)]

        pyc_code = self._load_pyc_code(pyc_file.path)
        if pyc_code is None:
            return [self._unverifiable_finding(pyc_file, py_file, "invalid-or-unsupported-pyc")]

        if self._code_fingerprint(source_code) != self._code_fingerprint(pyc_code):
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

    @staticmethod
    def _pyc_optimization_level(pyc_file: SkillFile) -> int | None:
        """Return the optimization level encoded in a PEP 3147 cache name."""
        match = re.search(r"\.opt-([^.]+)\.pyc$", pyc_file.path.name)
        if match is None:
            return 0
        marker = match.group(1)
        if marker not in {"0", "1", "2"}:
            return None
        return int(marker)

    @staticmethod
    def _code_fingerprint(code: CodeType) -> tuple:
        """Return a semantic fingerprint for *code*, ignoring source locations."""
        constants = tuple(
            BytecodeAnalyzer._code_fingerprint(value) if isinstance(value, CodeType) else value
            for value in code.co_consts
        )
        return (
            code.co_argcount,
            code.co_posonlyargcount,
            code.co_kwonlyargcount,
            code.co_nlocals,
            code.co_stacksize,
            code.co_flags,
            code.co_code,
            constants,
            code.co_names,
            code.co_varnames,
            code.co_freevars,
            code.co_cellvars,
            getattr(code, "co_exceptiontable", b""),
        )

    def _unverifiable_finding(self, pyc_file: SkillFile, py_file: SkillFile, reason: str) -> Finding:
        """Create a blocking finding when bytecode cannot be compared safely."""
        return Finding(
            id=self._generate_finding_id("BYTECODE_UNVERIFIABLE", pyc_file.relative_path),
            rule_id="BYTECODE_UNVERIFIABLE",
            category=ThreatCategory.OBFUSCATION,
            severity=Severity.HIGH,
            title="Python bytecode cannot be verified against source",
            description=(
                f"Bytecode file {pyc_file.relative_path} could not be compared with "
                f"{py_file.relative_path} ({reason}). Unverifiable bytecode may contain "
                "code that is absent from the visible source."
            ),
            file_path=pyc_file.relative_path,
            remediation="Remove pre-compiled bytecode or provide bytecode built by the scanner's Python version.",
            analyzer=self.name,
            metadata={"reason": reason, "source_file": py_file.relative_path},
        )

    def _load_pyc_code(self, pyc_path: Path) -> CodeType | None:
        """
        Load a code object from a .pyc file without executing it.

        Strategy:
        1. Validate the magic number for this Python interpreter
        2. Parse the PEP 552 header
        3. Use marshal to load the code object

        Returns a code object if it can be safely compared, otherwise None.
        """
        try:
            with open(pyc_path, "rb") as f:
                # Read .pyc header
                magic = f.read(4)
                if magic != importlib.util.MAGIC_NUMBER:
                    return None
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
            return code if isinstance(code, CodeType) else None

        except Exception as e:
            logger.debug("Failed to load .pyc %s: %s", pyc_path, e)
            return None
