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

"""Bytecode integrity verifier.

Compares ``.pyc`` files against their corresponding ``.py`` source files by
recompiling the visible source and comparing normalized code objects.  This
keeps integrity verification in the Python standard library and avoids
depending on decompilers that routinely lag new Python bytecode versions.
"""

import hashlib
import importlib.util
import logging
import marshal
import struct
import types
from pathlib import Path
from typing import Any

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
        """Compare a ``.pyc`` file against visible source code.

        The source is compiled at each supported optimization level and its
        semantic code-object fingerprint is compared with the marshalled code
        object in the bytecode file.  Filename and line-table metadata are
        intentionally excluded so harmless path, comment, and whitespace
        differences do not look like tampering.
        """
        findings: list[Finding] = []

        source_content = py_file.read_content()
        if not source_content and py_file.size_bytes:
            return [
                self._analysis_unavailable_finding(
                    pyc_file,
                    py_file,
                    "matching source file is non-empty but could not be read as text",
                )
            ]

        try:
            pyc_code = self._load_pyc_code(pyc_file.path)
            pyc_fingerprint = self._code_fingerprint(pyc_code)
        except Exception as e:
            logger.debug("Cannot verify bytecode %s: %s", pyc_file.relative_path, e)
            return [self._analysis_unavailable_finding(pyc_file, py_file, str(e))]

        source_fingerprints: list[tuple[Any, ...]] = []
        compile_errors: list[str] = []

        # ``py_compile.compile(..., cfile=...)`` can produce optimized code
        # without an ``.opt-N`` filename, so try every interpreter-supported
        # optimization level rather than trusting the filename alone.
        for optimize in (0, 1, 2):
            try:
                source_code = compile(
                    source_content,
                    py_file.relative_path,
                    "exec",
                    dont_inherit=True,
                    optimize=optimize,
                )
            except (SyntaxError, ValueError, TypeError) as e:
                compile_errors.append(str(e))
                continue
            source_fingerprints.append(self._code_fingerprint(source_code))

        if not source_fingerprints:
            reason = compile_errors[0] if compile_errors else "matching source could not be compiled"
            return [self._analysis_unavailable_finding(pyc_file, py_file, reason)]

        if pyc_fingerprint not in source_fingerprints:
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
    def _load_pyc_code(pyc_path: Path) -> types.CodeType:
        """Load a current-interpreter code object from a validated PYC file."""
        with open(pyc_path, "rb") as f:
            header = f.read(16)
            if len(header) != 16:
                raise ValueError("truncated Python bytecode header")

            magic = header[:4]
            if magic != importlib.util.MAGIC_NUMBER:
                raise ValueError(
                    "bytecode targets a different Python version "
                    f"(magic {magic.hex()}, expected {importlib.util.MAGIC_NUMBER.hex()})"
                )

            flags = struct.unpack("<I", header[4:8])[0]
            if flags & ~0x03:
                raise ValueError(f"bytecode header contains unsupported flags 0x{flags:x}")

            code = marshal.load(f)

        if not isinstance(code, types.CodeType):
            raise TypeError("bytecode payload is not a Python code object")
        return code

    @classmethod
    def _code_fingerprint(cls, code: types.CodeType) -> tuple[Any, ...]:
        """Return execution-relevant code metadata, excluding location data."""
        return (
            code.co_name,
            getattr(code, "co_qualname", code.co_name),
            code.co_argcount,
            getattr(code, "co_posonlyargcount", 0),
            code.co_kwonlyargcount,
            code.co_nlocals,
            code.co_stacksize,
            code.co_flags,
            code.co_code,
            tuple(cls._constant_fingerprint(value) for value in code.co_consts),
            code.co_names,
            code.co_varnames,
            code.co_freevars,
            code.co_cellvars,
            getattr(code, "co_exceptiontable", b""),
        )

    @classmethod
    def _constant_fingerprint(cls, value: Any) -> tuple[Any, ...]:
        """Normalize constants without relying on code-object identity."""
        if isinstance(value, types.CodeType):
            return ("code", cls._code_fingerprint(value))
        if isinstance(value, tuple):
            return ("tuple", tuple(cls._constant_fingerprint(item) for item in value))
        if isinstance(value, frozenset):
            items = [cls._constant_fingerprint(item) for item in value]
            return ("frozenset", tuple(sorted(items, key=repr)))
        if isinstance(value, float):
            return ("float", value.hex())
        if isinstance(value, complex):
            return ("complex", value.real.hex(), value.imag.hex())
        return (type(value).__module__, type(value).__qualname__, value)

    def _analysis_unavailable_finding(
        self,
        pyc_file: SkillFile,
        py_file: SkillFile,
        reason: str,
    ) -> Finding:
        """Create a blocking finding when bytecode integrity cannot be proven."""
        return Finding(
            id=self._generate_finding_id("BYTECODE_ANALYSIS_UNAVAILABLE", pyc_file.relative_path),
            rule_id="BYTECODE_ANALYSIS_UNAVAILABLE",
            category=ThreatCategory.OBFUSCATION,
            severity=Severity.HIGH,
            title="Python bytecode integrity could not be verified",
            description=(
                f"Bytecode file {pyc_file.relative_path} has matching source "
                f"{py_file.relative_path}, but the scanner could not compare them: {reason}. "
                "Unverifiable bytecode can conceal code that is absent from visible source."
            ),
            file_path=pyc_file.relative_path,
            remediation=(
                "Remove pre-compiled bytecode and regenerate it from the reviewed source "
                "using the target Python interpreter."
            ),
            analyzer=self.name,
            metadata={"source_file": py_file.relative_path, "reason": reason},
        )
