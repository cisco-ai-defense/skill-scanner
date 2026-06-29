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
Tests for dataflow fixpoint convergence on large files (Issue #120).

The CFG worklist algorithm stops when a node's out-fact stops changing.
That comparison runs through ``ForwardFlowFact.__eq__`` which delegates to
``ShapeEnvironment.__eq__`` / ``TaintShape.__eq__``. Those types previously
had no ``__eq__``, so freshly-copied environments always compared unequal by
identity. The fixpoint was therefore never detected and the analysis spun
until the iteration safety cap -- which is catastrophically slow on large
files (a ~2,400-line file took >70s and the wrapping process timed out).

These tests pin the value-equality semantics and guard against the
performance regression returning.
"""

import time

from skill_scanner.core.static_analysis.context_extractor import ContextExtractor
from skill_scanner.core.static_analysis.taint.tracker import (
    ShapeEnvironment,
    Taint,
    TaintShape,
    TaintStatus,
)


class TestTaintEquality:
    """Value-equality semantics required for fixpoint convergence."""

    def test_empty_environments_are_equal(self):
        assert ShapeEnvironment() == ShapeEnvironment()

    def test_copied_environment_equals_original(self):
        env = ShapeEnvironment()
        env.set_taint("x", Taint(status=TaintStatus.TAINTED, labels={"param:x"}))
        assert env == env.copy()

    def test_environments_with_different_taint_differ(self):
        a = ShapeEnvironment()
        a.set_taint("x", Taint(status=TaintStatus.TAINTED, labels={"param:x"}))
        b = ShapeEnvironment()
        b.set_taint("x", Taint(status=TaintStatus.UNTAINTED))
        assert a != b

    def test_environments_with_different_vars_differ(self):
        a = ShapeEnvironment()
        a.set_taint("x", Taint(status=TaintStatus.TAINTED))
        b = ShapeEnvironment()
        b.set_taint("y", Taint(status=TaintStatus.TAINTED))
        assert a != b

    def test_taintshape_equality_is_by_content(self):
        s1 = TaintShape(taint=Taint(status=TaintStatus.TAINTED, labels={"l"}))
        s2 = TaintShape(taint=Taint(status=TaintStatus.TAINTED, labels={"l"}))
        assert s1 == s2
        assert s1 == s1.copy()

    def test_taintshape_nested_fields_compared(self):
        s1 = TaintShape()
        s1.set_field("a", Taint(status=TaintStatus.TAINTED))
        s2 = TaintShape()
        s2.set_field("a", Taint(status=TaintStatus.TAINTED))
        assert s1 == s2
        s2.set_field("a", Taint(status=TaintStatus.UNTAINTED))
        assert s1 != s2

    def test_equality_with_other_type_is_false(self):
        assert ShapeEnvironment() != object()
        assert TaintShape() != object()

    def test_copy_is_isolated_via_set_taint(self):
        """copy() shares TaintShape objects (copy-on-write), but writing through
        the sanctioned set_taint() path must not leak into the source. This
        pins the COW invariant the forward-dataflow analysis relies on: mutate
        only via set_taint(), read only via get()."""
        original = ShapeEnvironment()
        original.set_taint("x", Taint(status=TaintStatus.TAINTED, labels={"param:x"}))

        clone = original.copy()
        assert clone == original

        # Mutate the clone through the sanctioned write path.
        clone.set_taint("x", Taint(status=TaintStatus.UNTAINTED))

        # Source is untouched; the two now differ.
        assert original.get_taint("x").is_tainted()
        assert not clone.get_taint("x").is_tainted()
        assert clone != original


# A synthetic file large enough that spinning to the iteration cap would take
# many seconds, but which converges almost instantly once a fixpoint is
# detected. Mirrors the structure (deep branching + loops) of the file in the
# original report without vendoring it.
def _build_large_source(num_blocks: int = 200) -> str:
    lines = ["import os", "import subprocess", ""]
    lines.append("def handler(arg):")
    lines.append("    result = arg")
    for i in range(num_blocks):
        lines.append(f"    if result == {i}:")
        lines.append(f"        tmp_{i} = result + {i}")
        lines.append(f"        for j in range({i % 5}):")
        lines.append(f"            tmp_{i} = tmp_{i} + j")
        lines.append(f"        result = tmp_{i}")
        lines.append("    else:")
        lines.append(f"        result = result - {i}")
    lines.append("    return result")
    return "\n".join(lines) + "\n"


class TestLargeFileConvergence:
    """Large files must converge quickly, not spin to the iteration cap."""

    def test_large_file_analyzes_quickly(self):
        source = _build_large_source(num_blocks=200)
        assert source.count("\n") > 1000  # genuinely large

        extractor = ContextExtractor()
        start = time.time()
        context = extractor.extract_context("large_skill.py", source)
        elapsed = time.time() - start

        # With convergence working this finishes in well under a second.
        # The pre-fix behavior took tens of seconds; 15s is a generous ceiling
        # that still catches a regression to the non-converging code path.
        assert elapsed < 15.0, f"extract_context took {elapsed:.1f}s -- fixpoint likely not converging"

        # Sanity: analysis produced a real parsed/extracted context, not the
        # parse-failure fallback (which would also set file_path). Assert on
        # analysis-specific output instead.
        assert context.file_path == "large_skill.py"
        assert len(context.functions) == 1
        assert "subprocess" in context.imports
