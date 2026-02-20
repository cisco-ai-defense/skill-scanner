# Copyright 2026 Cisco Systems, Inc.
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

"""Forward dataflow analysis using Control Flow Graph.

Tracks parameter flows from function entry points through all control structures
using proper CFG-based fixpoint analysis. This provides accurate flow tracking
through branches, loops, and function calls.

Replaces the simple AST walker approach with proper dataflow analysis.
"""

import ast
from dataclasses import dataclass, field
from typing import Any

from ..cfg.builder import CFGNode, DataFlowAnalyzer
from ..parser.python_parser import PythonParser
from ..taint.tracker import ShapeEnvironment, Taint, TaintStatus


@dataclass
class FlowPath:
    """Represents a complete flow path from parameter."""

    parameter_name: str
    operations: list[dict[str, Any]] = field(default_factory=list)
    reaches_calls: list[str] = field(default_factory=list)
    reaches_assignments: list[str] = field(default_factory=list)
    reaches_returns: bool = False
    reaches_external: bool = False  # Network, file, subprocess

    def copy(self) -> "FlowPath":
        """Create a deep copy of the flow path."""
        return FlowPath(
            parameter_name=self.parameter_name,
            operations=self.operations.copy(),
            reaches_calls=self.reaches_calls.copy(),
            reaches_assignments=self.reaches_assignments.copy(),
            reaches_returns=self.reaches_returns,
            reaches_external=self.reaches_external,
        )


@dataclass
class ForwardFlowFact:
    """Dataflow fact tracking parameter flows."""

    shape_env: ShapeEnvironment = field(default_factory=ShapeEnvironment)
    parameter_flows: dict[str, FlowPath] = field(default_factory=dict)

    def copy(self) -> "ForwardFlowFact":
        """Create a deep copy."""
        return ForwardFlowFact(
            shape_env=self.shape_env.copy(),
            parameter_flows={k: v.copy() for k, v in self.parameter_flows.items()},
        )

    def __eq__(self, other: object) -> bool:
        """Check equality for fixpoint detection."""
        if not isinstance(other, ForwardFlowFact):
            return False

        if self.shape_env != other.shape_env:
            return False

        if set(self.parameter_flows.keys()) != set(other.parameter_flows.keys()):
            return False

        # Compare flow paths
        for param in self.parameter_flows:
            self_flow = self.parameter_flows[param]
            other_flow = other.parameter_flows[param]

            if (
                len(self_flow.operations) != len(other_flow.operations)
                or set(self_flow.reaches_calls) != set(other_flow.reaches_calls)
                or self_flow.reaches_returns != other_flow.reaches_returns
                or self_flow.reaches_external != other_flow.reaches_external
            ):
                return False

        return True


class ForwardDataflowAnalysis(DataFlowAnalyzer[ForwardFlowFact]):
    """Track all forward flows from function parameters and script-level sources using CFG.

    Uses proper control flow graph and fixpoint analysis to accurately
    track how parameters flow through branches, loops, and function calls.
    Also detects script-level sources (credential files, env vars) and tracks
    their flows to sinks (network, eval, subprocess).
    """

    def __init__(self, parser: PythonParser, parameter_names: list[str] | None = None, detect_sources: bool = True):
        """Initialize forward flow tracker.

        Args:
            parser: Python parser instance
            parameter_names: Names of function parameters to track (None for script-level only)
            detect_sources: Whether to detect script-level sources (credential files, env vars)
        """
        super().__init__(parser)
        self.parameter_names = parameter_names or []
        self.detect_sources = detect_sources
        self.all_flows: list[FlowPath] = []
        self.script_sources: list[str] = []  # Detected script-level sources

    def analyze_forward_flows(self) -> list[FlowPath]:
        """Run forward flow analysis from parameters and script-level sources.

        Returns:
            List of all flow paths from parameters and sources
        """
        # Clear state to prevent accumulation from previous analyses
        # (defensive programming - instances should be fresh, but this ensures clean state)
        self.all_flows.clear()
        self.script_sources.clear()

        self.build_cfg()

        # Detect script-level sources if enabled
        if self.detect_sources:
            self._detect_script_sources()

        # Initialize: mark all parameters and sources as tainted with unique labels
        initial_fact = ForwardFlowFact()

        # Track function parameters
        for param_name in self.parameter_names:
            taint = Taint(status=TaintStatus.TAINTED)
            taint.add_label(f"param:{param_name}")
            initial_fact.shape_env.set_taint(param_name, taint)
            initial_fact.parameter_flows[param_name] = FlowPath(parameter_name=param_name)

        # Track script-level sources (credential files, env vars)
        for source_name in self.script_sources:
            source_type = self._get_source_type(source_name)
            taint = Taint(status=TaintStatus.TAINTED)
            taint.add_label(f"source:{source_type}:{source_name}")
            # Use a synthetic variable name for tracking
            var_name = f"__source_{source_type}_{len(self.all_flows)}"
            initial_fact.shape_env.set_taint(var_name, taint)
            initial_fact.parameter_flows[source_name] = FlowPath(parameter_name=source_name)

        self.analyze(initial_fact, forward=True)

        # Collect all flows
        self._collect_flows()

        return self.all_flows

    def _detect_script_sources(self) -> None:
        """Detect script-level sources (credential files, env vars)."""
        tree = getattr(self.parser, "tree", None)
        if not tree:
            return

        CREDENTIAL_FILES = [".aws/credentials", ".ssh/id_rsa", ".ssh/id_dsa", ".kube/config", ".netrc"]
        ENV_VAR_PATTERNS = ["API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"]

        tree = getattr(self.parser, "tree", None)
        if not tree:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)

                # Check for credential file access
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        # Credential files
                        if any(cred in arg.value for cred in CREDENTIAL_FILES):
                            source_name = f"credential_file:{arg.value}"
                            if source_name not in self.script_sources:
                                self.script_sources.append(source_name)

                        # os.path.expanduser with credential paths
                        if call_name == "os.path.expanduser":
                            if any(cred in arg.value for cred in CREDENTIAL_FILES):
                                source_name = f"credential_file:{arg.value}"
                                if source_name not in self.script_sources:
                                    self.script_sources.append(source_name)

                # Check for env var access
                if call_name in ["os.getenv", "os.environ.get", "getenv"]:
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                            if any(pattern in arg.value.upper() for pattern in ENV_VAR_PATTERNS):
                                source_name = f"env_var:{arg.value}"
                                if source_name not in self.script_sources:
                                    self.script_sources.append(source_name)

            # Check for os.environ.items() iteration
            elif isinstance(node, ast.For):
                if isinstance(node.iter, ast.Call):
                    if isinstance(node.iter.func, ast.Attribute):
                        if node.iter.func.attr == "items":
                            attr_name = self._get_attribute_name(node.iter.func.value)
                            if attr_name == "os.environ":
                                source_name = "env_var:os.environ (all)"
                                if source_name not in self.script_sources:
                                    self.script_sources.append(source_name)

            # Check for os.environ assignment
            elif isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Attribute):
                    attr_name = self._get_attribute_name(node.value)
                    if attr_name == "os.environ":
                        source_name = "env_var:os.environ (assignment)"
                        if source_name not in self.script_sources:
                            self.script_sources.append(source_name)

    def _get_source_type(self, source_name: str) -> str:
        """Get source type from source name."""
        if source_name.startswith("credential_file:"):
            return "credential_file"
        elif source_name.startswith("env_var:"):
            return "env_var"
        return "unknown"

    def _get_attribute_name(self, node: ast.Attribute) -> str:
        """Get full attribute name like 'os.environ'."""
        parts = []
        current = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        return ".".join(reversed(parts))

    def transfer(self, node: CFGNode, in_fact: ForwardFlowFact) -> ForwardFlowFact:
        """Transfer function tracking parameter flows.

        Args:
            node: CFG node
            in_fact: Input flow fact

        Returns:
            Output flow fact
        """
        out_fact = in_fact.copy()
        ast_node = node.ast_node

        self._transfer_python(ast_node, out_fact)
        return out_fact

    def _transfer_python(self, node: ast.AST, fact: ForwardFlowFact) -> None:
        """Transfer function for Python nodes.

        Args:
            node: Python AST node
            fact: Flow fact to update
        """
        # Track assignments
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    rhs_taint = self._eval_expr_taint(node.value, fact)

                    # Check if RHS is a source call (os.getenv, open with credential file, etc.)
                    if isinstance(node.value, ast.Call):
                        source_info = self._check_source_call(node.value)
                        if source_info:
                            source_type, source_name = source_info
                            rhs_taint = Taint(status=TaintStatus.TAINTED)
                            rhs_taint.add_label(f"source:{source_type}:{source_name}")
                            # Add to script sources if not already there
                            full_source_name = f"{source_type}:{source_name}"
                            if full_source_name not in self.script_sources:
                                self.script_sources.append(full_source_name)
                            if full_source_name not in fact.parameter_flows:
                                fact.parameter_flows[full_source_name] = FlowPath(parameter_name=full_source_name)

                    if rhs_taint.is_tainted():
                        fact.shape_env.set_taint(target.id, rhs_taint)

                        # Track which parameters/sources flow here
                        all_tracked = self.parameter_names + self.script_sources
                        for tracked_name in all_tracked:
                            if self._expr_uses_var(node.value, tracked_name, fact) or self._is_source_assignment(
                                node.value, tracked_name
                            ):
                                if tracked_name in fact.parameter_flows:
                                    flow = fact.parameter_flows[tracked_name]

                                    # Deduplicate: Check if this assignment was already recorded
                                    assignment_str = f"{target.id} = {self._unparse_safe(node.value)}"
                                    if assignment_str not in flow.reaches_assignments:
                                        flow.reaches_assignments.append(assignment_str)

                                    # Deduplicate operations by creating a key
                                    op_key = (
                                        "assignment",
                                        target.id,
                                        self._unparse_safe(node.value),
                                        None,  # function
                                        None,  # argument
                                        node.lineno if hasattr(node, "lineno") else 0,
                                    )
                                    existing_op_keys = {
                                        (
                                            op.get("type"),
                                            op.get("target"),
                                            op.get("value"),
                                            op.get("function"),
                                            op.get("argument"),
                                            op.get("line"),
                                        )
                                        for op in flow.operations
                                    }
                                    if op_key not in existing_op_keys:
                                        flow.operations.append(
                                            {
                                                "type": "assignment",
                                                "target": target.id,
                                                "value": self._unparse_safe(node.value),
                                                "line": node.lineno if hasattr(node, "lineno") else 0,
                                            }
                                        )

                                    # Check if RHS is a call to external operation
                                    if isinstance(node.value, ast.Call):
                                        call_name = self._get_call_name(node.value)
                                        if call_name not in flow.reaches_calls:
                                            flow.reaches_calls.append(call_name)
                                        if self._is_external_operation(call_name):
                                            flow.reaches_external = True
                    else:
                        # Clear taint if RHS is not tainted
                        fact.shape_env.set_taint(target.id, Taint(status=TaintStatus.UNTAINTED))

        # Track function calls
        elif isinstance(node, ast.Call):
            call_name = self._get_call_name(node)

            # Check if any arguments contain tracked parameters/sources
            for arg in node.args:
                arg_taint = self._eval_expr_taint(arg, fact)
                if arg_taint.is_tainted():
                    all_tracked = self.parameter_names + self.script_sources
                    for tracked_name in all_tracked:
                        if self._expr_uses_var(arg, tracked_name, fact):
                            if tracked_name in fact.parameter_flows:
                                flow = fact.parameter_flows[tracked_name]

                                # Deduplicate: Check if this call was already recorded
                                if call_name not in flow.reaches_calls:
                                    flow.reaches_calls.append(call_name)

                                # Deduplicate operations
                                op_key = (
                                    "function_call",
                                    None,  # target
                                    None,  # value
                                    call_name,
                                    self._unparse_safe(arg),
                                    node.lineno if hasattr(node, "lineno") else 0,
                                )
                                existing_op_keys = {
                                    (
                                        op.get("type"),
                                        op.get("target"),
                                        op.get("value"),
                                        op.get("function"),
                                        op.get("argument"),
                                        op.get("line"),
                                    )
                                    for op in flow.operations
                                }
                                if op_key not in existing_op_keys:
                                    flow.operations.append(
                                        {
                                            "type": "function_call",
                                            "function": call_name,
                                            "argument": self._unparse_safe(arg),
                                            "line": node.lineno if hasattr(node, "lineno") else 0,
                                        }
                                    )

                                if self._is_external_operation(call_name):
                                    flow.reaches_external = True

        # Track returns
        elif isinstance(node, ast.Return):
            if node.value:
                ret_taint = self._eval_expr_taint(node.value, fact)
                if ret_taint.is_tainted():
                    all_tracked = self.parameter_names + self.script_sources
                    for tracked_name in all_tracked:
                        if self._expr_uses_var(node.value, tracked_name, fact):
                            if tracked_name in fact.parameter_flows:
                                fact.parameter_flows[tracked_name].reaches_returns = True
                                fact.parameter_flows[tracked_name].operations.append(
                                    {
                                        "type": "return",
                                        "value": self._unparse_safe(node.value),
                                        "line": node.lineno if hasattr(node, "lineno") else 0,
                                    }
                                )

    def _eval_expr_taint(self, expr: ast.AST, fact: ForwardFlowFact) -> Taint:
        """Evaluate taint of an expression.

        Args:
            expr: Expression node
            fact: Current flow fact

        Returns:
            Taint of the expression
        """
        if isinstance(expr, ast.Name):
            return fact.shape_env.get_taint(expr.id)

        elif isinstance(expr, ast.Attribute):
            if isinstance(expr.value, ast.Name):
                obj_name = expr.value.id
                field_name = expr.attr
                shape = fact.shape_env.get(obj_name)
                return shape.get_field(field_name)
            else:
                return self._eval_expr_taint(expr.value, fact)

        elif isinstance(expr, ast.Subscript):
            if isinstance(expr.value, ast.Name):
                arr_name = expr.value.id
                shape = fact.shape_env.get(arr_name)
                return shape.get_element()
            else:
                return self._eval_expr_taint(expr.value, fact)

        elif isinstance(expr, ast.Call):
            # Merge taint from all arguments
            result = Taint(status=TaintStatus.UNTAINTED)
            for arg in expr.args:
                arg_taint = self._eval_expr_taint(arg, fact)
                result = result.merge(arg_taint)
            return result

        elif isinstance(expr, ast.BinOp):
            left_taint = self._eval_expr_taint(expr.left, fact)
            right_taint = self._eval_expr_taint(expr.right, fact)
            return left_taint.merge(right_taint)

        elif isinstance(expr, ast.JoinedStr):
            result = Taint(status=TaintStatus.UNTAINTED)
            for value in expr.values:
                if isinstance(value, ast.FormattedValue):
                    taint = self._eval_expr_taint(value.value, fact)
                    result = result.merge(taint)
            return result

        elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            result = Taint(status=TaintStatus.UNTAINTED)
            for elt in expr.elts:
                taint = self._eval_expr_taint(elt, fact)
                result = result.merge(taint)
            return result

        else:
            return Taint(status=TaintStatus.UNTAINTED)

    def _expr_uses_var(self, expr: ast.AST, var_name: str, fact: ForwardFlowFact) -> bool:
        """Check if expression uses a variable (directly or transitively).

        Uses source-sensitive tracking via taint labels.

        Args:
            expr: Expression node
            var_name: Variable name to check
            fact: Current flow fact

        Returns:
            True if expression uses the variable
        """
        target_shape = fact.shape_env.get(var_name)
        target_taint = target_shape.get_taint()
        target_labels = target_taint.labels if target_taint.is_tainted() else set()
        expected_label = f"param:{var_name}"

        for node in ast.walk(expr):
            if isinstance(node, ast.Name):
                if node.id == var_name:
                    return True

                # Check transitive dependencies with source sensitivity
                node_shape = fact.shape_env.get(node.id)
                node_taint = node_shape.get_taint()

                if node_taint.is_tainted():
                    if expected_label in node_taint.labels:
                        return True

                    if target_labels and node_taint.labels & target_labels:
                        return True

                    # Check structural shapes
                    if node_shape.is_object:
                        for field_name, field_shape in node_shape.fields.items():
                            field_taint = field_shape.get_taint()
                            if expected_label in field_taint.labels:
                                return True

                    if node_shape.is_array and node_shape.element_shape:
                        elem_taint = node_shape.element_shape.get_taint()
                        if expected_label in elem_taint.labels:
                            return True

        return False

    def _get_call_name(self, node: ast.Call) -> str:
        """Get function call name.

        Args:
            node: Call node

        Returns:
            Function name
        """
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        try:
            return ast.unparse(node.func) if hasattr(ast, "unparse") else str(node.func)
        except (AttributeError, TypeError, ValueError):
            return "<unknown>"

    def _unparse_safe(self, node: ast.AST) -> str:
        """Safely unparse AST node."""
        try:
            if hasattr(ast, "unparse"):
                return ast.unparse(node)
            return str(node)
        except (AttributeError, TypeError, ValueError):
            return "<unparseable>"

    def _is_external_operation(self, call_name: str) -> bool:
        """Check if call is an external operation (network, file, subprocess).

        Args:
            call_name: Function call name

        Returns:
            True if external operation
        """
        external_patterns = [
            "requests",
            "urllib",
            "http",
            "socket",
            "post",
            "get",
            "fetch",
            "open",
            "read",
            "write",
            "file",
            "subprocess",
            "os.system",
            "os.popen",
            "exec",
            "eval",
        ]
        call_lower = call_name.lower()
        return any(pattern in call_lower for pattern in external_patterns)

    def _check_source_call(self, call_node: ast.Call) -> tuple[str, str] | None:
        """Check if a call is a source (credential file, env var).

        Returns:
            (source_type, source_name) if source, None otherwise
        """
        call_name = self._get_call_name(call_node)
        CREDENTIAL_FILES = [".aws/credentials", ".ssh/id_rsa", ".ssh/id_dsa", ".kube/config", ".netrc"]
        ENV_VAR_PATTERNS = ["API_KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL"]

        # Check for env var access
        if call_name in ["os.getenv", "os.environ.get", "getenv"]:
            for arg in call_node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if any(pattern in arg.value.upper() for pattern in ENV_VAR_PATTERNS):
                        return ("env_var", arg.value)

        # Check for credential file access
        for arg in call_node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if any(cred in arg.value for cred in CREDENTIAL_FILES):
                    return ("credential_file", arg.value)

        # Check for os.path.expanduser with credential paths
        if call_name == "os.path.expanduser":
            for arg in call_node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    if any(cred in arg.value for cred in CREDENTIAL_FILES):
                        return ("credential_file", arg.value)

        return None

    def _is_source_assignment(self, expr: ast.AST, source_name: str) -> bool:
        """Check if expression is an assignment from a source."""
        if isinstance(expr, ast.Call):
            source_info = self._check_source_call(expr)
            if source_info:
                source_type, name = source_info
                full_name = f"{source_type}:{name}"
                return full_name == source_name
        return False

    def _collect_flows(self) -> None:
        """Collect all flows from analysis results."""
        if not self.cfg or not self.cfg.exit:
            return

        # Get flows at exit node
        exit_fact = self.out_facts.get(self.cfg.exit.id)
        if exit_fact:
            for param_name, flow in exit_fact.parameter_flows.items():
                self.all_flows.append(flow)

    def merge(self, facts: list[ForwardFlowFact]) -> ForwardFlowFact:
        """Merge multiple flow facts.

        Args:
            facts: List of facts to merge

        Returns:
            Merged fact
        """
        if not facts:
            return ForwardFlowFact()

        if len(facts) == 1:
            return facts[0]

        result = facts[0].copy()

        for fact in facts[1:]:
            result.shape_env = result.shape_env.merge(fact.shape_env)

            # Merge parameter flows
            for param_name, flow in fact.parameter_flows.items():
                if param_name in result.parameter_flows:
                    # Deduplicate operations by checking if already present
                    # Operations are dicts, so we compare by content
                    existing_ops = result.parameter_flows[param_name].operations
                    existing_ops_set = {
                        (
                            op.get("type"),
                            op.get("target"),
                            op.get("value"),
                            op.get("function"),
                            op.get("argument"),
                            op.get("line"),
                        )
                        for op in existing_ops
                    }

                    for op in flow.operations:
                        op_key = (
                            op.get("type"),
                            op.get("target"),
                            op.get("value"),
                            op.get("function"),
                            op.get("argument"),
                            op.get("line"),
                        )
                        if op_key not in existing_ops_set:
                            existing_ops.append(op)
                            existing_ops_set.add(op_key)

                    # Deduplicate reaches_calls and reaches_assignments using sets
                    result.parameter_flows[param_name].reaches_calls = list(
                        set(result.parameter_flows[param_name].reaches_calls + flow.reaches_calls)
                    )
                    result.parameter_flows[param_name].reaches_assignments = list(
                        set(result.parameter_flows[param_name].reaches_assignments + flow.reaches_assignments)
                    )

                    # Boolean flags use OR (idempotent)
                    result.parameter_flows[param_name].reaches_returns = (
                        result.parameter_flows[param_name].reaches_returns or flow.reaches_returns
                    )
                    result.parameter_flows[param_name].reaches_external = (
                        result.parameter_flows[param_name].reaches_external or flow.reaches_external
                    )
                else:
                    result.parameter_flows[param_name] = flow

        return result
