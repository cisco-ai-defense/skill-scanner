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

"""Control Flow Graph (CFG) builder for dataflow analysis.

Builds control flow graphs from Python ASTs to enable accurate dataflow
analysis through control structures (if/else, loops, functions).
"""

import ast
import logging
from typing import Any, Generic, TypeVar

from ..parser.python_parser import PythonParser

T = TypeVar("T")


class CFGNode:
    """Control Flow Graph node."""

    def __init__(self, node_id: int, ast_node: Any, label: str = "") -> None:
        """Initialize CFG node.

        Args:
            node_id: Unique node ID
            ast_node: Associated AST node
            label: Optional label
        """
        self.id = node_id
        self.ast_node = ast_node
        self.label = label
        self.predecessors: list[CFGNode] = []
        self.successors: list[CFGNode] = []

    def __repr__(self) -> str:
        """String representation."""
        return f"CFGNode({self.id}, {self.label})"


class ControlFlowGraph:
    """Control Flow Graph."""

    def __init__(self) -> None:
        """Initialize CFG."""
        self.nodes: list[CFGNode] = []
        self.entry: CFGNode | None = None
        self.exit: CFGNode | None = None
        self._node_counter = 0

    def create_node(self, ast_node: Any, label: str = "") -> CFGNode:
        """Create a new CFG node.

        Args:
            ast_node: AST node
            label: Optional label

        Returns:
            New CFG node
        """
        node = CFGNode(self._node_counter, ast_node, label)
        self._node_counter += 1
        self.nodes.append(node)
        return node

    def add_edge(self, from_node: CFGNode, to_node: CFGNode) -> None:
        """Add an edge between two nodes.

        Args:
            from_node: Source node
            to_node: Target node
        """
        from_node.successors.append(to_node)
        to_node.predecessors.append(from_node)

    def get_successors(self, node: CFGNode) -> list[CFGNode]:
        """Get successor nodes.

        Args:
            node: CFG node

        Returns:
            List of successor nodes
        """
        return node.successors

    def get_predecessors(self, node: CFGNode) -> list[CFGNode]:
        """Get predecessor nodes.

        Args:
            node: CFG node

        Returns:
            List of predecessor nodes
        """
        return node.predecessors


class DataFlowAnalyzer(Generic[T]):
    """Generic dataflow analysis framework."""

    def __init__(self, parser: PythonParser) -> None:
        """Initialize dataflow analyzer.

        Args:
            parser: Python parser instance
        """
        self.parser = parser
        self.cfg: ControlFlowGraph | None = None
        self.in_facts: dict[int, T] = {}
        self.out_facts: dict[int, T] = {}
        self.logger = logging.getLogger(__name__)

    def build_cfg(self) -> ControlFlowGraph:
        """Build Control Flow Graph from AST.

        Returns:
            Control Flow Graph
        """
        # Get AST from parser (PythonParser uses self.tree)
        ast_root = getattr(self.parser, "tree", None)
        if not ast_root:
            self.logger.warning("Cannot build CFG: no AST available. Call parser.parse() first.")
            return ControlFlowGraph()

        # Clear old state when building a new CFG to prevent state leakage
        self.in_facts.clear()
        self.out_facts.clear()

        cfg = ControlFlowGraph()
        self._build_python_cfg(ast_root, cfg)
        self.cfg = cfg
        return cfg

    def _build_python_cfg(self, node: ast.AST, cfg: ControlFlowGraph) -> CFGNode:
        """Build CFG for Python AST.

        Args:
            node: Python AST node
            cfg: Control Flow Graph

        Returns:
            Last CFG node created
        """
        if isinstance(node, ast.Module):
            entry = cfg.create_node(node, "entry")
            cfg.entry = entry

            current = entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(current, next_node)
                current = next_node

            exit_node = cfg.create_node(node, "exit")
            cfg.exit = exit_node
            cfg.add_edge(current, exit_node)

            return exit_node

        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Build CFG for function body
            entry = cfg.create_node(node, "func_entry")
            if not cfg.entry:
                cfg.entry = entry

            current = entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(current, next_node)
                current = next_node

            exit_node = cfg.create_node(node, "func_exit")
            if not cfg.exit:
                cfg.exit = exit_node
            cfg.add_edge(current, exit_node)

            return exit_node

        elif isinstance(node, ast.If):
            cond_node = cfg.create_node(node.test, "if_cond")

            then_entry = cfg.create_node(node, "then_entry")
            cfg.add_edge(cond_node, then_entry)

            then_current = then_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(then_current, next_node)
                then_current = next_node

            if node.orelse:
                else_entry = cfg.create_node(node, "else_entry")
                cfg.add_edge(cond_node, else_entry)

                else_current = else_entry
                for stmt in node.orelse:
                    next_node = self._build_python_cfg(stmt, cfg)
                    cfg.add_edge(else_current, next_node)
                    else_current = next_node

                merge = cfg.create_node(node, "if_merge")
                cfg.add_edge(then_current, merge)
                cfg.add_edge(else_current, merge)
                return merge
            else:
                merge = cfg.create_node(node, "if_merge")
                cfg.add_edge(then_current, merge)
                cfg.add_edge(cond_node, merge)
                return merge

        elif isinstance(node, ast.While):
            cond_node = cfg.create_node(node.test, "while_cond")

            body_entry = cfg.create_node(node, "while_body")
            cfg.add_edge(cond_node, body_entry)

            body_current = body_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(body_current, next_node)
                body_current = next_node

            cfg.add_edge(body_current, cond_node)

            exit_node = cfg.create_node(node, "while_exit")
            cfg.add_edge(cond_node, exit_node)

            return exit_node

        elif isinstance(node, ast.For):
            iter_node = cfg.create_node(node.iter, "for_iter")

            body_entry = cfg.create_node(node, "for_body")
            cfg.add_edge(iter_node, body_entry)

            body_current = body_entry
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(body_current, next_node)
                body_current = next_node

            cfg.add_edge(body_current, iter_node)

            exit_node = cfg.create_node(node, "for_exit")
            cfg.add_edge(iter_node, exit_node)

            return exit_node

        elif isinstance(node, ast.Try):
            # Handle try/except/finally blocks
            try_entry = cfg.create_node(node, "try_entry")
            current = try_entry

            # Try block
            for stmt in node.body:
                next_node = self._build_python_cfg(stmt, cfg)
                cfg.add_edge(current, next_node)
                current = next_node

            # Exception handlers
            if node.handlers:
                for handler in node.handlers:
                    handler_entry = cfg.create_node(handler, "except_entry")
                    cfg.add_edge(try_entry, handler_entry)
                    handler_current = handler_entry
                    for stmt in handler.body:
                        next_node = self._build_python_cfg(stmt, cfg)
                        cfg.add_edge(handler_current, next_node)
                        handler_current = next_node
                    # Merge exception handlers back
                    cfg.add_edge(handler_current, current)

            # Finally block
            if node.finalbody:
                finally_entry = cfg.create_node(node, "finally_entry")
                cfg.add_edge(current, finally_entry)
                finally_current = finally_entry
                for stmt in node.finalbody:
                    next_node = self._build_python_cfg(stmt, cfg)
                    cfg.add_edge(finally_current, next_node)
                    finally_current = next_node
                return finally_current

            return current

        else:
            return cfg.create_node(node, type(node).__name__)

    def analyze(self, initial_fact: T, forward: bool = True, max_iteration_multiplier: int = 1000) -> None:
        """Run dataflow analysis using worklist algorithm.

        Args:
            initial_fact: Initial dataflow fact
            forward: True for forward analysis, False for backward
            max_iteration_multiplier: Base multiplier for max iterations (default: 1000, increased from 500)
                                      Max iterations = CFG nodes * effective_multiplier
                                      Adaptive limits based on CFG size to handle complex files
        """
        if not self.cfg:
            self.build_cfg()

        if not self.cfg or not self.cfg.nodes:
            return

        # Clear facts dictionaries to ensure clean state (defensive programming)
        # This prevents any potential state leakage from previous analyses
        self.in_facts.clear()
        self.out_facts.clear()

        for node in self.cfg.nodes:
            self.in_facts[node.id] = initial_fact
            self.out_facts[node.id] = initial_fact

        worklist = list(self.cfg.nodes)
        in_worklist = {node.id for node in worklist}

        iteration_count = 0
        cfg_size = len(self.cfg.nodes)
        # Adaptive limit: Use higher multiplier for larger CFGs
        # Very small CFGs (< 20 nodes): 1000x multiplier (10k max iterations)
        # Small CFGs (20-50 nodes): 800x multiplier
        # Medium CFGs (50-100 nodes): 600x multiplier
        # Large CFGs (100-200 nodes): 400x multiplier
        # Very large CFGs (> 200 nodes): 300x multiplier (but still allows 60k+ iterations)
        if cfg_size < 20:
            effective_multiplier = max_iteration_multiplier  # 1000
        elif cfg_size < 50:
            effective_multiplier = int(max_iteration_multiplier * 0.8)  # 800
        elif cfg_size < 100:
            effective_multiplier = int(max_iteration_multiplier * 0.6)  # 600
        elif cfg_size < 200:
            effective_multiplier = int(max_iteration_multiplier * 0.4)  # 400
        else:
            effective_multiplier = int(max_iteration_multiplier * 0.3)  # 300
        max_iterations = cfg_size * effective_multiplier  # Safety limit

        while worklist:
            iteration_count += 1

            # Safety check to prevent infinite loops
            if iteration_count > max_iterations:
                # Log at debug level to reduce noise - this is expected for complex files
                # The analysis still completes, it just stops early at the safety limit
                self.logger.debug(
                    f"Dataflow analysis exceeded max iterations ({max_iterations:,} iterations, "
                    f"CFG size: {cfg_size} nodes). Analysis stopped at safety limit. "
                    f"This is normal for complex control flow and analysis may be incomplete."
                )
                break

            node = worklist.pop(0)
            in_worklist.discard(node.id)

            if forward:
                pred_facts = [self.out_facts[pred.id] for pred in node.predecessors]
                if pred_facts:
                    in_fact = self.merge(pred_facts)
                else:
                    in_fact = initial_fact

                self.in_facts[node.id] = in_fact

                out_fact = self.transfer(node, in_fact)

                if out_fact != self.out_facts[node.id]:
                    self.out_facts[node.id] = out_fact

                    for succ in node.successors:
                        if succ.id not in in_worklist:
                            worklist.append(succ)
                            in_worklist.add(succ.id)
            else:
                succ_facts = [self.in_facts[succ.id] for succ in node.successors]
                if succ_facts:
                    out_fact = self.merge(succ_facts)
                else:
                    out_fact = initial_fact

                self.out_facts[node.id] = out_fact

                in_fact = self.transfer(node, out_fact)

                if in_fact != self.in_facts[node.id]:
                    self.in_facts[node.id] = in_fact

                    for pred in node.predecessors:
                        if pred.id not in in_worklist:
                            worklist.append(pred)
                            in_worklist.add(pred.id)

    def transfer(self, node: CFGNode, in_fact: T) -> T:
        """Transfer function for dataflow analysis.

        Args:
            node: CFG node
            in_fact: Input dataflow fact

        Returns:
            Output dataflow fact
        """
        return in_fact

    def merge(self, facts: list[T]) -> T:
        """Merge multiple dataflow facts.

        Args:
            facts: List of facts to merge

        Returns:
            Merged fact
        """
        if facts:
            return facts[0]
        raise NotImplementedError("merge must be implemented by subclass")

    def get_reaching_definitions(self, node: CFGNode) -> T:
        """Get reaching definitions at a node.

        Args:
            node: CFG node

        Returns:
            Dataflow fact
        """
        return self.in_facts.get(node.id, self.in_facts.get(0) if self.in_facts else None)  # type: ignore
