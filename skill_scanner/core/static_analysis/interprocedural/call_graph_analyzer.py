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

"""Cross-file analysis for agent skills.

Tracks how function parameters flow through function calls across multiple files.
This enables detection of data exfiltration patterns that span multiple scripts.
"""

import ast
import logging
from pathlib import Path
from typing import Any


class CallGraph:
    """Call graph for cross-file analysis.

    Tracks function definitions and call relationships across multiple files.
    """

    def __init__(self) -> None:
        """Initialize call graph."""
        self.functions: dict[str, Any] = {}  # full_name -> function node
        self.calls: list[tuple] = []  # (caller, callee) pairs
        self.entry_points: set[str] = set()  # Skill entry point functions

    def add_function(self, name: str, node: Any, file_path: Path, is_entry_point: bool = False) -> None:
        """Add a function definition.

        Args:
            name: Function name
            node: Function definition node
            file_path: File containing the function
            is_entry_point: Whether this is a skill entry point
        """
        full_name = f"{file_path}::{name}"
        self.functions[full_name] = node
        if is_entry_point:
            self.entry_points.add(full_name)

    def add_call(self, caller: str, callee: str) -> None:
        """Add a function call edge.

        Args:
            caller: Caller function name
            callee: Callee function name
        """
        self.calls.append((caller, callee))

    def get_callees(self, func_name: str) -> list[str]:
        """Get functions called by a function.

        Args:
            func_name: Function name

        Returns:
            List of callee function names
        """
        return [callee for caller, callee in self.calls if caller == func_name]

    def get_entry_points(self) -> set[str]:
        """Get all entry point functions.

        Returns:
            Set of entry point function names
        """
        return self.entry_points.copy()


class CallGraphAnalyzer:
    """Performs cross-file analysis for agent skills.

    Tracks parameter flow from skill entry points through
    the entire codebase across multiple files.
    """

    def __init__(self) -> None:
        """Initialize cross-file analyzer."""
        self.call_graph = CallGraph()
        self.analyzers: dict[Path, ast.Module] = {}  # file -> AST
        self.import_map: dict[Path, list[Path]] = {}  # file -> imported files
        self.logger = logging.getLogger(__name__)

    def add_file(self, file_path: Path, source_code: str) -> None:
        """Add a file to the analysis.

        Args:
            file_path: Path to the file
            source_code: Source code content
        """
        try:
            tree = ast.parse(source_code)
            self.analyzers[file_path] = tree

            # Extract function definitions
            self._extract_functions(file_path, tree)

            # Extract imports
            self._extract_imports(file_path, tree)
        except SyntaxError as e:
            self.logger.debug(f"Skipping unparseable file {file_path}: {e}")

    def _extract_functions(self, file_path: Path, tree: ast.Module) -> None:
        """Extract function definitions from Python file.

        Args:
            file_path: File path
            tree: AST tree
        """
        # Extract top-level functions
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Check if it looks like an entry point (has main-like name or is decorated)
                is_entry = self._is_entry_point(node)
                self.call_graph.add_function(node.name, node, file_path, is_entry)

        # Extract class methods
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_full_name = f"{class_name}.{item.name}"
                        self.call_graph.add_function(method_full_name, item, file_path, False)

    def _is_entry_point(self, func_def: ast.FunctionDef) -> bool:
        """Check if function is a skill entry point.

        Entry points are identified by:
        - Function name starts with main, run, or execute
        - Function has decorators (common pattern for skills)

        Args:
            func_def: Function definition node

        Returns:
            True if entry point
        """
        # Check function name patterns
        name_lower = func_def.name.lower()
        if name_lower in ["main", "run", "execute", "process", "handle"]:
            return True
        if name_lower.startswith(("main_", "run_", "execute_", "process_", "handle_")):
            return True

        # Check for decorators (often indicate entry points)
        if func_def.decorator_list:
            return True

        return False

    def _extract_imports(self, file_path: Path, tree: ast.Module) -> None:
        """Extract import relationships.

        Args:
            file_path: File path
            tree: AST tree
        """
        imported_files = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name
                    imported_file = self._resolve_import(file_path, module_name)
                    if imported_file:
                        imported_files.append(imported_file)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_file = self._resolve_import(file_path, node.module)
                    if imported_file:
                        imported_files.append(imported_file)

        self.import_map[file_path] = imported_files

    def _resolve_import(self, from_file: Path, module_name: str) -> Path | None:
        """Resolve Python import to file path.

        Args:
            from_file: File doing the import
            module_name: Module name

        Returns:
            Resolved file path or None
        """
        module_parts = module_name.split(".")
        current_dir = from_file.parent

        # Try relative to current file
        for i in range(len(module_parts), 0, -1):
            potential_path = current_dir / "/".join(module_parts[:i])

            # Try as file
            py_file = potential_path.with_suffix(".py")
            if py_file.exists():
                return py_file

            # Try as package
            init_file = potential_path / "__init__.py"
            if init_file.exists():
                return init_file

        return None

    def build_call_graph(self) -> CallGraph:
        """Build the complete call graph.

        Returns:
            Call graph
        """
        # Extract function calls from each file
        for file_path, tree in self.analyzers.items():
            self._extract_calls(file_path, tree)

        return self.call_graph

    def _extract_calls(self, file_path: Path, tree: ast.Module) -> None:
        """Extract function calls from Python file.

        Args:
            file_path: File path
            tree: AST tree
        """
        # Extract calls from top-level functions
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                caller_name = f"{file_path}::{node.name}"
                self._extract_calls_from_function(file_path, node, caller_name)

        # Extract calls from class methods
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        caller_name = f"{file_path}::{class_name}.{item.name}"
                        self._extract_calls_from_function(file_path, item, caller_name)

    def _extract_calls_from_function(self, file_path: Path, func_node: ast.FunctionDef, caller_name: str) -> None:
        """Extract calls from a single function.

        Args:
            file_path: File path
            func_node: Function AST node
            caller_name: Full caller name
        """
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                callee_name = self._get_call_name(node)

                # Try to resolve to full name
                full_callee = self._resolve_call_target(file_path, callee_name)

                if full_callee:
                    self.call_graph.add_call(caller_name, full_callee)
                else:
                    # Add with partial name
                    self.call_graph.add_call(caller_name, callee_name)

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
            return ast.unparse(node.func)
        except (AttributeError, TypeError, ValueError):
            return "<unknown>"

    def _resolve_call_target(self, file_path: Path, call_name: str) -> str | None:
        """Resolve a function call to its full qualified name.

        Args:
            file_path: File where call occurs
            call_name: Function call name

        Returns:
            Full qualified name or None
        """
        # Check if it's defined in the same file
        for func_name in self.call_graph.functions.keys():
            if func_name.endswith(f"::{call_name}"):
                if func_name.startswith(str(file_path)):
                    return func_name

        # Check imported files
        if file_path in self.import_map:
            for imported_file in self.import_map[file_path]:
                potential_name = f"{imported_file}::{call_name}"
                if potential_name in self.call_graph.functions:
                    return potential_name

        return None

    def get_reachable_functions(self, start_func: str) -> list[str]:
        """Get all functions reachable from a starting function.

        Args:
            start_func: Starting function

        Returns:
            List of reachable function names
        """
        reachable = set()
        to_visit = [start_func]
        visited = set()

        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue

            visited.add(current)
            reachable.add(current)

            # Add all callees
            callees = self.call_graph.get_callees(current)
            for callee in callees:
                if callee not in visited:
                    to_visit.append(callee)

        return list(reachable)

    def analyze_parameter_flow_across_files(self, entry_point: str, param_names: list[str]) -> dict[str, Any]:
        """Analyze how parameters flow across files from an entry point.

        Args:
            entry_point: Entry point function name
            param_names: Parameter names to track

        Returns:
            Dictionary with cross-file flow information
        """
        # Get all reachable functions
        reachable = self.get_reachable_functions(entry_point)

        # Track parameter-influenced functions
        param_influenced_funcs = set()
        cross_file_flows = []

        for func_name in reachable:
            if func_name == entry_point:
                continue

            # Check if this function is called from entry point or influenced functions
            for caller, callee in self.call_graph.calls:
                if callee == func_name and (caller == entry_point or caller in param_influenced_funcs):
                    param_influenced_funcs.add(func_name)

                    # Extract file information
                    caller_file = caller.split("::")[0] if "::" in caller else "unknown"
                    callee_file = callee.split("::")[0] if "::" in callee else "unknown"

                    if caller_file != callee_file:
                        cross_file_flows.append(
                            {
                                "from_function": caller,
                                "to_function": callee,
                                "from_file": caller_file,
                                "to_file": callee_file,
                            }
                        )

        return {
            "reachable_functions": reachable,
            "param_influenced_functions": list(param_influenced_funcs),
            "cross_file_flows": cross_file_flows,
            "total_files_involved": len(set(f.split("::")[0] for f in reachable if "::" in f)),
        }

    def get_all_files(self) -> list[Path]:
        """Get all files in the analysis.

        Returns:
            List of file paths
        """
        return list(self.analyzers.keys())
