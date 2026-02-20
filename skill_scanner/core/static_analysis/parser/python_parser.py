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

"""
Python AST parser for agent skills scripts.
"""

import ast
from dataclasses import dataclass, field


@dataclass
class FunctionInfo:
    """Information about a function in a skill script."""

    name: str
    parameters: list[str]
    docstring: str | None
    line_number: int
    source_code: str
    ast_node: ast.FunctionDef

    # Security indicators
    has_network_calls: bool = False
    has_file_operations: bool = False
    has_subprocess: bool = False
    has_eval_exec: bool = False

    # Collected elements
    imports: list[str] = field(default_factory=list)
    function_calls: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    assignments: list[str] = field(default_factory=list)


class PythonParser:
    """Parse Python source code and extract security-relevant information."""

    # Security-relevant patterns
    NETWORK_MODULES = ["requests", "urllib", "http", "socket", "aiohttp"]
    FILE_OPERATIONS = ["open", "read", "write", "Path", "os.remove", "shutil"]
    SUBPROCESS_PATTERNS = ["subprocess", "os.system", "os.popen"]
    DANGEROUS_FUNCTIONS = ["eval", "exec", "compile", "__import__"]

    # Agent tool indicators - map code patterns to agent tools
    TOOL_INDICATORS = {
        "Read": {
            "open",
            "read",
            "readline",
            "readlines",
            "Path.read_text",
            "Path.read_bytes",
            "json.load",
            "yaml.safe_load",
            "configparser",
        },
        "Write": {
            "write",
            "writelines",
            "Path.write_text",
            "Path.write_bytes",
            "json.dump",
            "yaml.dump",
        },
        "Bash": {
            "subprocess.run",
            "subprocess.call",
            "subprocess.Popen",
            "subprocess.check_output",
            "subprocess.check_call",
            "os.system",
            "os.popen",
            "os.spawn",
            "commands.getoutput",
            "commands.getstatusoutput",
        },
        "Grep": {
            "re.search",
            "re.match",
            "re.findall",
            "re.finditer",
            "re.sub",
            "re.split",
        },
        "Glob": {
            "glob.glob",
            "glob.iglob",
            "Path.glob",
            "Path.rglob",
            "fnmatch.fnmatch",
            "fnmatch.filter",
        },
        "Network": {
            "requests.get",
            "requests.post",
            "requests.put",
            "requests.delete",
            "urllib.request.urlopen",
            "urllib.urlopen",
            "http.client.HTTPConnection",
            "http.client.HTTPSConnection",
            "socket.connect",
            "socket.create_connection",
            "aiohttp.ClientSession",
            "httpx.get",
            "httpx.post",
        },
    }

    def __init__(self, source_code: str):
        """
        Initialize parser with source code.

        Args:
            source_code: Python source code to parse
        """
        self.source_code = source_code
        self.tree: ast.Module | None = None
        self.functions: list[FunctionInfo] = []
        self.imports: list[str] = []
        self.global_calls: list[str] = []
        self.module_strings: list[str] = []  # All strings at module/class level
        self.class_attributes: list[dict[str, str]] = []  # Class-level attributes

    def parse(self) -> bool:
        """
        Parse the source code.

        Returns:
            True if parsing succeeded, False otherwise
        """
        try:
            self.tree = ast.parse(self.source_code)
            self._extract_imports()
            self._extract_module_level_strings()
            self._extract_functions()
            self._extract_global_code()
            return True
        except SyntaxError as e:
            print(f"Syntax error in source: {e}")
            return False

    def _extract_module_level_strings(self) -> None:
        """Extract strings from module and class level (not in functions)."""
        if self.tree is None:
            return
        for node in self.tree.body:
            # Module-level assignments
            if isinstance(node, ast.Assign):
                for value_node in ast.walk(node.value):
                    if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                        self.module_strings.append(value_node.value)

            # Class definitions
            elif isinstance(node, ast.ClassDef):
                for class_node in node.body:
                    if isinstance(class_node, ast.Assign):
                        # Class attribute
                        for target in class_node.targets:
                            if isinstance(target, ast.Name):
                                # Extract value if it's a string constant
                                if isinstance(class_node.value, ast.Constant):
                                    if isinstance(class_node.value.value, str):
                                        self.module_strings.append(class_node.value.value)
                                        self.class_attributes.append(
                                            {"name": target.id, "value": class_node.value.value}
                                        )

    def _extract_imports(self) -> None:
        """Extract all import statements."""
        if self.tree is None:
            return
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.imports.append(node.module)

    def _extract_functions(self) -> None:
        """Extract all function definitions."""
        if self.tree is None:
            return
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                func_info = self._analyze_function(node)
                self.functions.append(func_info)

    def _analyze_function(self, node: ast.FunctionDef) -> FunctionInfo:
        """
        Analyze a function and extract security information.

        Args:
            node: AST FunctionDef node

        Returns:
            FunctionInfo with extracted data
        """
        # Extract parameters
        parameters = [arg.arg for arg in node.args.args]

        # Extract docstring
        docstring = ast.get_docstring(node)

        # Get source code snippet
        source_lines = self.source_code.split("\n")
        func_source = "\n".join(source_lines[node.lineno - 1 : node.end_lineno])

        # Create function info
        func_info = FunctionInfo(
            name=node.name,
            parameters=parameters,
            docstring=docstring,
            line_number=node.lineno,
            source_code=func_source,
            ast_node=node,
            imports=self.imports.copy(),
        )

        # Analyze function body for security indicators
        self._analyze_function_body(node, func_info)

        return func_info

    def _analyze_function_body(self, node: ast.FunctionDef, func_info: FunctionInfo):
        """Analyze function body for security patterns."""

        for child in ast.walk(node):
            # Check for function calls
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    func_info.function_calls.append(call_name)

                    # Check for security-relevant calls
                    if any(net in call_name for net in self.NETWORK_MODULES):
                        func_info.has_network_calls = True
                    if any(file_op in call_name for file_op in self.FILE_OPERATIONS):
                        func_info.has_file_operations = True
                    if any(sub in call_name for sub in self.SUBPROCESS_PATTERNS):
                        func_info.has_subprocess = True
                    if any(danger in call_name for danger in self.DANGEROUS_FUNCTIONS):
                        func_info.has_eval_exec = True

            # Extract string literals
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                if len(child.value) > 5:  # Skip very short strings
                    func_info.string_literals.append(child.value)

            # Track assignments
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        func_info.assignments.append(target.id)

    def _get_call_name(self, node: ast.Call) -> str | None:
        """Extract function call name from AST node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            # Handle module.function() calls
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return None

    def _extract_global_code(self) -> None:
        """Extract code executed at module level (not in functions)."""
        if self.tree is None:
            return
        for node in self.tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call_name = self._get_call_name(node.value)
                if call_name:
                    self.global_calls.append(call_name)

    def get_functions(self) -> list[FunctionInfo]:
        """Get all analyzed functions."""
        return self.functions

    def has_security_indicators(self) -> dict[str, bool]:
        """Check if code has any security indicators."""
        return {
            "has_network": any(f.has_network_calls for f in self.functions),
            "has_file_ops": any(f.has_file_operations for f in self.functions),
            "has_subprocess": any(f.has_subprocess for f in self.functions),
            "has_eval_exec": any(f.has_eval_exec for f in self.functions),
            "has_dangerous_imports": any(
                mod in self.imports for mod in self.NETWORK_MODULES + self.SUBPROCESS_PATTERNS
            ),
        }

    def get_inferred_tools(self) -> dict[str, bool]:
        """
        Determine which agent tools are implied by the code patterns.

        Analyzes function calls, imports, and patterns in the code to infer
        which agent tools would be needed to execute similar operations.

        Returns:
            Dictionary mapping tool names to whether they are detected
        """
        inferred = {tool: False for tool in self.TOOL_INDICATORS.keys()}

        # Collect all function calls from all functions
        all_calls = set()
        for func in self.functions:
            all_calls.update(func.function_calls)
        all_calls.update(self.global_calls)

        # Also check imports for module-level indicators
        import_based_tools = {
            "requests": "Network",
            "urllib": "Network",
            "aiohttp": "Network",
            "httpx": "Network",
            "socket": "Network",
            "subprocess": "Bash",
            "glob": "Glob",
            "fnmatch": "Glob",
            "re": "Grep",
        }

        for module in self.imports:
            base_module = module.split(".")[0]
            if base_module in import_based_tools:
                tool = import_based_tools[base_module]
                inferred[tool] = True

        # Check function calls against tool indicators
        for tool, patterns in self.TOOL_INDICATORS.items():
            for call in all_calls:
                # Check both exact match and partial match for method calls
                for pattern in patterns:
                    if pattern in call or call.endswith(pattern.split(".")[-1] if "." in pattern else pattern):
                        inferred[tool] = True
                        break
                if inferred[tool]:
                    break

        # Check for file operations that indicate Read/Write
        for func in self.functions:
            if func.has_file_operations:
                # Need to check if it's read or write
                for call in func.function_calls:
                    if any(r in call for r in ["read", "load"]):
                        inferred["Read"] = True
                    if any(w in call for w in ["write", "dump"]):
                        inferred["Write"] = True
            if func.has_subprocess:
                inferred["Bash"] = True
            if func.has_network_calls:
                inferred["Network"] = True

        return inferred

    def get_detected_tools_list(self) -> list[str]:
        """
        Get a list of agent tools that are detected in the code.

        Returns:
            List of tool names that were detected
        """
        inferred = self.get_inferred_tools()
        return [tool for tool, detected in inferred.items() if detected]
