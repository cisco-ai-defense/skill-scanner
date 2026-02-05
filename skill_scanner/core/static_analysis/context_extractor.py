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
Context extractor for agent skills behavioral analysis.

Extracts comprehensive security context from skill scripts for LLM analysis.
"""

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .dataflow.forward_analysis import ForwardDataflowAnalysis
from .parser.python_parser import FunctionInfo, PythonParser


@dataclass
class SkillScriptContext:
    """Complete security context for a skill script."""

    file_path: str
    functions: list[FunctionInfo]
    imports: list[str]
    dataflows: list[dict[str, Any]] = field(default_factory=list)  # Empty - pattern detection used instead

    # Security indicators (aggregated from all functions)
    has_network: bool = False
    has_file_ops: bool = False
    has_subprocess: bool = False
    has_eval_exec: bool = False
    has_credential_access: bool = False
    has_env_var_access: bool = False

    # Dangerous patterns (simple pattern matching results)
    dangerous_flows: list[dict[str, Any]] = field(default_factory=list)
    has_exfiltration_chain: bool = False
    has_injection_chain: bool = False

    # Evidence for LLM
    all_function_calls: list[str] = field(default_factory=list)
    all_string_literals: list[str] = field(default_factory=list)
    suspicious_urls: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for LLM prompt."""
        return {
            "file_path": self.file_path,
            "function_count": len(self.functions),
            "imports": self.imports,
            "security_indicators": {
                "has_network": self.has_network,
                "has_file_ops": self.has_file_ops,
                "has_subprocess": self.has_subprocess,
                "has_eval_exec": self.has_eval_exec,
                "has_credential_access": self.has_credential_access,
                "has_env_var_access": self.has_env_var_access,
            },
            "dangerous_patterns": {
                "exfiltration_chain": self.has_exfiltration_chain,
                "injection_chain": self.has_injection_chain,
                "dangerous_flow_count": len(self.dangerous_flows),
            },
            "functions": [
                {
                    "name": f.name,
                    "parameters": f.parameters,
                    "has_network": f.has_network_calls,
                    "has_file_ops": f.has_file_operations,
                    "has_subprocess": f.has_subprocess,
                    "has_eval_exec": f.has_eval_exec,
                    "calls": f.function_calls[:10],  # First 10
                }
                for f in self.functions
            ],
            "suspicious_urls": self.suspicious_urls,
        }


@dataclass
class SkillFunctionContext:
    """Complete context for a single function (for alignment verification).

    This dataclass contains rich analysis data for a single function,
    including dataflow analysis, parameter tracking, and behavioral patterns.
    Used by the alignment verification layer to detect description/code mismatches.
    """

    # Required fields (no defaults)
    name: str
    imports: list[str]
    function_calls: list[dict[str, Any]]
    assignments: list[dict[str, Any]]
    control_flow: dict[str, Any]
    parameter_flows: list[dict[str, Any]]  # All paths from parameters
    constants: dict[str, Any]
    variable_dependencies: dict[str, list[str]]
    has_file_operations: bool
    has_network_operations: bool
    has_subprocess_calls: bool
    has_eval_exec: bool

    # Optional fields (with defaults)
    docstring: str | None = None
    parameters: list[dict[str, Any]] = field(default_factory=list)
    return_type: str | None = None
    line_number: int = 0

    # Cross-file analysis
    cross_file_calls: list[dict[str, Any]] = field(default_factory=list)
    reachable_functions: list[str] = field(default_factory=list)

    # High-value security indicators
    string_literals: list[str] = field(default_factory=list)
    return_expressions: list[str] = field(default_factory=list)
    exception_handlers: list[dict[str, Any]] = field(default_factory=list)
    env_var_access: list[str] = field(default_factory=list)

    # State manipulation
    global_writes: list[dict[str, Any]] = field(default_factory=list)
    attribute_access: list[dict[str, Any]] = field(default_factory=list)

    # Dataflow facts
    dataflow_summary: dict[str, Any] = field(default_factory=dict)


class ContextExtractor:
    """Extract comprehensive security context from skill scripts."""

    # ONLY flag URLs to explicitly suspicious domains - not all unknown URLs
    # Reference: https://lots-project.com/ (Living Off Trusted Sites)
    SUSPICIOUS_DOMAINS = [
        # Known exfil/C2/paste services (LOTS: Download, Exfiltration, C&C)
        "pastebin.com",
        "hastebin.com",
        "paste.ee",
        "rentry.co",
        "zerobin.net",
        "textbin.net",
        "termbin.com",
        "sprunge.us",
        "clbin.com",
        "ix.io",
        "pastetext.net",
        "pastie.org",
        "ideone.com",
        # File sharing services (LOTS: Download, Exfiltration)
        "transfer.sh",
        "filebin.net",
        "gofile.io",
        "anonfiles.com",
        "mediafire.com",
        "mega.nz",
        "wetransfer.com",
        "filetransfer.io",
        "ufile.io",
        "4sync.com",
        "uplooder.net",
        "filecloudonline.com",
        "sendspace.com",
        "siasky.net",
        # Tunneling/webhook services (LOTS: C&C, Exfiltration)
        "webhook.site",
        "requestbin",
        "ngrok.io",
        "pipedream.net",
        "localhost.run",
        "trycloudflare.com",
        # Code execution services (LOTS: C&C, Download)
        "codepen.io",
        "repl.co",
        "glitch.me",
        # Explicitly malicious example domains
        "attacker.example.com",
        "evil.example.com",
        "malicious.com",
        "c2-server.com",
    ]

    # Domains that are always safe (not flagged even if matched by SUSPICIOUS_DOMAINS pattern)
    # NOTE: We intentionally exclude file-hosting/messaging services that appear in LOTS
    # (https://lots-project.com/) with Download/C&C capabilities, even if commonly used.
    LEGITIMATE_DOMAINS = [
        # AI provider services (API endpoints only, not user content)
        "api.anthropic.com",
        "statsig.anthropic.com",
        "api.openai.com",
        "api.together.xyz",
        "api.cohere.ai",
        "generativelanguage.googleapis.com",
        # Package registries (read-only, no user-uploaded executables)
        "registry.npmjs.org",
        "npmjs.com",
        "npmjs.org",
        "yarnpkg.com",
        "registry.yarnpkg.com",
        "pypi.org",
        "files.pythonhosted.org",
        "pythonhosted.org",
        "crates.io",
        "rubygems.org",
        "pkg.go.dev",
        # System packages
        "archive.ubuntu.com",
        "security.ubuntu.com",
        "debian.org",
        # XML schemas (for OOXML document processing)
        "schemas.microsoft.com",
        "schemas.openxmlformats.org",
        "www.w3.org",
        "purl.org",
        "json-schema.org",
        # Localhost and development
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
        # Common safe services (API-focused, not file hosting)
        "stripe.com",
        "zoom.us",
        "twilio.com",
        "mailgun.com",
        "sentry.io",
        "datadog.com",
        "newrelic.com",
        "elastic.co",
        "mongodb.com",
        "redis.io",
        "postgresql.org",
        # NOTE: The following are intentionally NOT in this list due to LOTS risk:
        # - github.com, gitlab.com, bitbucket.org (Download, C&C)
        # - raw.githubusercontent.com (Download, C&C)
        # - discord.com, telegram.org, slack.com (C&C, Exfil)
        # - amazonaws.com, googleapis.com, azure.com, cloudflare.com (wildcard hosting)
        # - google.com, microsoft.com (too broad, includes file hosting)
        # - sendgrid.com (email tracking/download)
    ]

    def extract_context(self, file_path: Path, source_code: str) -> SkillScriptContext:
        """
        Extract complete security context from a script.

        Args:
            file_path: Path to the script file
            source_code: Python source code

        Returns:
            SkillScriptContext with extracted information
        """
        # Parse with AST parser
        parser = PythonParser(source_code)
        if not parser.parse():
            # Return empty context if parsing fails
            return SkillScriptContext(file_path=str(file_path), functions=[], imports=[], dataflows=[])

        # Aggregate security indicators
        has_network = any(f.has_network_calls for f in parser.functions)
        has_file_ops = any(f.has_file_operations for f in parser.functions)
        has_subprocess = any(f.has_subprocess for f in parser.functions)
        has_eval_exec = any(f.has_eval_exec for f in parser.functions)

        # Use CFG-based ForwardDataflowAnalysis for script-level source detection and flow tracking
        try:
            forward_analyzer = ForwardDataflowAnalysis(parser, parameter_names=[], detect_sources=True)
            script_flows = forward_analyzer.analyze_forward_flows()
        except Exception as e:
            import logging

            logging.getLogger(__name__).warning(f"CFG-based script-level analysis failed: {e}")
            script_flows = []

        # Extract credential/env access from detected sources
        has_credential_access = any(flow.parameter_name.startswith("credential_file:") for flow in script_flows)
        has_env_var_access = any(flow.parameter_name.startswith("env_var:") for flow in script_flows)

        # Extract dangerous flows
        dangerous_flows = []
        for flow in script_flows:
            if flow.reaches_external:
                source_type = "parameter"
                if flow.parameter_name.startswith("credential_file:"):
                    source_type = "credential_file"
                elif flow.parameter_name.startswith("env_var:"):
                    source_type = "env_var"

                # Determine sink type from calls
                sink_type = "external"
                network_calls = ["requests", "urllib", "http", "socket", "post", "get"]
                eval_calls = ["eval", "exec", "compile"]
                if any(any(nc in call.lower() for nc in network_calls) for call in flow.reaches_calls):
                    sink_type = "network"
                elif any(any(ec in call.lower() for ec in eval_calls) for call in flow.reaches_calls):
                    sink_type = "eval"

                dangerous_flows.append(
                    {
                        "source_type": source_type,
                        "source_name": flow.parameter_name,
                        "sink_type": sink_type,
                        "sink_operation": ", ".join(flow.reaches_calls),
                        "is_dangerous": True,
                    }
                )

        has_exfiltration_chain = any(
            flow.get("source_type") in ["credential_file", "env_var"] and flow.get("sink_type") == "network"
            for flow in dangerous_flows
        )
        has_injection_chain = any(
            flow.get("source_type") == "parameter" and flow.get("sink_type") == "eval" for flow in dangerous_flows
        )

        # Collect all function calls and strings
        all_calls = []
        all_strings = []
        for func in parser.functions:
            all_calls.extend(func.function_calls)
            all_strings.extend(func.string_literals)

        # Also collect module-level strings (class attributes, etc.)
        all_strings.extend(parser.module_strings)

        # Find suspicious URLs - ONLY flag URLs to known-bad destinations
        # Don't flag unknown URLs - that creates too many false positives
        suspicious_urls = []
        for s in all_strings:
            # Skip if not URL-like or contains newlines (docstrings)
            if "\n" in s or not s.startswith("http"):
                continue
            # Skip if too long (likely docstring) or too short
            if len(s) > 200 or len(s) < 10:
                continue
            # Skip if contains legitimate domain
            if any(domain in s for domain in self.LEGITIMATE_DOMAINS):
                continue
            # ONLY flag if URL contains a known suspicious domain
            # Don't flag all unknown URLs - that's too aggressive
            if any(domain in s for domain in self.SUSPICIOUS_DOMAINS):
                suspicious_urls.append(s)

        # Create context
        context = SkillScriptContext(
            file_path=str(file_path),
            functions=parser.functions,
            imports=parser.imports,
            dataflows=[],  # Empty - using pattern detection instead
            has_network=has_network,
            has_file_ops=has_file_ops,
            has_subprocess=has_subprocess,
            has_eval_exec=has_eval_exec,
            has_credential_access=has_credential_access,
            has_env_var_access=has_env_var_access,
            dangerous_flows=dangerous_flows,
            has_exfiltration_chain=has_exfiltration_chain,
            has_injection_chain=has_injection_chain,
            all_function_calls=list(set(all_calls)),
            all_string_literals=all_strings,
            suspicious_urls=suspicious_urls,
        )

        return context

    def extract_function_contexts(self, file_path: Path, source_code: str) -> list[SkillFunctionContext]:
        """Extract detailed context for each function in the source code.

        Used by the alignment verification layer to analyze individual functions.

        Args:
            file_path: Path to the script file
            source_code: Python source code

        Returns:
            List of SkillFunctionContext for each function
        """
        contexts = []

        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return contexts

        # Parse with AST parser
        parser = PythonParser(source_code)
        if not parser.parse():
            return contexts

        # Extract module-level imports
        imports = parser.imports

        # Process each function
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                context = self._extract_function_context(node, imports, source_code, file_path)
                if context:
                    contexts.append(context)

        return contexts

    def _extract_function_context(
        self, node: ast.FunctionDef, imports: list[str], source_code: str, file_path: Path
    ) -> SkillFunctionContext:
        """Extract detailed context for a single function.

        Args:
            node: Function AST node
            imports: Module-level imports
            source_code: Full source code
            file_path: Path to the file

        Returns:
            SkillFunctionContext with extracted information
        """
        # Basic info
        name = node.name
        docstring = ast.get_docstring(node)
        parameters = self._extract_parameters(node)
        return_type = self._extract_return_type(node)
        line_number = node.lineno

        # Code structure
        function_calls = self._extract_function_calls(node)
        assignments = self._extract_assignments(node)
        control_flow = self._analyze_control_flow(node)

        # Parameter flow analysis
        parameter_flows = self._analyze_parameter_flows(node, parameters)

        # Constants
        constants = self._extract_constants(node)

        # Variable dependencies
        var_deps = self._analyze_variable_dependencies(node)

        # Behavioral patterns
        has_file_ops = self._has_file_operations(node)
        has_network_ops = self._has_network_operations(node)
        has_subprocess = self._has_subprocess_calls(node)
        has_eval_exec = self._has_eval_exec(node)

        # High-value security indicators
        string_literals = self._extract_string_literals(node)
        return_expressions = self._extract_return_expressions(node)
        exception_handlers = self._extract_exception_handlers(node)
        env_var_access = self._extract_env_var_access(node)

        # State manipulation
        global_writes = self._extract_global_writes(node)
        attribute_access = self._extract_attribute_access(node)

        # Dataflow summary
        dataflow_summary = self._create_dataflow_summary(node)

        return SkillFunctionContext(
            name=name,
            docstring=docstring,
            parameters=parameters,
            return_type=return_type,
            line_number=line_number,
            imports=imports,
            function_calls=function_calls,
            assignments=assignments,
            control_flow=control_flow,
            parameter_flows=parameter_flows,
            constants=constants,
            variable_dependencies=var_deps,
            has_file_operations=has_file_ops,
            has_network_operations=has_network_ops,
            has_subprocess_calls=has_subprocess,
            has_eval_exec=has_eval_exec,
            string_literals=string_literals,
            return_expressions=return_expressions,
            exception_handlers=exception_handlers,
            env_var_access=env_var_access,
            global_writes=global_writes,
            attribute_access=attribute_access,
            dataflow_summary=dataflow_summary,
        )

    def _extract_parameters(self, node: ast.FunctionDef) -> list[dict[str, Any]]:
        """Extract function parameters with type hints."""
        params = []
        for arg in node.args.args:
            param_info = {"name": arg.arg}
            if arg.annotation:
                try:
                    param_info["type"] = ast.unparse(arg.annotation)
                except (AttributeError, TypeError, ValueError):
                    param_info["type"] = "<unknown>"
            params.append(param_info)
        return params

    def _extract_return_type(self, node: ast.FunctionDef) -> str:
        """Extract return type annotation."""
        if node.returns:
            try:
                return ast.unparse(node.returns)
            except (AttributeError, TypeError, ValueError):
                return "<unknown>"
        return None

    def _extract_function_calls(self, node: ast.FunctionDef) -> list[dict[str, Any]]:
        """Extract all function calls with arguments."""
        calls = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                args_list = []
                for arg in child.args:
                    try:
                        args_list.append(ast.unparse(arg))
                    except (AttributeError, TypeError, ValueError):
                        args_list.append("<complex>")

                call_info = {
                    "name": self._get_call_name(child),
                    "args": args_list,
                    "line": child.lineno if hasattr(child, "lineno") else 0,
                }
                calls.append(call_info)
        return calls

    def _get_call_name(self, node: ast.Call) -> str:
        """Get function call name."""
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

    def _extract_assignments(self, node: ast.FunctionDef) -> list[dict[str, Any]]:
        """Extract all assignments."""
        assignments = []
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        try:
                            value_str = ast.unparse(child.value)
                        except (AttributeError, TypeError, ValueError):
                            value_str = "<complex>"
                        assignments.append(
                            {
                                "variable": target.id,
                                "value": value_str,
                                "line": child.lineno if hasattr(child, "lineno") else 0,
                            }
                        )
        return assignments

    def _analyze_control_flow(self, node: ast.FunctionDef) -> dict[str, Any]:
        """Analyze control flow structure."""
        has_if = any(isinstance(n, ast.If) for n in ast.walk(node))
        has_for = any(isinstance(n, (ast.For, ast.AsyncFor)) for n in ast.walk(node))
        has_while = any(isinstance(n, ast.While) for n in ast.walk(node))
        has_try = any(isinstance(n, ast.Try) for n in ast.walk(node))

        return {
            "has_conditionals": has_if,
            "has_loops": has_for or has_while,
            "has_exception_handling": has_try,
        }

    def _analyze_parameter_flows(self, node: ast.FunctionDef, parameters: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze how parameters flow through the function using CFG-based analysis.

        Uses proper control flow graph and fixpoint analysis for accurate tracking
        through branches, loops, and function calls.
        """
        flows = []
        param_names = [p["name"] for p in parameters]

        if not param_names:
            return flows

        # Extract function source code for parser
        try:
            func_source = ast.unparse(node) if hasattr(ast, "unparse") else None
        except (AttributeError, TypeError, ValueError):
            # Reconstruct from AST if unparse fails

            param_str = ", ".join(p["name"] for p in parameters)
            func_source = f"def {node.name}({param_str}):\n    pass"

        if not func_source:
            return flows

        # Create parser and run CFG-based forward analysis
        parser = PythonParser(func_source)
        if not parser.parse():
            return flows

        try:
            forward_analyzer = ForwardDataflowAnalysis(parser, param_names)
            flow_paths = forward_analyzer.analyze_forward_flows()

            # Convert FlowPath objects to dict format
            for flow_path in flow_paths:
                flows.append(
                    {
                        "parameter": flow_path.parameter_name,
                        "operations": flow_path.operations,
                        "reaches_calls": flow_path.reaches_calls,
                        "reaches_assignments": flow_path.reaches_assignments,
                        "reaches_returns": flow_path.reaches_returns,
                        "reaches_external": flow_path.reaches_external,
                    }
                )
        except Exception as e:
            # Log error but return empty flows (no fallback)
            import logging

            logging.getLogger(__name__).warning(f"CFG-based parameter flow analysis failed: {e}")
            return flows

        return flows

    def _extract_constants(self, node: ast.FunctionDef) -> dict[str, Any]:
        """Extract constant values."""
        constants = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and isinstance(child.value, ast.Constant):
                        constants[target.id] = child.value.value
        return constants

    def _analyze_variable_dependencies(self, node: ast.FunctionDef) -> dict[str, list[str]]:
        """Analyze variable dependencies."""
        dependencies = {}
        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        deps = []
                        for name_node in ast.walk(child.value):
                            if isinstance(name_node, ast.Name):
                                deps.append(name_node.id)
                        dependencies[target.id] = deps
        return dependencies

    def _has_file_operations(self, node: ast.FunctionDef) -> bool:
        """Check for file operations."""
        file_patterns = ["open", "read", "write", "path", "file", "os.remove", "shutil"]
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child).lower()
                if any(pattern in call_name for pattern in file_patterns):
                    return True
        return False

    def _has_network_operations(self, node: ast.FunctionDef) -> bool:
        """Check for network operations."""
        network_patterns = ["requests", "urllib", "http", "socket", "post", "get", "fetch"]
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child).lower()
                if any(pattern in call_name for pattern in network_patterns):
                    return True
        return False

    def _has_subprocess_calls(self, node: ast.FunctionDef) -> bool:
        """Check for subprocess calls."""
        subprocess_patterns = ["subprocess", "os.system", "os.popen", "shell", "exec"]
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child).lower()
                if any(pattern in call_name for pattern in subprocess_patterns):
                    return True
        return False

    def _has_eval_exec(self, node: ast.FunctionDef) -> bool:
        """Check for eval/exec calls."""
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name in ["eval", "exec", "compile", "__import__"]:
                    return True
        return False

    def _extract_string_literals(self, node: ast.FunctionDef) -> list[str]:
        """Extract all string literals from function."""
        literals = []
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                literal = child.value[:200]
                if literal and literal not in literals:
                    literals.append(literal)
        return literals[:20]

    def _extract_return_expressions(self, node: ast.FunctionDef) -> list[str]:
        """Extract return expressions from function."""
        returns = []
        for child in ast.walk(node):
            if isinstance(child, ast.Return) and child.value:
                try:
                    return_expr = ast.unparse(child.value)[:100]
                    returns.append(return_expr)
                except (AttributeError, TypeError, ValueError):
                    returns.append("<unparseable>")
        return returns

    def _extract_exception_handlers(self, node: ast.FunctionDef) -> list[dict[str, Any]]:
        """Extract exception handling details."""
        handlers = []
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                handler_info = {
                    "line": child.lineno,
                    "exception_type": ast.unparse(child.type) if child.type else "Exception",
                    "is_silent": len(child.body) == 1 and isinstance(child.body[0], ast.Pass),
                }
                handlers.append(handler_info)
        return handlers

    def _extract_env_var_access(self, node: ast.FunctionDef) -> list[str]:
        """Extract environment variable accesses."""
        env_accesses = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if "environ" in call_name or "getenv" in call_name:
                    if child.args and isinstance(child.args[0], ast.Constant):
                        key = child.args[0].value
                        env_accesses.append(f"{call_name}('{key}')")
                    else:
                        env_accesses.append(call_name)
        return env_accesses

    def _extract_global_writes(self, node: ast.FunctionDef) -> list[dict[str, Any]]:
        """Extract global variable writes."""
        global_writes = []
        global_vars = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Global):
                global_vars.update(child.names)

        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name) and target.id in global_vars:
                        try:
                            value_str = ast.unparse(child.value)[:100]
                        except (AttributeError, TypeError, ValueError):
                            value_str = "<complex>"
                        global_writes.append({"variable": target.id, "value": value_str, "line": child.lineno})

        return global_writes

    def _extract_attribute_access(self, node: ast.FunctionDef) -> list[dict[str, Any]]:
        """Extract attribute access patterns."""
        attribute_ops = []

        for child in ast.walk(node):
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Attribute):
                        obj_name = ""
                        if isinstance(target.value, ast.Name):
                            obj_name = target.value.id
                        try:
                            value_str = ast.unparse(child.value)[:100]
                        except (AttributeError, TypeError, ValueError):
                            value_str = "<complex>"
                        attribute_ops.append(
                            {
                                "type": "write",
                                "object": obj_name,
                                "attribute": target.attr,
                                "value": value_str,
                                "line": child.lineno,
                            }
                        )

        return attribute_ops[:20]

    def _create_dataflow_summary(self, node: ast.FunctionDef) -> dict[str, Any]:
        """Create dataflow summary."""
        return {
            "total_statements": len([n for n in ast.walk(node) if isinstance(n, ast.stmt)]),
            "total_expressions": len([n for n in ast.walk(node) if isinstance(n, ast.expr)]),
            "complexity": self._calculate_complexity(node),
        }

    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity."""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity
