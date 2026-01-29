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

"""Alignment Prompt Builder for Semantic Verification.

This module constructs comprehensive prompts for LLM-based semantic alignment
verification between skill descriptions and their actual implementation behavior.

The prompt builder creates evidence-rich prompts that present:
- Skill description/claims (what the skill says it does)
- Actual behavior evidence (what static analysis shows it does)
- Supporting dataflow and call graph evidence
"""

import json
import logging
import secrets
from pathlib import Path

from .....core.static_analysis.context_extractor import SkillFunctionContext


class AlignmentPromptBuilder:
    """Builds comprehensive prompts for semantic alignment verification.

    Constructs detailed prompts that provide LLMs with:
    - Function metadata and signatures
    - Parameter flow tracking evidence
    - Function call sequences
    - Cross-file call chains
    - Security indicators (file ops, network ops, etc.)
    - Control flow and data dependencies

    Uses randomized delimiters to prevent prompt injection attacks.
    """

    # Configurable limits for prompt size
    MAX_OPERATIONS_PER_PARAM = 10
    MAX_FUNCTION_CALLS = 20
    MAX_ASSIGNMENTS = 15
    MAX_CROSS_FILE_CALLS = 10
    MAX_REACHABLE_FILES = 5
    MAX_CONSTANTS = 10
    MAX_STRING_LITERALS = 15
    MAX_REACHES_CALLS = 10

    def __init__(
        self,
        max_operations: int | None = None,
        max_calls: int | None = None,
        max_assignments: int | None = None,
        max_cross_file_calls: int | None = None,
        max_reachable_files: int | None = None,
        max_constants: int | None = None,
        max_string_literals: int | None = None,
        max_reaches_calls: int | None = None,
    ):
        """Initialize the alignment prompt builder.

        Args:
            max_operations: Maximum operations to show per parameter
            max_calls: Maximum function calls to show
            max_assignments: Maximum assignments to show
            max_cross_file_calls: Maximum cross-file calls to show
            max_reachable_files: Maximum reachable files to show
            max_constants: Maximum constants to show
            max_string_literals: Maximum string literals to show
            max_reaches_calls: Maximum reaches calls to show
        """
        self.logger = logging.getLogger(__name__)
        self._template = self._load_template()

        # Use provided values or defaults
        self.MAX_OPERATIONS_PER_PARAM = max_operations or self.MAX_OPERATIONS_PER_PARAM
        self.MAX_FUNCTION_CALLS = max_calls or self.MAX_FUNCTION_CALLS
        self.MAX_ASSIGNMENTS = max_assignments or self.MAX_ASSIGNMENTS
        self.MAX_CROSS_FILE_CALLS = max_cross_file_calls or self.MAX_CROSS_FILE_CALLS
        self.MAX_REACHABLE_FILES = max_reachable_files or self.MAX_REACHABLE_FILES
        self.MAX_CONSTANTS = max_constants or self.MAX_CONSTANTS
        self.MAX_STRING_LITERALS = max_string_literals or self.MAX_STRING_LITERALS
        self.MAX_REACHES_CALLS = max_reaches_calls or self.MAX_REACHES_CALLS

    def build_prompt(self, func_context: SkillFunctionContext, skill_description: str | None = None) -> str:
        """Build comprehensive alignment verification prompt.

        Args:
            func_context: Complete function context with dataflow analysis
            skill_description: Overall skill description from SKILL.md

        Returns:
            Formatted prompt string with evidence
        """
        # Generate random delimiter tags to prevent prompt injection
        random_id = secrets.token_hex(16)
        start_tag = f"<!---UNTRUSTED_INPUT_START_{random_id}--->"
        end_tag = f"<!---UNTRUSTED_INPUT_END_{random_id}--->"

        docstring = func_context.docstring or "No docstring provided"

        # Build the analysis content using list accumulation for efficiency
        content_parts = []

        # Skill description (if provided)
        if skill_description:
            content_parts.append(f"""**SKILL DESCRIPTION (from SKILL.md):**
{skill_description}

""")

        # Function information
        content_parts.append(f"""**FUNCTION INFORMATION:**
- Function Name: {func_context.name}
- Line: {func_context.line_number}
- Docstring/Description: {docstring}

**FUNCTION SIGNATURE:**
- Parameters: {json.dumps(func_context.parameters, indent=2)}
- Return Type: {func_context.return_type or "Not specified"}
""")

        # Add imports section
        if func_context.imports:
            import_parts = ["\n**IMPORTS:**\n"]
            import_parts.append("The following libraries and modules are imported:\n")
            for imp in func_context.imports:
                import_parts.append(f"  {imp}\n")
            import_parts.append("\n")
            content_parts.append("".join(import_parts))

        content_parts.append("""
**DATAFLOW ANALYSIS:**
All parameters are treated as untrusted input (skill entry points receive external data).

Parameter Flow Tracking:
""")

        # Add parameter flow tracking
        if func_context.parameter_flows:
            param_parts = ["\n**PARAMETER FLOW TRACKING:**\n"]
            for flow in func_context.parameter_flows:
                param_name = flow.get("parameter", "unknown")
                param_parts.append(f"\nParameter '{param_name}' flows through:\n")

                if flow.get("operations"):
                    param_parts.append(f"  Operations ({len(flow['operations'])} total):\n")
                    for op in flow["operations"][: self.MAX_OPERATIONS_PER_PARAM]:
                        op_type = op.get("type", "unknown")
                        line = op.get("line", 0)
                        if op_type == "assignment":
                            param_parts.append(f"    Line {line}: {op.get('target')} = {op.get('value')}\n")
                        elif op_type == "function_call":
                            param_parts.append(f"    Line {line}: {op.get('function')}({op.get('argument')})\n")
                        elif op_type == "return":
                            param_parts.append(f"    Line {line}: return {op.get('value')}\n")

                if flow.get("reaches_calls"):
                    param_parts.append(
                        f"  Reaches function calls: {', '.join(flow['reaches_calls'][: self.MAX_REACHES_CALLS])}\n"
                    )

                if flow.get("reaches_external"):
                    param_parts.append("  [WARNING] REACHES EXTERNAL OPERATIONS (file/network/subprocess)\n")

                if flow.get("reaches_returns"):
                    param_parts.append("  Returns to caller\n")

            content_parts.append("".join(param_parts))

        # Add variable dependencies
        if func_context.variable_dependencies:
            var_parts = ["\n**VARIABLE DEPENDENCIES:**\n"]
            for var, deps in func_context.variable_dependencies.items():
                var_parts.append(f"  {var} depends on: {', '.join(deps)}\n")
            content_parts.append("".join(var_parts))

        # Add function calls
        if func_context.function_calls:
            call_parts = [f"\n**FUNCTION CALLS ({len(func_context.function_calls)} total):**\n"]
            for call in func_context.function_calls[: self.MAX_FUNCTION_CALLS]:
                try:
                    call_name = call.get("name", "unknown")
                    call_args = call.get("args", [])
                    call_line = call.get("line", 0)
                    call_parts.append(f"  Line {call_line}: {call_name}({', '.join(str(a) for a in call_args)})\n")
                except Exception:
                    continue
            content_parts.append("".join(call_parts))

        # Add assignments
        if func_context.assignments:
            assign_parts = [f"\n**ASSIGNMENTS ({len(func_context.assignments)} total):**\n"]
            for assign in func_context.assignments[: self.MAX_ASSIGNMENTS]:
                try:
                    line = assign.get("line", 0)
                    var = assign.get("variable", "unknown")
                    val = assign.get("value", "unknown")
                    assign_parts.append(f"  Line {line}: {var} = {val}\n")
                except Exception:
                    continue
            content_parts.append("".join(assign_parts))

        # Add control flow information
        if func_context.control_flow:
            content_parts.append(f"\n**CONTROL FLOW:**\n{json.dumps(func_context.control_flow, indent=2)}\n")

        # Add cross-file analysis
        if func_context.cross_file_calls:
            cross_file_parts = [
                f"\n**CROSS-FILE CALL CHAINS ({len(func_context.cross_file_calls)} calls to other files):**\n"
            ]
            cross_file_parts.append(
                "[WARNING] This function calls functions from other files. Full call chains shown:\n\n"
            )
            for call in func_context.cross_file_calls[: self.MAX_CROSS_FILE_CALLS]:
                try:
                    if "to_function" in call:
                        cross_file_parts.append(
                            f"  {call.get('from_function', 'unknown')} -> {call.get('to_function', 'unknown')}\n"
                        )
                        cross_file_parts.append(f"    From: {call.get('from_file', 'unknown')}\n")
                        cross_file_parts.append(f"    To: {call.get('to_file', 'unknown')}\n")
                    else:
                        func_name = call.get("function", "unknown")
                        file_name = call.get("file", "unknown")
                        cross_file_parts.append(f"  {func_name}() in {file_name}\n")
                    cross_file_parts.append("\n")
                except Exception:
                    continue
            cross_file_parts.append(
                "Note: Analyze the entire call chain to understand what operations are performed.\n"
            )
            content_parts.append("".join(cross_file_parts))

        # Add reachability analysis
        if func_context.reachable_functions:
            total_reachable = len(func_context.reachable_functions)
            functions_by_file = {}
            for func in func_context.reachable_functions:
                if "::" in func:
                    file_path, func_name = func.rsplit("::", 1)
                    if file_path not in functions_by_file:
                        functions_by_file[file_path] = []
                    functions_by_file[file_path].append(func_name)

            if len(functions_by_file) > 1:
                reach_parts = ["\n**REACHABILITY ANALYSIS:**\n"]
                reach_parts.append(
                    f"Total reachable functions: {total_reachable} across {len(functions_by_file)} file(s)\n\n"
                )
                for file_path, funcs in list(functions_by_file.items())[: self.MAX_REACHABLE_FILES]:
                    file_name = file_path.split("/")[-1] if "/" in file_path else file_path
                    reach_parts.append(f"  {file_name}: {', '.join(funcs[:10])}\n")
                    if len(funcs) > 10:
                        reach_parts.append(f"    ... and {len(funcs) - 10} more\n")
                content_parts.append("".join(reach_parts))

        # Add constants
        if func_context.constants:
            const_parts = ["\n**CONSTANTS:**\n"]
            for var, val in list(func_context.constants.items())[: self.MAX_CONSTANTS]:
                const_parts.append(f"  {var} = {val}\n")
            content_parts.append("".join(const_parts))

        # Add string literals
        if func_context.string_literals:
            lit_parts = [f"\n**STRING LITERALS ({len(func_context.string_literals)} total):**\n"]
            for literal in func_context.string_literals[: self.MAX_STRING_LITERALS]:
                safe_literal = literal.replace("\n", "\\n").replace("\r", "\\r")[:150]
                lit_parts.append(f'  "{safe_literal}"\n')
            content_parts.append("".join(lit_parts))

        # Add return expressions
        if func_context.return_expressions:
            ret_parts = ["\n**RETURN EXPRESSIONS:**\n"]
            if func_context.return_type:
                ret_parts.append(f"Declared return type: {func_context.return_type}\n")
            for ret_expr in func_context.return_expressions:
                ret_parts.append(f"  return {ret_expr}\n")
            content_parts.append("".join(ret_parts))

        # Add exception handling
        if func_context.exception_handlers:
            exc_parts = ["\n**EXCEPTION HANDLING:**\n"]
            for handler in func_context.exception_handlers:
                exc_parts.append(f"  Line {handler['line']}: except {handler['exception_type']}")
                if handler.get("is_silent"):
                    exc_parts.append(" ([WARNING] SILENT - just 'pass')\n")
                else:
                    exc_parts.append("\n")
            content_parts.append("".join(exc_parts))

        # Add environment variable access
        if func_context.env_var_access:
            env_parts = ["\n**ENVIRONMENT VARIABLE ACCESS:**\n"]
            env_parts.append("[WARNING] This function accesses environment variables:\n")
            for env_access in func_context.env_var_access:
                env_parts.append(f"  {env_access}\n")
            content_parts.append("".join(env_parts))

        # Add global variable writes
        if func_context.global_writes:
            global_parts = ["\n**GLOBAL VARIABLE WRITES:**\n"]
            global_parts.append("[WARNING] This function modifies global state:\n")
            for gwrite in func_context.global_writes:
                global_parts.append(f"  Line {gwrite['line']}: global {gwrite['variable']} = {gwrite['value']}\n")
            content_parts.append("".join(global_parts))

        # Add attribute access
        if func_context.attribute_access:
            writes = [op for op in func_context.attribute_access if op.get("type") == "write"]
            if writes:
                attr_parts = ["\n**ATTRIBUTE WRITES:**\n"]
                for op in writes[:10]:
                    attr_parts.append(f"  Line {op['line']}: {op['object']}.{op['attribute']} = {op['value']}\n")
                content_parts.append("".join(attr_parts))

        # Join all content parts efficiently
        analysis_content = "".join(content_parts)

        # Security validation: Check that the untrusted input doesn't contain our delimiter tags
        if start_tag in analysis_content or end_tag in analysis_content:
            self.logger.warning(
                f"Potential prompt injection detected in function {func_context.name}: Input contains delimiter tags"
            )

        # Wrap the untrusted content with randomized delimiters
        prompt = f"""{self._template}

{start_tag}
{analysis_content}
{end_tag}
"""

        return prompt.strip()

    def _load_template(self) -> str:
        """Load the alignment verification prompt template.

        Returns:
            Prompt template string
        """
        try:
            # Try to load from data/prompts directory
            prompt_file = (
                Path(__file__).parent.parent.parent.parent.parent
                / "data"
                / "prompts"
                / "skill_alignment_analysis_prompt.md"
            )

            if prompt_file.is_file():
                return prompt_file.read_text(encoding="utf-8")

            # Fallback to embedded prompt
            self.logger.warning("Prompt file not found, using embedded prompt")
            return self._get_embedded_prompt()

        except Exception as e:
            self.logger.warning(f"Failed to load prompt file: {e}, using embedded prompt")
            return self._get_embedded_prompt()

    def _get_embedded_prompt(self) -> str:
        """Get embedded fallback prompt template.

        Returns:
            Embedded prompt template
        """
        return """# Agent Skill Alignment Analysis

You are a security expert analyzing agent skills for alignment mismatches between their
described behavior and actual implementation.

## Your Task

Analyze the provided code evidence and determine if there are any mismatches between:
1. What the skill description/docstring claims the code does
2. What the code actually does based on dataflow analysis

## Analysis Guidelines

Focus on detecting:
- **Data Exfiltration**: Code that sends data to external servers not mentioned in description
- **Credential Theft**: Accessing credential files (.aws, .ssh) or environment variables
- **Hidden Network Calls**: Network operations not disclosed in skill description
- **Command Injection**: Executing arbitrary commands via user input
- **Unauthorized File Access**: Reading/writing files beyond stated scope

## Response Format

Respond with valid JSON:

```json
{
    "mismatch_detected": true/false,
    "threat_name": "THREAT_CATEGORY or empty",
    "severity": "CRITICAL/HIGH/MEDIUM/LOW/INFO",
    "confidence": "HIGH/MEDIUM/LOW",
    "summary": "Brief description of the mismatch",
    "description_claims": "What the skill claims to do",
    "actual_behavior": "What the code actually does",
    "security_implications": "Security impact",
    "dataflow_evidence": "Key evidence from dataflow analysis"
}
```

If no mismatch is detected, set mismatch_detected to false.

## Evidence to Analyze
"""
