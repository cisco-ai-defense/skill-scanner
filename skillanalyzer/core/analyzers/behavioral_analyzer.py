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
Behavioral analyzer for agent skills using static dataflow analysis.

Analyzes skill scripts using AST parsing, dataflow tracking, and description-behavior
alignment checking. Detects threats through code analysis without execution.

Features:
- Static dataflow analysis for code behavior tracking
- Cross-file correlation analysis
- LLM-powered alignment verification (optional)
- Threat vs vulnerability classification
"""

import asyncio
import hashlib
import logging
import os
from pathlib import Path
from typing import Any

from ...core.models import Finding, Severity, Skill, ThreatCategory
from ...core.static_analysis.context_extractor import (
    ContextExtractor,
    SkillFunctionContext,
    SkillScriptContext,
)
from ...core.static_analysis.interprocedural.call_graph_analyzer import CallGraphAnalyzer
from ...core.static_analysis.interprocedural.cross_file_analyzer import CrossFileAnalyzer, CrossFileCorrelation
from .base import BaseAnalyzer

logger = logging.getLogger(__name__)


class BehavioralAnalyzer(BaseAnalyzer):
    """
    Behavioral analyzer using static dataflow analysis.

    Analyzes skill scripts through:
    1. AST parsing and function extraction
    2. Dataflow tracking (sources → sinks)
    3. Description-behavior alignment checking (optional LLM-powered)
    4. Threat pattern detection
    5. Cross-file correlation analysis

    Does NOT execute code - uses static analysis for safety.
    """

    def __init__(
        self,
        use_static_analysis: bool = True,
        use_alignment_verification: bool = False,
        llm_model: str | None = None,
        llm_api_key: str | None = None,
    ):
        """
        Initialize behavioral analyzer.

        Args:
            use_static_analysis: Deprecated parameter, kept for backward compatibility.
                Static analysis is always enabled as it's required for the analyzer to function.
            use_alignment_verification: Enable LLM-powered alignment verification
            llm_model: LLM model for alignment verification (e.g., "gemini/gemini-2.0-flash")
            llm_api_key: API key for the LLM provider (or resolved from environment)

        Note:
            This analyzer currently only processes Python (.py) files.
            Markdown files with code blocks (e.g., bash in .md files) are not analyzed.
            Use the LLM analyzer for comprehensive markdown/bash code block analysis.
        """
        super().__init__("behavioral_analyzer")

        # Static analysis is always required - the parameter is kept for backward compatibility
        if not use_static_analysis:
            logger.warning(
                "use_static_analysis=False is deprecated and ignored. "
                "Static analysis is required for the behavioral analyzer to function."
            )
        self.use_static_analysis = True  # Always enabled
        self.use_alignment_verification = use_alignment_verification
        self.context_extractor = ContextExtractor()  # Always initialized

        # Alignment verification (LLM-powered)
        self.alignment_orchestrator = None
        if use_alignment_verification:
            try:
                from .behavioral.alignment import AlignmentOrchestrator

                # Resolve LLM configuration - use SKILL_SCANNER_LLM_* variables
                model = llm_model or os.environ.get("SKILL_SCANNER_LLM_MODEL", "gemini/gemini-2.0-flash")
                api_key = llm_api_key or os.environ.get("SKILL_SCANNER_LLM_API_KEY")

                if api_key:
                    self.alignment_orchestrator = AlignmentOrchestrator(
                        llm_model=model,
                        llm_api_key=api_key,
                    )
                    logger.info("Alignment verification enabled with %s", model)
                else:
                    logger.warning("Alignment verification requested but no API key found")
            except ImportError as e:
                logger.warning("Alignment verification not available: %s", e)

    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze skill using static dataflow analysis.

        Note: Currently only analyzes Python files. Markdown files with
        bash/shell code blocks require the LLM analyzer.

        Args:
            skill: Skill to analyze

        Returns:
            List of behavioral findings
        """
        return self._analyze_static(skill)

    def _analyze_static(self, skill: Skill) -> list[Finding]:
        """Analyze skill using static dataflow analysis with cross-file correlation."""
        findings = []
        cross_file = CrossFileAnalyzer()
        call_graph_analyzer = CallGraphAnalyzer()

        # Get skill description for alignment verification
        skill_description = None
        if skill.manifest:
            skill_description = skill.manifest.description

        # First pass: Extract context from each Python script
        for script_file in skill.get_scripts():
            if script_file.file_type != "python":
                continue

            content = script_file.read_content()
            if not content:
                continue

            # Add to call graph analyzer
            call_graph_analyzer.add_file(script_file.path, content)

            # Extract security context
            try:
                context = self.context_extractor.extract_context(script_file.path, content)

                # Add to cross-file analyzer
                cross_file.add_file_context(script_file.relative_path, context)

                # Generate findings from individual file context
                script_findings = self._generate_findings_from_context(context, skill)
                findings.extend(script_findings)

                # Alignment verification (LLM-powered)
                if self.alignment_orchestrator:
                    alignment_findings = self._run_alignment_verification(script_file.path, content, skill_description)
                    findings.extend(alignment_findings)

            except Exception as e:
                logger.warning("Failed to analyze %s: %s", script_file.relative_path, e)

        # Build call graph for cross-file analysis
        call_graph_analyzer.build_call_graph()

        # Second pass: Analyze cross-file correlations
        correlations = cross_file.analyze_correlations()
        correlation_findings = self._generate_findings_from_correlations(correlations, skill)
        findings.extend(correlation_findings)

        return findings

    def _run_alignment_verification(
        self,
        file_path: Path,
        source_code: str,
        skill_description: str | None,
    ) -> list[Finding]:
        """Run LLM-powered alignment verification on a file.

        Args:
            file_path: Path to the script file
            source_code: Python source code
            skill_description: Overall skill description from SKILL.md

        Returns:
            List of findings from alignment verification
        """
        findings = []

        if not self.alignment_orchestrator:
            return findings

        try:
            # Extract function contexts for alignment verification
            function_contexts = self.context_extractor.extract_function_contexts(file_path, source_code)

            # Run alignment verification on each function
            for func_context in function_contexts:
                try:
                    # Run async alignment check
                    result = asyncio.get_event_loop().run_until_complete(
                        self.alignment_orchestrator.check_alignment(func_context, skill_description)
                    )

                    if result:
                        analysis, ctx = result
                        finding = self._create_alignment_finding(analysis, ctx, str(file_path))
                        if finding:
                            findings.append(finding)

                except Exception as e:
                    logger.warning("Alignment check failed for %s: %s", func_context.name, e)

        except Exception as e:
            logger.warning("Alignment verification failed for %s: %s", file_path, e)

        return findings

    def _create_alignment_finding(
        self,
        analysis: dict[str, Any],
        func_context: SkillFunctionContext,
        file_path: str,
    ) -> Finding | None:
        """Create a Finding from alignment verification result.

        Args:
            analysis: Analysis dict from LLM
            func_context: Function context that was analyzed
            file_path: Path to the source file

        Returns:
            Finding object or None if invalid
        """
        try:
            threat_name = analysis.get("threat_name", "ALIGNMENT_MISMATCH").upper()
            severity_str = analysis.get("severity", "MEDIUM").upper()

            # Map severity
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
                "LOW": Severity.LOW,
                "INFO": Severity.LOW,
            }
            severity = severity_map.get(severity_str, Severity.MEDIUM)

            # Map threat name to category
            category_map = {
                "DATA EXFILTRATION": ThreatCategory.DATA_EXFILTRATION,
                "CREDENTIAL THEFT": ThreatCategory.DATA_EXFILTRATION,
                "COMMAND INJECTION": ThreatCategory.COMMAND_INJECTION,
                "HIDDEN FUNCTIONALITY": ThreatCategory.POLICY_VIOLATION,
                "ALIGNMENT_MISMATCH": ThreatCategory.POLICY_VIOLATION,
            }
            category = category_map.get(threat_name, ThreatCategory.POLICY_VIOLATION)

            # Build description
            description_claims = analysis.get("description_claims", "")
            actual_behavior = analysis.get("actual_behavior", "")
            summary = analysis.get("summary", f"Alignment mismatch in {func_context.name}")

            if description_claims and actual_behavior:
                description = (
                    f"{summary}. Description claims: '{description_claims}'. Actual behavior: {actual_behavior}"
                )
            else:
                description = summary

            return Finding(
                id=self._generate_id(f"ALIGNMENT_{threat_name}", f"{file_path}:{func_context.name}"),
                rule_id=f"BEHAVIOR_ALIGNMENT_{threat_name.replace(' ', '_')}",
                category=category,
                severity=severity,
                title=f"Alignment mismatch: {threat_name} in {func_context.name}",
                description=description,
                file_path=file_path,
                line_number=func_context.line_number,
                remediation=f"Review function {func_context.name} and ensure documentation matches implementation",
                analyzer="behavioral",
                metadata={
                    "function_name": func_context.name,
                    "threat_name": threat_name,
                    "confidence": analysis.get("confidence"),
                    "security_implications": analysis.get("security_implications"),
                    "dataflow_evidence": analysis.get("dataflow_evidence"),
                    "classification": analysis.get("threat_vulnerability_classification"),
                },
            )

        except Exception as e:
            logger.warning("Failed to create alignment finding: %s", e)
            return None

    def _generate_findings_from_context(self, context: SkillScriptContext, skill: Skill) -> list[Finding]:
        """Generate security findings from extracted context."""
        findings = []

        # Check for exfiltration patterns
        if context.has_network and context.has_env_var_access:
            findings.append(
                Finding(
                    id=self._generate_id("ENV_VAR_EXFILTRATION", context.file_path),
                    rule_id="BEHAVIOR_ENV_VAR_EXFILTRATION",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=Severity.CRITICAL,
                    title="Environment variable access with network calls detected",
                    description=f"Script accesses environment variables and makes network calls in {context.file_path}",
                    file_path=context.file_path,
                    remediation="Remove environment variable harvesting or network transmission",
                    analyzer="behavioral",
                    metadata={
                        "has_network": context.has_network,
                        "has_env_access": context.has_env_var_access,
                        "suspicious_urls": context.suspicious_urls,
                    },
                )
            )

        # Check for credential file access
        if context.has_credential_access:
            findings.append(
                Finding(
                    id=self._generate_id("CREDENTIAL_FILE_ACCESS", context.file_path),
                    rule_id="BEHAVIOR_CREDENTIAL_FILE_ACCESS",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=Severity.HIGH,
                    title="Credential file access detected",
                    description=f"Script accesses credential files in {context.file_path}",
                    file_path=context.file_path,
                    remediation="Remove access to ~/.aws, ~/.ssh, or other credential files",
                    analyzer="behavioral",
                )
            )

        # Check for environment variable harvesting (even without immediate network)
        if context.has_env_var_access:
            findings.append(
                Finding(
                    id=self._generate_id("ENV_VAR_HARVESTING", context.file_path),
                    rule_id="BEHAVIOR_ENV_VAR_HARVESTING",
                    category=ThreatCategory.DATA_EXFILTRATION,
                    severity=Severity.MEDIUM,
                    title="Environment variable harvesting detected",
                    description=f"Script iterates through environment variables in {context.file_path}",
                    file_path=context.file_path,
                    remediation="Remove environment variable collection unless explicitly required and documented",
                    analyzer="behavioral",
                )
            )

        # Check for suspicious URLs
        if context.suspicious_urls:
            for url in context.suspicious_urls:
                findings.append(
                    Finding(
                        id=self._generate_id("SUSPICIOUS_URL", url),
                        rule_id="BEHAVIOR_SUSPICIOUS_URL",
                        category=ThreatCategory.DATA_EXFILTRATION,
                        severity=Severity.HIGH,
                        title=f"Suspicious URL detected: {url}",
                        description="Script contains suspicious URL that may be used for data exfiltration",
                        file_path=context.file_path,
                        remediation="Review URL and ensure it's legitimate and documented",
                        analyzer="behavioral",
                        metadata={"url": url},
                    )
                )

        # Check for eval/exec with subprocess
        if context.has_eval_exec and context.has_subprocess:
            findings.append(
                Finding(
                    id=self._generate_id("EVAL_SUBPROCESS", context.file_path),
                    rule_id="BEHAVIOR_EVAL_SUBPROCESS",
                    category=ThreatCategory.COMMAND_INJECTION,
                    severity=Severity.CRITICAL,
                    title="eval/exec combined with subprocess detected",
                    description=f"Dangerous combination of code execution and system commands in {context.file_path}",
                    file_path=context.file_path,
                    remediation="Remove eval/exec or use safer alternatives",
                    analyzer="behavioral",
                )
            )

        return findings

    def _generate_id(self, prefix: str, context: str) -> str:
        """Generate unique finding ID."""
        combined = f"{prefix}:{context}"
        hash_obj = hashlib.sha256(combined.encode())
        return f"{prefix}_{hash_obj.hexdigest()[:10]}"

    def _generate_findings_from_correlations(
        self, correlations: list[CrossFileCorrelation], skill: Skill
    ) -> list[Finding]:
        """Generate findings from cross-file correlations."""
        findings = []

        for correlation in correlations:
            # Map correlation type to severity
            severity_map = {
                "CRITICAL": Severity.CRITICAL,
                "HIGH": Severity.HIGH,
                "MEDIUM": Severity.MEDIUM,
            }
            severity = severity_map.get(correlation.severity, Severity.MEDIUM)

            # Map threat type to category
            category_map = {
                "exfiltration_chain": ThreatCategory.DATA_EXFILTRATION,
                "credential_network_separation": ThreatCategory.DATA_EXFILTRATION,
                "env_var_exfiltration": ThreatCategory.DATA_EXFILTRATION,
            }
            category = category_map.get(correlation.threat_type, ThreatCategory.POLICY_VIOLATION)

            # Create finding
            finding = Finding(
                id=self._generate_id(
                    f"CROSSFILE_{correlation.threat_type.upper()}", "_".join(correlation.files_involved)
                ),
                rule_id=f"BEHAVIOR_CROSSFILE_{correlation.threat_type.upper()}",
                category=category,
                severity=severity,
                title=f"Cross-file {correlation.threat_type.replace('_', ' ')}: {len(correlation.files_involved)} files",
                description=correlation.description,
                file_path=None,  # Multiple files involved
                remediation=f"Review data flow across files: {', '.join(correlation.files_involved)}",
                analyzer="behavioral",
                metadata={
                    "files_involved": correlation.files_involved,
                    "threat_type": correlation.threat_type,
                    "evidence": correlation.evidence,
                },
            )
            findings.append(finding)

        return findings
