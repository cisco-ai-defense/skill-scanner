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
Cross-file correlation analyzer for detecting multi-step attacks.

Tracks how data flows across multiple Python files in a skill package.
"""

from dataclasses import dataclass, field
from typing import Any

from ..context_extractor import SkillScriptContext


@dataclass
class CrossFileCorrelation:
    """Represents a correlated threat across multiple files."""

    threat_type: str  # "exfiltration_chain", "collection_pipeline"
    severity: str
    files_involved: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    description: str = ""


class CrossFileAnalyzer:
    """
    Analyzes correlations across multiple files in a skill package.

    Detects multi-step attacks like:
    1. File A: Collects credentials/env vars
    2. File B: Encodes data
    3. File C: Sends to network
    """

    def __init__(self):
        self.file_contexts: dict[str, SkillScriptContext] = {}
        self.correlations: list[CrossFileCorrelation] = []

    def add_file_context(self, file_name: str, context: SkillScriptContext):
        """Add a file's context for correlation analysis."""
        self.file_contexts[file_name] = context

    def analyze_correlations(self) -> list[CrossFileCorrelation]:
        """
        Analyze all files together to find multi-step attack patterns.

        Returns:
            List of detected cross-file correlations
        """
        self.correlations = []

        # Pattern 1: Collection → Encoding → Exfiltration chain
        self._detect_exfiltration_chain()

        # Pattern 2: Credential access in one file + Network in another
        self._detect_credential_network_separation()

        # Pattern 3: Environment harvesting + Network transmission
        self._detect_env_var_exfiltration_chain()

        return self.correlations

    def _detect_exfiltration_chain(self):
        """
        Detect Collection → Encoding → Network chain across files.

        Pattern:
        - File A: has_env_var_access or has_credential_access
        - File B: has encoding (base64, json)
        - File C: has_network
        """
        has_collection = []
        has_encoding = []
        has_network = []

        for file_name, context in self.file_contexts.items():
            if context.has_env_var_access or context.has_credential_access:
                has_collection.append(file_name)

            # Check for encoding operations
            if any("base64" in call or "encode" in call for call in context.all_function_calls):
                has_encoding.append(file_name)

            if context.has_network:
                has_network.append(file_name)

        # If we have all three stages across different files
        if has_collection and has_network and len(self.file_contexts) > 1:
            correlation = CrossFileCorrelation(
                threat_type="exfiltration_chain",
                severity="CRITICAL",
                files_involved=list(set(has_collection + has_encoding + has_network)),
                evidence={
                    "collection_files": has_collection,
                    "encoding_files": has_encoding,
                    "network_files": has_network,
                },
                description=f"Multi-file exfiltration chain detected: {', '.join(has_collection)} collect data → {', '.join(has_encoding) if has_encoding else 'encode'} → {', '.join(has_network)} transmit to network",
            )
            self.correlations.append(correlation)

    def _detect_credential_network_separation(self):
        """
        Detect credential access separated from network calls.

        This is a common evasion technique: put credential access in one file
        and network transmission in another to avoid simple pattern detection.
        """
        credential_files = []
        network_files = []

        for file_name, context in self.file_contexts.items():
            if context.has_credential_access:
                credential_files.append(file_name)
            if context.has_network:
                network_files.append(file_name)

        # If credentials and network are in DIFFERENT files
        if credential_files and network_files and not set(credential_files) & set(network_files):
            correlation = CrossFileCorrelation(
                threat_type="credential_network_separation",
                severity="HIGH",
                files_involved=credential_files + network_files,
                evidence={
                    "credential_files": credential_files,
                    "network_files": network_files,
                },
                description=f"Credential access ({', '.join(credential_files)}) separated from network transmission ({', '.join(network_files)}) - possible evasion technique",
            )
            self.correlations.append(correlation)

    def _detect_env_var_exfiltration_chain(self):
        """
        Detect environment variable harvesting + network transmission across files.

        Pattern:
        - File A: Iterates os.environ collecting secrets
        - File B: Has network calls
        - Together: Likely exfiltrating environment variables
        """
        env_var_files = []
        network_files = []

        for file_name, context in self.file_contexts.items():
            if context.has_env_var_access:
                env_var_files.append(file_name)
            if context.has_network:
                network_files.append(file_name)

        # If env vars and network exist (even in same or different files)
        if env_var_files and network_files:
            # Check if they're in different files (more sophisticated)
            if not set(env_var_files) & set(network_files):
                severity = "CRITICAL"
                desc = f"Environment variable harvesting ({', '.join(env_var_files)}) separated from network transmission ({', '.join(network_files)}) across files"
            else:
                # Same file - less sophisticated but still dangerous
                severity = "CRITICAL"
                desc = f"Environment variable access with network calls in {', '.join(env_var_files)}"

            correlation = CrossFileCorrelation(
                threat_type="env_var_exfiltration",
                severity=severity,
                files_involved=list(set(env_var_files + network_files)),
                evidence={
                    "env_var_files": env_var_files,
                    "network_files": network_files,
                },
                description=desc,
            )
            self.correlations.append(correlation)

    def get_critical_correlations(self) -> list[CrossFileCorrelation]:
        """Get only CRITICAL severity correlations."""
        return [c for c in self.correlations if c.severity == "CRITICAL"]
