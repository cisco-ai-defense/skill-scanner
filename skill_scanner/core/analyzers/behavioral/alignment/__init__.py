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

"""Alignment Verification Layer for Semantic Analysis.

This package provides the alignment verification layer that checks if skill
descriptions and manifest claims accurately match their actual implementation behavior.

Components:
- AlignmentOrchestrator: Main orchestrator coordinating alignment verification
- AlignmentPromptBuilder: Constructs comprehensive prompts with evidence
- AlignmentLLMClient: Handles LLM API interaction for verification
- AlignmentResponseValidator: Validates and parses LLM responses
- ThreatVulnerabilityClassifier: Classifies findings as threats or vulnerabilities

All components use the 'alignment_' prefix to indicate they are part of
the semantic alignment verification layer.
"""

from .alignment_llm_client import AlignmentLLMClient
from .alignment_orchestrator import AlignmentOrchestrator
from .alignment_prompt_builder import AlignmentPromptBuilder
from .alignment_response_validator import AlignmentResponseValidator
from .threat_vulnerability_classifier import ThreatVulnerabilityClassifier

__all__ = [
    "AlignmentOrchestrator",
    "AlignmentPromptBuilder",
    "AlignmentLLMClient",
    "AlignmentResponseValidator",
    "ThreatVulnerabilityClassifier",
]
