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
LLM-based analyzer for semantic security analysis.

Production analyzer with:
- LiteLLM for universal provider support (100+ models)
- Prompt injection protection with random delimiters
- Retry logic with exponential backoff
- AWS Bedrock support with IAM roles
- Async analysis for performance
- AITech taxonomy alignment
"""

import asyncio
from enum import Enum
from typing import Any

from ...core.models import Finding, Severity, Skill, ThreatCategory
from ...threats.threats import ThreatMapping
from .base import BaseAnalyzer
from .llm_prompt_builder import PromptBuilder
from .llm_provider_config import ProviderConfig
from .llm_request_handler import LLMRequestHandler
from .llm_response_parser import ResponseParser

# Export constants for backward compatibility with tests
try:
    from .llm_provider_config import GOOGLE_GENAI_AVAILABLE, LITELLM_AVAILABLE
except (ImportError, ModuleNotFoundError):
    LITELLM_AVAILABLE = False
    GOOGLE_GENAI_AVAILABLE = False


class LLMProvider(str, Enum):
    """Supported LLM providers via LiteLLM.
    - openai: OpenAI models (gpt-4o, gpt-4-turbo, etc.)
    - anthropic: Anthropic models (claude-3-5-sonnet, claude-3-opus, etc.)
    - azure-openai: Azure OpenAI Service
    - azure-ai: Azure AI Service (alternative)
    - aws-bedrock: AWS Bedrock models
    - gcp-vertex: Google Cloud Vertex AI
    - ollama: Local Ollama models
    - openrouter: OpenRouter API
    """

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure-openai"
    AZURE_AI = "azure-ai"
    AWS_BEDROCK = "aws-bedrock"
    GCP_VERTEX = "gcp-vertex"
    OLLAMA = "ollama"
    OPENROUTER = "openrouter"

    @classmethod
    def is_valid_provider(cls, provider: str) -> bool:
        """Check if a provider string is valid."""
        try:
            cls(provider.lower())
            return True
        except ValueError:
            return False


class SecurityError(Exception):
    """Custom exception for security violations in LLM prompts."""

    pass


class LLMAnalyzer(BaseAnalyzer):
    """
    Production LLM analyzer using LLM as a judge.

    Features:
    - Universal LLM support via LiteLLM (Anthropic, OpenAI, Azure, Bedrock)
    - Prompt injection protection with random delimiters
    - Retry logic with exponential backoff
    - Async analysis for better performance
    - AWS Bedrock credential support

    Example:
        >>> analyzer = LLMAnalyzer(
        ...     model=os.getenv("SKILL_SCANNER_LLM_MODEL", "claude-3-5-sonnet-20241022"),
        ...     api_key=os.getenv("SKILL_SCANNER_LLM_API_KEY")
        ... )
        >>> findings = analyzer.analyze(skill)
    """

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        max_tokens: int = 4000,
        temperature: float = 0.0,
        max_retries: int = 3,
        rate_limit_delay: float = 2.0,
        timeout: int = 120,
        # Azure-specific
        base_url: str | None = None,
        api_version: str | None = None,
        # AWS Bedrock-specific
        aws_region: str | None = None,
        aws_profile: str | None = None,
        aws_session_token: str | None = None,
        # Provider selection (can be enum or string)
        provider: str | None = None,
    ):
        """
        Initialize enhanced LLM analyzer.

        Args:
            model: Model identifier (e.g., "claude-3-5-sonnet-20241022", "gpt-4o", "bedrock/anthropic.claude-v2")
            api_key: API key (if None, reads from environment)
            max_tokens: Maximum tokens for response
            temperature: Sampling temperature (0.0 for deterministic)
            max_retries: Max retry attempts on rate limits
            rate_limit_delay: Base delay for exponential backoff
            timeout: Request timeout in seconds
            base_url: Custom base URL (for Azure)
            api_version: API version (for Azure)
            aws_region: AWS region (for Bedrock)
            aws_profile: AWS profile name (for Bedrock)
            aws_session_token: AWS session token (for Bedrock)
            provider: LLM provider name (e.g., "openai", "anthropic", "aws-bedrock", etc.)
                Can be enum or string (e.g., "openai", "anthropic", "aws-bedrock")
        """
        super().__init__("llm_analyzer")

        # Handle provider selection: if provider is specified, map to default model
        if provider is not None and model is None:
            # Normalize provider string (handle both enum and string inputs)
            if isinstance(provider, LLMProvider):
                provider_str = provider.value
            else:
                provider_str = str(provider).lower().strip()

            # Validate provider if it's a string
            if not isinstance(provider, LLMProvider) and not LLMProvider.is_valid_provider(provider_str):
                raise ValueError(
                    f"Invalid provider '{provider}'. Valid providers: {', '.join([p.value for p in LLMProvider])}"
                )

            # Map provider to default model
            model_mapping = {
                "openai": "gpt-4o",
                "anthropic": "claude-3-5-sonnet-20241022",
                "azure-openai": "azure/gpt-4o",
                "azure-ai": "azure/gpt-4",
                "aws-bedrock": "bedrock/anthropic.claude-v2",
                "gcp-vertex": "vertex_ai/gemini-1.5-pro",
                "ollama": "ollama/llama2",
                "openrouter": "openrouter/openai/gpt-4",
            }
            model = model_mapping.get(provider_str, "claude-3-5-sonnet-20241022")
        elif model is None:
            # Default to anthropic if nothing specified
            model = "claude-3-5-sonnet-20241022"

        # Initialize components
        self.provider_config = ProviderConfig(
            model=model,
            api_key=api_key,
            base_url=base_url,
            api_version=api_version,
            aws_region=aws_region,
            aws_profile=aws_profile,
            aws_session_token=aws_session_token,
        )
        self.provider_config.validate()

        self.request_handler = LLMRequestHandler(
            provider_config=self.provider_config,
            max_tokens=max_tokens,
            temperature=temperature,
            max_retries=max_retries,
            rate_limit_delay=rate_limit_delay,
            timeout=timeout,
        )

        self.prompt_builder = PromptBuilder()
        self.response_parser = ResponseParser()

        # Expose commonly accessed attributes for backward compatibility
        self.model = self.provider_config.model
        self.api_key = self.provider_config.api_key
        self.is_bedrock = self.provider_config.is_bedrock
        self.is_gemini = self.provider_config.is_gemini
        self.aws_region = self.provider_config.aws_region
        self.aws_profile = self.provider_config.aws_profile
        self.aws_session_token = self.provider_config.aws_session_token
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.max_retries = max_retries
        self.rate_limit_delay = rate_limit_delay
        self.timeout = timeout

    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze skill using LLM (sync wrapper for async method).

        Args:
            skill: Skill to analyze

        Returns:
            List of security findings
        """
        # Run async analysis in event loop
        return asyncio.run(self.analyze_async(skill))

    async def analyze_async(self, skill: Skill) -> list[Finding]:
        """
        Analyze skill using LLM (async).

        Args:
            skill: Skill to analyze

        Returns:
            List of security findings
        """
        findings = []

        try:
            # Format all skill components
            manifest_text = self.prompt_builder.format_manifest(skill.manifest)
            code_files_text = self.prompt_builder.format_code_files(skill)
            referenced_files_text = self.prompt_builder.format_referenced_files(skill)

            # Create protected prompt
            prompt, injection_detected = self.prompt_builder.build_threat_analysis_prompt(
                skill.name,
                skill.description,
                manifest_text,
                skill.instruction_body[:3000],
                code_files_text,
                referenced_files_text,
            )

            # If injection detected, create immediate finding
            if injection_detected:
                findings.append(
                    Finding(
                        id=f"prompt_injection_{skill.name}",
                        rule_id="LLM_PROMPT_INJECTION_DETECTED",
                        category=ThreatCategory.PROMPT_INJECTION,
                        severity=Severity.HIGH,
                        title="Prompt injection attack detected",
                        description="Skill content contains delimiter injection attempt",
                        file_path="SKILL.md",
                        remediation="Remove malicious delimiter tags from skill content",
                        analyzer="llm",
                    )
                )
                return findings

            # Query LLM with retry logic
            # System message includes context about AITech taxonomy for structured outputs
            messages = [
                {
                    "role": "system",
                    "content": """You are a security expert analyzing agent skills. Follow the analysis framework provided.

When selecting AITech codes for findings, use these mappings:
- AITech-1.1: Direct prompt injection in SKILL.md (jailbreak, instruction override)
- AITech-1.2: Indirect prompt injection - instruction manipulation (embedding malicious instructions in external sources)
- AITech-4.3: Protocol manipulation - capability inflation (skill discovery abuse, keyword baiting, over-broad claims)
- AITech-8.2: Data exfiltration/exposure (unauthorized access, credential theft, hardcoded secrets)
- AITech-9.1: Model/agentic manipulation (command injection, code injection, SQL injection, obfuscation)
- AITech-12.1: Tool exploitation (tool poisoning, shadowing, unauthorized use)
- AITech-13.1: Disruption of Availability (resource abuse, DoS, infinite loops) - AISubtech-13.1.1: Compute Exhaustion
- AITech-15.1: Harmful/misleading content (deceptive content, misinformation)

The structured output schema will enforce these exact codes.""",
                },
                {"role": "user", "content": prompt},
            ]

            response_content = await self.request_handler.make_request(
                messages, context=f"threat analysis for {skill.name}"
            )

            # Parse response
            analysis_result = self.response_parser.parse(response_content)

            # Convert to findings
            findings = self._convert_to_findings(analysis_result, skill)

        except Exception as e:
            print(f"LLM analysis failed for {skill.name}: {e}")
            # Return empty findings - don't pollute results with errors
            return []

        return findings

    def _convert_to_findings(self, analysis_result: dict[str, Any], skill: Skill) -> list[Finding]:
        """Convert LLM analysis results to Finding objects."""
        findings = []

        for idx, llm_finding in enumerate(analysis_result.get("findings", [])):
            try:
                # Parse severity
                severity_str = llm_finding.get("severity", "MEDIUM").upper()
                severity = Severity(severity_str)

                # Parse AITech code (required by structured output)
                aitech_code = llm_finding.get("aitech")
                if not aitech_code:
                    print("Warning: Missing AITech code in LLM finding, skipping")
                    continue

                # Get threat mapping from AITech code
                threat_mapping = ThreatMapping.get_threat_mapping_by_aitech(aitech_code)

                # Map AITech code to ThreatCategory enum
                category_str = ThreatMapping.get_threat_category_from_aitech(aitech_code)
                try:
                    category = ThreatCategory(category_str)
                except ValueError:
                    print(
                        f"Warning: Invalid ThreatCategory '{category_str}' for AITech '{aitech_code}', using policy_violation"
                    )
                    category = ThreatCategory.POLICY_VIOLATION

                # Filter false positives: Suppress findings about reading internal files
                # Skills reading their own files is normal and expected behavior
                title = llm_finding.get("title", "")
                description = llm_finding.get("description", "")

                # Check if this is about reading internal/referenced files
                is_internal_file_reading = (
                    aitech_code == "AITech-1.2"  # Indirect prompt injection
                    and category == ThreatCategory.PROMPT_INJECTION
                    and (
                        "local files" in description.lower()
                        or "referenced files" in description.lower()
                        or "external guideline files" in description.lower()
                        or "unvalidated local files" in description.lower()
                        or "transitive trust" in description.lower()
                        and "external" not in description.lower()
                    )
                    and
                    # Check if referenced files are internal (within skill package)
                    all(self._is_internal_file(skill, ref_file) for ref_file in skill.referenced_files)
                )

                if is_internal_file_reading:
                    # Suppress false positive - reading internal files is normal
                    continue

                # Lower severity for missing tool declarations (not a security issue)
                if category == ThreatCategory.UNAUTHORIZED_TOOL_USE and (
                    "missing tool" in title.lower()
                    or "undeclared tool" in title.lower()
                    or "not specified" in description.lower()
                ):
                    severity = Severity.LOW  # Downgrade from MEDIUM/HIGH to LOW

                # Parse location
                location = llm_finding.get("location", "")
                file_path = None
                line_number = None

                if ":" in location:
                    parts = location.split(":")
                    file_path = parts[0]
                    if len(parts) > 1 and parts[1].isdigit():
                        line_number = int(parts[1])

                # Get AISubtech code if provided
                aisubtech_code = llm_finding.get("aisubtech")

                # Create finding with AITech alignment
                finding = Finding(
                    id=f"llm_finding_{skill.name}_{idx}",
                    rule_id=f"LLM_{category_str.upper()}",
                    category=category,
                    severity=severity,
                    title=title,
                    description=description,
                    file_path=file_path,
                    line_number=line_number,
                    snippet=llm_finding.get("evidence", ""),
                    remediation=llm_finding.get("remediation", ""),
                    analyzer="llm",
                    metadata={
                        "model": self.model,
                        "overall_assessment": analysis_result.get("overall_assessment", ""),
                        "primary_threats": analysis_result.get("primary_threats", []),
                        "aitech": aitech_code,
                        "aitech_name": threat_mapping.get("aitech_name"),
                        "aisubtech": aisubtech_code or threat_mapping.get("aisubtech"),
                        "aisubtech_name": threat_mapping.get("aisubtech_name") if not aisubtech_code else None,
                        "scanner_category": threat_mapping.get("scanner_category"),
                    },
                )

                findings.append(finding)

            except (ValueError, KeyError) as e:
                print(f"Warning: Failed to parse LLM finding: {e}")
                continue

        return findings

    def _is_internal_file(self, skill: Skill, file_path: str) -> bool:
        """Check if a file path is internal to the skill package."""
        from pathlib import Path

        skill_dir = Path(skill.directory)
        file_path_obj = Path(file_path)

        # If it's an absolute path, check if it's within skill directory
        if file_path_obj.is_absolute():
            try:
                return skill_dir in file_path_obj.parents or file_path_obj.is_relative_to(skill_dir)
            except AttributeError:
                # Python < 3.9 compatibility
                try:
                    return skill_dir.resolve() in file_path_obj.resolve().parents
                except OSError:
                    return False

        # Relative path - check if it exists within skill directory
        full_path = skill_dir / file_path
        return full_path.exists() and full_path.is_relative_to(skill_dir)
