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
Centralized analyzer construction.

Every entry point (CLI, API, pre-commit hook, eval runner, SkillScanner
fallback) **must** build analyzers through the helpers in this module so that:

* All core analyzers receive the active ``ScanPolicy``.
* The ``policy.analyzers.*`` toggles are respected everywhere.
* Adding or removing a core analyzer only requires a change here.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from .analyzers.base import BaseAnalyzer
from .analyzers.bytecode_analyzer import BytecodeAnalyzer
from .analyzers.pipeline_analyzer import PipelineAnalyzer
from .analyzers.static import StaticAnalyzer
from .scan_policy import ScanPolicy

logger = logging.getLogger(__name__)


def build_core_analyzers(
    policy: ScanPolicy,
    *,
    custom_yara_rules_path: str | Path | None = None,
) -> list[BaseAnalyzer]:
    """Build the three core analyzers, respecting ``policy.analyzers`` toggles.

    This is the **single source of truth** for which core analyzers exist
    and how they are configured.  ``SkillScanner.__init__``, the CLI, the
    API router, the pre-commit hook, and the eval runner all delegate here.

    Args:
        policy: The active scan policy.
        custom_yara_rules_path: Optional path to a directory of custom YARA
            rule files (``.yara``).  Forwarded to :class:`StaticAnalyzer`.

    Returns:
        A list of core analyzer instances with *policy* attached.
    """
    analyzers: list[BaseAnalyzer] = []

    if policy.analyzers.static:
        analyzers.append(StaticAnalyzer(custom_yara_rules_path=custom_yara_rules_path, policy=policy))
    if policy.analyzers.bytecode:
        analyzers.append(BytecodeAnalyzer(policy=policy))
    if policy.analyzers.pipeline:
        analyzers.append(PipelineAnalyzer(policy=policy))

    return analyzers


def build_analyzers(
    policy: ScanPolicy,
    *,
    custom_yara_rules_path: str | Path | None = None,
    use_behavioral: bool = False,
    use_llm: bool = False,
    llm_model: str | None = None,
    llm_api_key: str | None = None,
    llm_base_url: str | None = None,
    llm_api_version: str | None = None,
    llm_provider: str | None = None,
    use_virustotal: bool = False,
    vt_api_key: str | None = None,
    vt_upload_files: bool = False,
    use_aidefense: bool = False,
    aidefense_api_key: str | None = None,
    aidefense_api_url: str | None = None,
    use_trigger: bool = False,
    llm_consensus_runs: int = 1,
) -> list[BaseAnalyzer]:
    """Build the full analyzer list (core + optional).

    Core analyzers are toggled by ``policy.analyzers.*``.
    Optional analyzers are toggled by explicit boolean flags.

    This function is designed to be called from the CLI, API, pre-commit
    hook, and eval scripts so that every entry point uses the exact same
    construction logic.

    Returns:
        A list of analyzer instances ready to be passed to
        :class:`SkillScanner`.
    """
    analyzers = build_core_analyzers(policy, custom_yara_rules_path=custom_yara_rules_path)

    # -- Optional analyzers (flag-driven) -----------------------------------

    if use_behavioral:
        try:
            from .analyzers.behavioral_analyzer import BehavioralAnalyzer

            analyzers.append(BehavioralAnalyzer())
        except (ImportError, Exception) as exc:
            logger.warning("Could not initialise behavioral analyzer: %s", exc)

    if use_llm:
        try:
            from .analyzers.llm_analyzer import LLMAnalyzer

            model = llm_model or os.getenv("SKILL_SCANNER_LLM_MODEL") or "claude-3-5-sonnet-20241022"
            key = llm_api_key or os.getenv("SKILL_SCANNER_LLM_API_KEY")
            base_url = llm_base_url or os.getenv("SKILL_SCANNER_LLM_BASE_URL")
            api_version = llm_api_version or os.getenv("SKILL_SCANNER_LLM_API_VERSION")
            if llm_provider and not llm_model and not os.getenv("SKILL_SCANNER_LLM_MODEL"):
                llm = LLMAnalyzer(provider=llm_provider, policy=policy)
            else:
                llm = LLMAnalyzer(model=model, api_key=key, base_url=base_url, api_version=api_version, policy=policy)
            if llm_consensus_runs > 1:
                llm.consensus_runs = llm_consensus_runs
            analyzers.append(llm)
        except (ImportError, Exception) as exc:
            logger.warning("Could not initialise LLM analyzer: %s", exc)

    if use_virustotal:
        try:
            from .analyzers.virustotal_analyzer import VirusTotalAnalyzer

            key = vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
            if not key:
                logger.warning("VirusTotal requested but no API key.  Set VIRUSTOTAL_API_KEY or pass vt_api_key")
            else:
                analyzers.append(VirusTotalAnalyzer(api_key=key, enabled=True, upload_files=vt_upload_files))
        except (ImportError, Exception) as exc:
            logger.warning("Could not initialise VirusTotal analyzer: %s", exc)

    if use_aidefense:
        try:
            from .analyzers.aidefense_analyzer import AIDefenseAnalyzer

            key = aidefense_api_key or os.getenv("AI_DEFENSE_API_KEY")
            url = aidefense_api_url or os.getenv("AI_DEFENSE_API_URL")
            if not key:
                logger.warning("AI Defense requested but no API key.  Set AI_DEFENSE_API_KEY or pass aidefense_api_key")
            else:
                analyzers.append(AIDefenseAnalyzer(api_key=key, api_url=url))
        except (ImportError, Exception) as exc:
            logger.warning("Could not initialise AI Defense analyzer: %s", exc)

    if use_trigger:
        try:
            from .analyzers.trigger_analyzer import TriggerAnalyzer

            analyzers.append(TriggerAnalyzer())
        except (ImportError, Exception) as exc:
            logger.warning("Could not initialise Trigger analyzer: %s", exc)

    return analyzers
