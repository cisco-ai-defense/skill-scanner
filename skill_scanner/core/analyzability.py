# Copyright 2026 Cisco Systems, Inc. and its affiliates
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
Fail-closed analyzability scoring.

Quantifies what percentage of a skill's content the scanner could actually
inspect. Files that resist analysis (encrypted, obfuscated, compiled bytecode
without source, unknown binary formats) lower the score.

Score = (analyzed_weight / total_weight) * 100

A low score doesn't mean the skill is malicious, but it means we can't
confidently say it's safe.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .models import Skill, SkillFile

if TYPE_CHECKING:
    from .scan_policy import ScanPolicy


@dataclass
class FileAnalyzability:
    """Analyzability assessment for a single file."""

    relative_path: str
    file_type: str
    size_bytes: int
    is_analyzable: bool
    analysis_methods: list[str] = field(default_factory=list)
    skip_reason: str | None = None
    weight: float = 1.0  # Larger/more important files have higher weight


@dataclass
class AnalyzabilityReport:
    """Overall analyzability assessment for a skill."""

    score: float = 100.0  # 0-100
    total_files: int = 0
    analyzed_files: int = 0
    unanalyzable_files: int = 0
    total_weight: float = 0.0
    analyzed_weight: float = 0.0
    file_details: list[FileAnalyzability] = field(default_factory=list)
    risk_level: str = "LOW"  # LOW, MEDIUM, HIGH based on score

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "score": round(self.score, 1),
            "total_files": self.total_files,
            "analyzed_files": self.analyzed_files,
            "unanalyzable_files": self.unanalyzable_files,
            "risk_level": self.risk_level,
            "unanalyzable_file_list": [
                {"path": fd.relative_path, "reason": fd.skip_reason} for fd in self.file_details if not fd.is_analyzable
            ],
        }


# File types we can fully analyze
_ANALYZABLE_TYPES = {"python", "bash", "markdown", "other"}

# Extensions we can analyze as text
_TEXT_EXTENSIONS = {
    ".py",
    ".sh",
    ".bash",
    ".rb",
    ".pl",
    ".js",
    ".ts",
    ".php",
    ".md",
    ".markdown",
    ".txt",
    ".rst",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".html",
    ".css",
    ".toml",
    ".cfg",
    ".ini",
    ".conf",
    ".csv",
    ".env",
    ".gitignore",
    ".dockerignore",
}

# Extensions that are inert (viewable but no executable concern)
_INERT_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".bmp",
    ".webp",
    ".ico",
    ".tiff",
    ".tif",
    ".svg",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
    ".eot",
}


def compute_analyzability(skill: Skill, *, policy: ScanPolicy | None = None) -> AnalyzabilityReport:
    """
    Compute the analyzability score for a skill.

    The score is a weighted average where file size determines weight.
    Larger files that can't be analyzed have more impact on the score.

    Args:
        skill: The skill to score.
        policy: Optional scan policy.  When provided, the risk-level
            thresholds come from ``policy.analysis_thresholds``.

    Returns:
        AnalyzabilityReport with score and details.
    """
    report = AnalyzabilityReport()

    if not skill.files:
        report.score = 100.0
        report.risk_level = "LOW"
        return report

    for sf in skill.files:
        # Compute weight based on size (min 1, log-scaled)
        weight = max(1.0, math.log2(max(sf.size_bytes, 1)))

        fa = FileAnalyzability(
            relative_path=sf.relative_path,
            file_type=sf.file_type,
            size_bytes=sf.size_bytes,
            is_analyzable=False,
            weight=weight,
        )

        ext = sf.path.suffix.lower()

        if sf.file_type in _ANALYZABLE_TYPES:
            content = sf.read_content()
            if content:
                fa.is_analyzable = True
                fa.analysis_methods = _get_analysis_methods(sf)
            else:
                fa.is_analyzable = False
                fa.skip_reason = "File exists but content is empty or unreadable"

        elif ext in _INERT_EXTENSIONS:
            # Inert files are "analyzable" (nothing to find)
            fa.is_analyzable = True
            fa.analysis_methods = ["magic_byte_check", "extension_validation"]

        elif ext in (".pyc", ".pyo"):
            # Bytecode - analyzable if we have matching source
            has_source = any(
                f.path.stem.split(".cpython-")[0] == sf.path.stem.split(".cpython-")[0] and f.path.suffix == ".py"
                for f in skill.files
            )
            if has_source:
                fa.is_analyzable = True
                fa.analysis_methods = ["bytecode_integrity_check"]
            else:
                fa.is_analyzable = False
                fa.skip_reason = "Bytecode without matching source - cannot verify"

        elif sf.file_type == "binary":
            fa.is_analyzable = False
            fa.skip_reason = f"Binary file ({ext}) - cannot inspect content"

        else:
            fa.is_analyzable = False
            fa.skip_reason = f"Unknown file type ({ext})"

        report.file_details.append(fa)
        report.total_files += 1
        report.total_weight += weight

        if fa.is_analyzable:
            report.analyzed_files += 1
            report.analyzed_weight += weight
        else:
            report.unanalyzable_files += 1

    # Compute score
    if report.total_weight > 0:
        report.score = (report.analyzed_weight / report.total_weight) * 100.0
    else:
        report.score = 100.0

    # Determine risk level (use policy thresholds when available)
    low_threshold = 90
    medium_threshold = 70
    if policy is not None:
        low_threshold = policy.analysis_thresholds.analyzability_low_risk
        medium_threshold = policy.analysis_thresholds.analyzability_medium_risk

    if report.score >= low_threshold:
        report.risk_level = "LOW"
    elif report.score >= medium_threshold:
        report.risk_level = "MEDIUM"
    else:
        report.risk_level = "HIGH"

    return report


def _get_analysis_methods(sf: SkillFile) -> list[str]:
    """Determine which analysis methods apply to a file."""
    methods = []
    ext = sf.path.suffix.lower()

    if sf.file_type == "python":
        methods.extend(["static_regex", "yara_scan", "behavioral_ast"])
    elif sf.file_type == "bash":
        methods.extend(["static_regex", "yara_scan", "command_safety"])
    elif sf.file_type == "markdown":
        methods.extend(["static_regex", "yara_scan", "prompt_analysis"])
    else:
        methods.append("yara_scan")

    if ext in (".json", ".yaml", ".yml", ".toml"):
        methods.append("config_analysis")

    return methods
