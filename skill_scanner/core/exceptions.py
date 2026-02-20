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

"""Skill Scanner exceptions.

This module defines custom exceptions for Skill Scanner operations.
All exceptions inherit from SkillScannerError for easy catching.

Example:
    >>> from skill_scanner import Scanner
    >>> from skill_scanner.core.exceptions import SkillLoadError
    >>>
    >>> scanner = Scanner()
    >>>
    >>> try:
    ...     skill = scanner.load_skill("path/to/skill")
    ... except SkillLoadError as e:
    ...     print(f"Failed to load skill: {e}")
    ... except SkillAnalysisError as e:
    ...     print(f"Analysis failed: {e}")
"""


class SkillScannerError(Exception):
    """Base exception for all Skill Scanner errors."""

    pass


class SkillLoadError(SkillScannerError):
    """Raised when unable to load a skill package.

    This can indicate:
    - Missing SKILL.md file
    - Invalid YAML frontmatter
    - Corrupted skill package
    - File system errors
    """

    pass


class SkillAnalysisError(SkillScannerError):
    """Raised when skill analysis fails.

    This typically indicates:
    - Analyzer configuration errors
    - Internal analysis errors
    - Resource exhaustion during analysis
    """

    pass


class SkillValidationError(SkillScannerError):
    """Raised when skill validation fails.

    This indicates:
    - Invalid skill manifest
    - Missing required fields
    - Invalid skill structure
    """

    pass
