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
Base analyzer interface for skill security scanning.
"""

from abc import ABC, abstractmethod

from ..models import Finding, Skill


class BaseAnalyzer(ABC):
    """Abstract base class for all security analyzers."""

    def __init__(self, name: str):
        """
        Initialize analyzer.

        Args:
            name: Name of the analyzer
        """
        self.name = name

    @abstractmethod
    def analyze(self, skill: Skill) -> list[Finding]:
        """
        Analyze a skill for security issues.

        Args:
            skill: The skill to analyze

        Returns:
            List of security findings
        """
        pass

    def get_name(self) -> str:
        """Get the analyzer name."""
        return self.name
