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
Skill Scanner - Security scanner for agent skills packages.
"""

try:
    from ._version import __version__
except ImportError:
    __version__ = "0.0.0+unknown"

__author__ = "Cisco Systems, Inc."

# Core exports
from .config.config import Config
from .config.constants import SkillScannerConstants
from .core.loader import SkillLoader, load_skill
from .core.models import Finding, Report, ScanResult, Severity, Skill, ThreatCategory
from .core.scanner import SkillScanner, scan_directory, scan_skill

__all__ = [
    "SkillScanner",
    "scan_skill",
    "scan_directory",
    "Skill",
    "Finding",
    "ScanResult",
    "Report",
    "Severity",
    "ThreatCategory",
    "SkillLoader",
    "load_skill",
    "Config",
    "SkillScannerConstants",
]
