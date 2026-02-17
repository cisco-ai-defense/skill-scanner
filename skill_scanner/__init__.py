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


def __getattr__(name: str):
    """Lazy-load public API symbols on first access.

    This avoids heavy imports (YARA, Magika, AST analysis, etc.) when the
    package is merely *imported* — e.g. ``python -m skill_scanner.cli.cli``
    or ``python -m skill_scanner.hooks.pre_commit`` — which previously
    triggered ``runpy`` warnings from eager top-level imports.
    """
    _lazy_map = {
        "Config": (".config.config", "Config"),
        "SkillScannerConstants": (".config.constants", "SkillScannerConstants"),
        "SkillLoader": (".core.loader", "SkillLoader"),
        "load_skill": (".core.loader", "load_skill"),
        "Finding": (".core.models", "Finding"),
        "Report": (".core.models", "Report"),
        "ScanResult": (".core.models", "ScanResult"),
        "Severity": (".core.models", "Severity"),
        "Skill": (".core.models", "Skill"),
        "ThreatCategory": (".core.models", "ThreatCategory"),
        "SkillScanner": (".core.scanner", "SkillScanner"),
        "scan_skill": (".core.scanner", "scan_skill"),
        "scan_directory": (".core.scanner", "scan_directory"),
        "SkillValidator": (".core.strict_structure", "SkillValidator"),
        "validate_skill": (".core.strict_structure", "validate_skill"),
    }
    if name in _lazy_map:
        module_path, attr = _lazy_map[name]
        import importlib

        mod = importlib.import_module(module_path, __package__)
        val = getattr(mod, attr)
        # Cache on the module so __getattr__ is only called once per symbol
        globals()[name] = val
        return val
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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
    "SkillValidator",
    "validate_skill",
    "Config",
    "SkillScannerConstants",
]
