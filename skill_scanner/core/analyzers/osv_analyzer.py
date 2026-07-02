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

"""OSV dependency vulnerability analyzer.

Checks a skill's pinned Python dependencies against the free, open
`OSV.dev <https://osv.dev>`_ vulnerability database. Opt-in (like the
VirusTotal analyzer), requires no API key, and fails open on network errors so
it never blocks a scan.

Only dependencies pinned to an exact version (``package==1.2.3``) are queried:
an open range (``package>=1``) has no single version to look up, and that risk
is already surfaced by the unpinned-dependency static check.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from ..models import Finding, Severity, ThreatCategory
from .base import BaseAnalyzer

if TYPE_CHECKING:
    from ..models import Skill
    from ..scan_policy import ScanPolicy

logger = logging.getLogger(__name__)

# name[extras]==version  (exact pins only; markers/comments stripped beforehand)
_PINNED_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*(?P<version>[A-Za-z0-9][A-Za-z0-9.\-+!]*)\s*$"
)


class OSVAnalyzer(BaseAnalyzer):
    """Query pinned dependencies against the OSV.dev vulnerability database."""

    QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

    def __init__(
        self,
        enabled: bool = True,
        ecosystem: str = "PyPI",
        timeout: float = 10.0,
        policy: ScanPolicy | None = None,
    ):
        super().__init__("osv_analyzer", policy=policy)
        self.enabled = enabled
        self.ecosystem = ecosystem
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def analyze(self, skill: Skill) -> list[Finding]:
        if not self.enabled:
            return []

        dependencies = self._collect_pinned_dependencies(skill)
        if not dependencies:
            return []

        try:
            vuln_lists = self._query_osv_batch([(name, version) for name, version, _, _ in dependencies])
        except (httpx.HTTPError, ValueError) as exc:
            # Fail open: OSV is an optional signal and must never break a scan.
            logger.warning("OSV query failed, skipping vulnerability analysis: %s", exc)
            return []

        findings: list[Finding] = []
        for (name, version, source, line_number), vulns in zip(dependencies, vuln_lists, strict=False):
            if not vulns:
                continue
            findings.append(self._create_finding(name, version, vulns, source, line_number))
        return findings

    def _collect_pinned_dependencies(self, skill: Skill) -> list[tuple[str, str, str, int | None]]:
        """Return ``(name, version, source_path, line_number)`` for exact pins.

        Sources: ``requirements*.txt`` files and a manifest ``metadata``
        ``dependencies`` list.
        """
        collected: list[tuple[str, str, str, int | None]] = []

        for skill_file in skill.files:
            file_name = Path(skill_file.relative_path).name.lower()
            if not (file_name.startswith("requirements") and file_name.endswith(".txt")):
                continue
            for line_number, raw in enumerate(skill_file.read_content().splitlines(), start=1):
                parsed = self._parse_pinned(raw)
                if parsed is not None:
                    collected.append((parsed[0], parsed[1], skill_file.relative_path, line_number))

        metadata = skill.manifest.metadata
        if isinstance(metadata, dict):
            declared = metadata.get("dependencies")
            if isinstance(declared, list):
                for declared_dep in declared:
                    parsed = self._parse_pinned(str(declared_dep))
                    if parsed is not None:
                        collected.append((parsed[0], parsed[1], str(skill.skill_md_path), None))

        return collected

    @staticmethod
    def _parse_pinned(raw: str) -> tuple[str, str] | None:
        """Extract ``(name, version)`` from an exactly pinned requirement line."""
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            return None
        line = line.split(";", 1)[0].strip()
        # Drop trailing pip hash options that may share the line.
        line = line.split("--hash", 1)[0].strip()
        match = _PINNED_RE.match(line)
        if not match:
            return None
        return match.group("name"), match.group("version")

    def _query_osv_batch(self, packages: list[tuple[str, str]]) -> list[list[dict]]:
        """Query OSV querybatch; return a per-package list of vulnerability dicts."""
        if not packages:
            return []
        payload = {
            "queries": [
                {"package": {"ecosystem": self.ecosystem, "name": name}, "version": version}
                for name, version in packages
            ]
        }
        response = self._client.post(self.QUERYBATCH_URL, json=payload)
        response.raise_for_status()
        results = response.json().get("results", [])
        return [(results[index].get("vulns") or []) if index < len(results) else [] for index in range(len(packages))]

    def _create_finding(
        self, name: str, version: str, vulns: list[dict], source: str, line_number: int | None
    ) -> Finding:
        vuln_ids = [v.get("id") for v in vulns if v.get("id")]
        references = [f"https://osv.dev/vulnerability/{vuln_id}" for vuln_id in vuln_ids]
        ids_display = ", ".join(vuln_ids) if vuln_ids else "unknown"
        return Finding(
            id=f"OSV_{name}_{version}",
            rule_id="SUPPLY_CHAIN_KNOWN_VULNERABILITY",
            category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
            severity=Severity.HIGH,
            title=f"Known vulnerability in dependency {name}=={version}",
            description=(
                f"Dependency '{name}=={version}' has {len(vuln_ids)} known "
                f"vulnerability advisory(ies) in the OSV database: {ids_display}."
            ),
            file_path=source,
            line_number=line_number,
            snippet=f"{name}=={version}",
            remediation="Upgrade to a patched version listed in the referenced OSV advisories.",
            analyzer="osv",
            metadata={
                "package": name,
                "version": version,
                "ecosystem": self.ecosystem,
                "vulnerability_ids": vuln_ids,
                "references": references,
            },
        )
