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

"""Attach Cisco AI taxonomy codes to findings.

Every finding that leaves the scanner carries the same taxonomy fields in
``Finding.metadata``:

``aitech`` / ``aitech_name``
    Technique code and official name.
``aisubtech`` / ``aisubtech_name``
    Sub-technique code and name, or ``None`` when the selection is a
    technique without a sub-technique.
``aitech_mappings`` / ``aisubtech_mappings``
    OWASP, MITRE ATLAS and NIST AML crosswalks the taxonomy lists for the
    technique and for the sub-technique.  The two lists differ: the
    technique's list covers the whole technique family.
``framework_mappings``
    The most specific of the two: the sub-technique's crosswalks when a
    sub-technique is selected, otherwise the technique's.
``taxonomy_status``
    ``mapped``, ``not_applicable`` (an operational finding that describes no
    attack technique, e.g. an analyzer error), or ``unmapped``.
``taxonomy_source``
    Where the selection came from, in precedence order: ``finding`` (the
    analyzer chose a code for this finding), ``threat_mapping`` (a custom
    ``--threat-mapping`` file set a code for the finding's analyzer and
    category), ``rule`` (the rule's ``taxonomy`` in its pack manifest), or
    ``pack_default`` (the pack's default for the rule's category).

Codes are only ever taken from the active taxonomy; a selection the taxonomy
does not contain is reported as ``unmapped`` instead of being guessed.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from ..threats import cisco_ai_taxonomy as taxonomy
from ..threats.threats import get_taxonomy_override
from .rule_registry import TAXONOMY_NOT_APPLICABLE, TAXONOMY_PER_FINDING

if TYPE_CHECKING:
    from .models import Finding, ScanResult
    from .rule_registry import RuleRegistry

TAXONOMY_STATUS_MAPPED = "mapped"
TAXONOMY_STATUS_NOT_APPLICABLE = "not_applicable"
TAXONOMY_STATUS_UNMAPPED = "unmapped"

TAXONOMY_SOURCE_FINDING = "finding"
TAXONOMY_SOURCE_THREAT_MAPPING = "threat_mapping"


def select_taxonomy(aitech: Any, aisubtech: Any) -> tuple[str | None, str | None]:
    """Resolve an analyzer's ``(aitech, aisubtech)`` choice against the active taxonomy.

    A valid sub-technique implies its parent technique.  When both are given
    and disagree, the technique wins and the sub-technique is dropped, since
    the two cannot both be right and the technique is the required field.
    Values that are not codes in the active taxonomy are ignored.
    """
    tech = aitech if isinstance(aitech, str) and taxonomy.is_valid_aitech(aitech) else None
    sub = aisubtech if isinstance(aisubtech, str) and taxonomy.is_valid_aisubtech(aisubtech) else None
    parent = taxonomy.get_aisubtech_parent(sub) if sub else None
    if sub and parent and taxonomy.is_valid_aitech(parent) and (tech is None or tech == parent):
        return parent, sub
    return tech, None


def _write(finding: Finding, aitech: str | None, aisubtech: str | None, status: str, source: str | None) -> None:
    metadata = finding.metadata
    metadata["aitech"] = aitech
    metadata["aitech_name"] = taxonomy.get_aitech_name(aitech) if aitech else None
    metadata["aisubtech"] = aisubtech
    metadata["aisubtech_name"] = taxonomy.get_aisubtech_name(aisubtech) if aisubtech else None
    aitech_mappings = taxonomy.get_aitech_framework_mappings(aitech) if aitech else []
    aisubtech_mappings = taxonomy.get_aisubtech_framework_mappings(aisubtech) if aisubtech else []
    metadata["aitech_mappings"] = aitech_mappings
    metadata["aisubtech_mappings"] = aisubtech_mappings
    metadata["framework_mappings"] = list(aisubtech_mappings if aisubtech else aitech_mappings)
    metadata["taxonomy_status"] = status
    metadata["taxonomy_source"] = source


def annotate_finding_taxonomy(finding: Finding, rule_registry: RuleRegistry | None) -> None:
    """Set the taxonomy fields on one finding.

    Safe to call more than once: codes written from a rule declaration on an
    earlier pass are not mistaken for the analyzer's own choice.
    """
    metadata = finding.metadata
    analyzer_chose = metadata.get("taxonomy_source", TAXONOMY_SOURCE_FINDING) == TAXONOMY_SOURCE_FINDING
    if analyzer_chose:
        aitech, aisubtech = select_taxonomy(metadata.get("aitech"), metadata.get("aisubtech"))
        if aitech:
            _write(finding, aitech, aisubtech, TAXONOMY_STATUS_MAPPED, TAXONOMY_SOURCE_FINDING)
            return

    override = get_taxonomy_override(finding.analyzer, finding.category.value)
    if override is not None:
        aitech, aisubtech = select_taxonomy(*override)
        if aitech:
            _write(finding, aitech, aisubtech, TAXONOMY_STATUS_MAPPED, TAXONOMY_SOURCE_THREAT_MAPPING)
            return

    definition = rule_registry.get(finding.rule_id) if rule_registry is not None else None
    if definition is not None and definition.taxonomy == TAXONOMY_NOT_APPLICABLE:
        _write(finding, None, None, TAXONOMY_STATUS_NOT_APPLICABLE, definition.taxonomy_source)
        return
    if definition is not None and definition.taxonomy and definition.taxonomy != TAXONOMY_PER_FINDING:
        aitech, aisubtech = taxonomy.resolve_taxonomy_code(definition.taxonomy)
        if aitech:
            _write(finding, aitech, aisubtech, TAXONOMY_STATUS_MAPPED, definition.taxonomy_source)
            return
    _write(finding, None, None, TAXONOMY_STATUS_UNMAPPED, None)


def annotate_findings_taxonomy(findings: Iterable[Finding], rule_registry: RuleRegistry | None) -> None:
    """Set the taxonomy fields on every finding."""
    for finding in findings:
        annotate_finding_taxonomy(finding, rule_registry)


def refresh_taxonomy_scan_metadata(result: ScanResult) -> None:
    """Recount ``scan_metadata["taxonomy"]`` after findings change post-scan (meta analysis)."""
    if result.scan_metadata is not None and "taxonomy" in result.scan_metadata:
        result.scan_metadata["taxonomy"] = taxonomy_scan_metadata(result.findings)


def taxonomy_scan_metadata(findings: Iterable[Finding]) -> dict[str, Any]:
    """Describe the active taxonomy and how findings resolved against it."""
    counts = {TAXONOMY_STATUS_MAPPED: 0, TAXONOMY_STATUS_NOT_APPLICABLE: 0, TAXONOMY_STATUS_UNMAPPED: 0}
    for finding in findings:
        status = finding.metadata.get("taxonomy_status")
        if status in counts:
            counts[status] += 1
    return {**taxonomy.get_taxonomy_info(), "findings": counts}
