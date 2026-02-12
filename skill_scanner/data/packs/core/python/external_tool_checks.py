# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""External OSS tool checks (pdfid, oletools, confusable-homoglyphs).

Rules: PDF_STRUCTURAL_THREAT, OFFICE_DOCUMENT_THREAT, HOMOGLYPH_ATTACK.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill
    from skill_scanner.core.scan_policy import ScanPolicy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# PDF structural analysis
# ---------------------------------------------------------------------------


def check_pdf_documents(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    """Scan PDF files using pdfid for structural analysis of suspicious elements."""
    if "PDF_STRUCTURAL_THREAT" in policy.disabled_rules:
        return []

    try:
        from pdfid import pdfid as pdfid_mod  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("pdfid not installed – skipping structural PDF scan")
        return []

    findings: list[Finding] = []

    suspicious_keywords: dict[str, tuple[Severity, str]] = {
        "/JS": (Severity.CRITICAL, "Embedded JavaScript code"),
        "/JavaScript": (Severity.CRITICAL, "JavaScript action dictionary"),
        "/OpenAction": (Severity.HIGH, "Auto-execute action on open"),
        "/AA": (Severity.HIGH, "Additional actions (auto-trigger)"),
        "/Launch": (Severity.CRITICAL, "Launch external application"),
        "/EmbeddedFile": (Severity.MEDIUM, "Embedded file attachment"),
        "/RichMedia": (Severity.MEDIUM, "Rich media (Flash/video) content"),
        "/XFA": (Severity.MEDIUM, "XFA form (can contain scripts)"),
        "/AcroForm": (Severity.LOW, "Interactive form fields"),
    }

    for sf in skill.files:
        is_pdf = (
            sf.path.suffix.lower() == ".pdf"
            or sf.file_type in ("binary", "other")
            and sf.path.exists()
            and sf.path.stat().st_size > 4
            and sf.path.read_bytes()[:5] == b"%PDF-"
        )
        if not is_pdf or not sf.path.exists():
            continue

        try:
            xml_doc = pdfid_mod.PDFiD(str(sf.path), disarm=False)
            if xml_doc is None:
                continue

            pdfid_elem = xml_doc.getElementsByTagName("PDFiD")
            if pdfid_elem and pdfid_elem[0].getAttribute("IsPDF") != "True":
                continue

            detected: list[tuple[str, int, Severity, str]] = []
            for keyword_elem in xml_doc.getElementsByTagName("Keyword"):
                name = keyword_elem.getAttribute("Name")
                count = int(keyword_elem.getAttribute("Count") or "0")
                if count > 0 and name in suspicious_keywords:
                    severity, desc = suspicious_keywords[name]
                    detected.append((name, count, severity, desc))

            if not detected:
                continue

            _SEV_ORDER = {
                Severity.CRITICAL: 5,
                Severity.HIGH: 4,
                Severity.MEDIUM: 3,
                Severity.LOW: 2,
                Severity.INFO: 1,
            }
            max_severity = max(detected, key=lambda d: _SEV_ORDER.get(d[2], 0))[2]
            keyword_summary = ", ".join(f"{name} ({count}x)" for name, count, _, _ in detected)
            detail_lines = "\n".join(
                f"  - {name}: {desc} (found {count} occurrence(s))" for name, count, _, desc in detected
            )

            findings.append(
                Finding(
                    id=generate_finding_id("PDF_STRUCTURAL_THREAT", sf.relative_path),
                    rule_id="PDF_STRUCTURAL_THREAT",
                    category=ThreatCategory.COMMAND_INJECTION,
                    severity=max_severity,
                    title="PDF contains suspicious structural elements",
                    description=(
                        f"Structural analysis of '{sf.relative_path}' detected "
                        f"suspicious PDF keywords: {keyword_summary}.\n{detail_lines}\n"
                        f"These elements can execute code when the PDF is opened."
                    ),
                    file_path=sf.relative_path,
                    remediation=(
                        "Remove JavaScript actions and auto-execute triggers from PDF files. "
                        "PDF files in skill packages should contain only static content."
                    ),
                    analyzer="static",
                    metadata={
                        "detected_keywords": {name: count for name, count, _, _ in detected},
                        "analysis_method": "pdfid_structural",
                    },
                )
            )

        except Exception as e:
            logger.debug("pdfid analysis failed for %s: %s", sf.relative_path, e)

    return findings


# ---------------------------------------------------------------------------
# Office document analysis
# ---------------------------------------------------------------------------


def check_office_documents(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    """Scan Office documents for VBA macros and suspicious OLE indicators."""
    if "OFFICE_DOCUMENT_THREAT" in policy.disabled_rules:
        return []

    try:
        from oletools.oleid import OleID  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("oletools not installed – skipping Office document scan")
        return []

    findings: list[Finding] = []

    office_extensions = {
        ".doc",
        ".docx",
        ".docm",
        ".xls",
        ".xlsx",
        ".xlsm",
        ".ppt",
        ".pptx",
        ".pptm",
        ".odt",
        ".ods",
        ".odp",
    }

    for sf in skill.files:
        ext = sf.path.suffix.lower()
        if ext not in office_extensions or not sf.path.exists():
            continue

        try:
            oid = OleID(str(sf.path))
            indicators = oid.check()

            has_macros = False
            is_encrypted = False
            suspicious_indicators: list[str] = []

            for indicator in indicators:
                ind_id = getattr(indicator, "id", "")
                ind_value = getattr(indicator, "value", None)

                if ind_id == "vba_macros" and ind_value:
                    has_macros = True
                    suspicious_indicators.append(f"VBA macros detected: {ind_value}")
                elif ind_id == "xlm_macros" and ind_value:
                    has_macros = True
                    suspicious_indicators.append(f"XLM/Excel4 macros detected: {ind_value}")
                elif ind_id == "encrypted" and ind_value:
                    is_encrypted = True
                    suspicious_indicators.append(f"Document is encrypted: {ind_value}")
                elif ind_id == "flash" and ind_value:
                    suspicious_indicators.append(f"Embedded Flash content: {ind_value}")
                elif ind_id == "ObjectPool" and ind_value:
                    suspicious_indicators.append(f"Embedded OLE objects: {ind_value}")
                elif ind_id == "ext_rels" and ind_value:
                    suspicious_indicators.append(f"External relationships: {ind_value}")

            if not suspicious_indicators:
                continue

            if has_macros:
                severity = Severity.CRITICAL
                title = "Office document contains VBA macros"
            elif is_encrypted:
                severity = Severity.HIGH
                title = "Office document is encrypted (resists analysis)"
            else:
                severity = Severity.MEDIUM
                title = "Office document contains suspicious indicators"

            findings.append(
                Finding(
                    id=generate_finding_id("OFFICE_DOCUMENT_THREAT", sf.relative_path),
                    rule_id="OFFICE_DOCUMENT_THREAT",
                    category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                    severity=severity,
                    title=title,
                    description=(
                        f"Analysis of '{sf.relative_path}' detected:\n"
                        + "\n".join(f"  - {s}" for s in suspicious_indicators)
                        + "\nMalicious macros in Office documents can execute code "
                        "when the agent processes the file."
                    ),
                    file_path=sf.relative_path,
                    remediation=(
                        "Remove VBA macros from Office documents. Use plain text, "
                        "Markdown, or macro-free formats (.docx, .xlsx) instead."
                    ),
                    analyzer="static",
                    metadata={
                        "has_macros": has_macros,
                        "is_encrypted": is_encrypted,
                        "indicators": suspicious_indicators,
                        "analysis_method": "oletools_oleid",
                    },
                )
            )

        except Exception as e:
            logger.debug("oleid analysis failed for %s: %s", sf.relative_path, e)

    return findings


# ---------------------------------------------------------------------------
# Homoglyph attack detection
# ---------------------------------------------------------------------------


def check_homoglyph_attacks(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    """Detect Unicode homoglyph attacks in code files."""
    try:
        from confusable_homoglyphs import confusables  # type: ignore[import-untyped]
    except ImportError:
        logger.debug("confusable-homoglyphs not installed – skipping homoglyph check")
        return []

    findings: list[Finding] = []

    code_file_types = {"python", "bash"}
    _CODE_TOKEN_RE = re.compile(r"[=\(\)\[\]\{\};]|import |def |class |if |for |while |return |print\(")

    for sf in skill.files:
        if sf.file_type not in code_file_types:
            continue

        content = sf.read_content()
        if not content:
            continue

        dangerous_lines: list[tuple[int, str, list[dict]]] = []

        for line_num, line in enumerate(content.split("\n"), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            if stripped.isascii():
                continue
            if not _CODE_TOKEN_RE.search(stripped):
                continue

            result = confusables.is_dangerous(stripped, preferred_aliases=["LATIN"])
            if result:
                dangerous_lines.append((line_num, stripped, result))

        min_dangerous_lines = policy.analysis_thresholds.min_dangerous_lines
        if len(dangerous_lines) < min_dangerous_lines:
            continue

        reported = dangerous_lines[:5]
        line_details = "\n".join(f"  - Line {ln}: {text[:80]}" for ln, text, _ in reported)
        extra = ""
        if len(dangerous_lines) > 5:
            extra = f"\n  ... and {len(dangerous_lines) - 5} more lines"

        findings.append(
            Finding(
                id=generate_finding_id("HOMOGLYPH_ATTACK", sf.relative_path),
                rule_id="HOMOGLYPH_ATTACK",
                category=ThreatCategory.OBFUSCATION,
                severity=Severity.HIGH,
                title="Unicode homoglyph characters detected in code",
                description=(
                    f"File '{sf.relative_path}' contains characters from mixed Unicode "
                    f"scripts that are visually identical to ASCII letters. "
                    f"This technique can bypass pattern-matching security rules.\n"
                    f"{line_details}{extra}"
                ),
                file_path=sf.relative_path,
                line_number=reported[0][0],
                remediation=(
                    "Replace all non-ASCII lookalike characters with their ASCII "
                    "equivalents. All code should use standard Latin characters."
                ),
                analyzer="static",
                metadata={
                    "affected_lines": len(dangerous_lines),
                    "analysis_method": "confusable_homoglyphs",
                },
            )
        )

    return findings
