# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Emission-level contracts for findings owned by ``ContentExtractor``."""

from __future__ import annotations

import io
import stat
import struct
import zipfile
from pathlib import Path

import pytest

from skill_scanner.core.extractors.content_extractor import (
    ContentExtractor,
    ExtractionLimits,
    ExtractionResult,
)
from skill_scanner.core.models import Severity, SkillFile, ThreatCategory
from skill_scanner.core.rule_registry import PackLoader, RuleRegistry
from skill_scanner.data.packs.core.python.archive_checks import ARCHIVE_RULE_IDS

EXPECTED_CONTENT_EXTRACTOR_RULE_IDS = {
    "ARCHIVE_EXTRACTION_FAILED",
    "ARCHIVE_NESTED_TOO_DEEP",
    "ARCHIVE_PATH_TRAVERSAL",
    "ARCHIVE_SYMLINK",
    "ARCHIVE_ZIP_BOMB",
    "OFFICE_EMBEDDED_OLE",
    "OFFICE_VBA_MACRO",
}


@pytest.fixture(scope="module")
def bundled_registry() -> RuleRegistry:
    """Load the same authoritative manifest used by production scans."""

    return PackLoader().build_registry()


def _scan_archive(path: Path, *, limits: ExtractionLimits | None = None) -> ExtractionResult:
    extractor = ContentExtractor(limits=limits)
    skill_file = SkillFile(
        path=path,
        relative_path=path.name,
        file_type="binary",
        size_bytes=path.stat().st_size,
    )
    try:
        return extractor.extract_skill_archives([skill_file])
    finally:
        extractor.cleanup()


def _assert_emitted_contract(
    result: ExtractionResult,
    registry: RuleRegistry,
    *,
    rule_id: str,
    category: ThreatCategory,
    severity: Severity,
) -> None:
    findings = [finding for finding in result.findings if finding.rule_id == rule_id]
    assert len(findings) == 1, [finding.rule_id for finding in result.findings]

    finding = findings[0]
    assert finding.analyzer == "content_extractor"
    assert finding.category is category
    assert finding.severity is severity
    assert registry.validate_bundled_python_finding(finding, require_known=True) == ()

    definition = registry.get(rule_id)
    assert definition is not None
    assert definition.source_type == "python"
    assert definition.analyzer == finding.analyzer
    assert definition.category == finding.category.value
    assert definition.default_severity.upper() == finding.severity.value


def test_content_extractor_audit_inventory_covers_all_manifest_owned_rules() -> None:
    assert set(ARCHIVE_RULE_IDS) == EXPECTED_CONTENT_EXTRACTOR_RULE_IDS


def test_archive_extraction_failed_emission_matches_manifest(tmp_path: Path, bundled_registry: RuleRegistry) -> None:
    archive = tmp_path / "corrupt.zip"
    archive.write_bytes(b"this is not a ZIP archive")

    result = _scan_archive(archive)

    _assert_emitted_contract(
        result,
        bundled_registry,
        rule_id="ARCHIVE_EXTRACTION_FAILED",
        category=ThreatCategory.OBFUSCATION,
        severity=Severity.MEDIUM,
    )


def test_archive_nested_too_deep_emission_matches_manifest(tmp_path: Path, bundled_registry: RuleRegistry) -> None:
    nested_bytes = io.BytesIO()
    with zipfile.ZipFile(nested_bytes, "w") as nested:
        nested.writestr("payload.txt", "inert fixture")

    archive = tmp_path / "outer.zip"
    with zipfile.ZipFile(archive, "w") as outer:
        outer.writestr("nested.zip", nested_bytes.getvalue())

    result = _scan_archive(archive, limits=ExtractionLimits(max_depth=0))

    _assert_emitted_contract(
        result,
        bundled_registry,
        rule_id="ARCHIVE_NESTED_TOO_DEEP",
        category=ThreatCategory.OBFUSCATION,
        severity=Severity.HIGH,
    )


def test_archive_zip_bomb_emission_matches_manifest(tmp_path: Path, bundled_registry: RuleRegistry) -> None:
    archive = tmp_path / "high-ratio.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("repeated.bin", b"A" * (1024 * 1024))

    result = _scan_archive(archive, limits=ExtractionLimits(max_compression_ratio=10.0))

    _assert_emitted_contract(
        result,
        bundled_registry,
        rule_id="ARCHIVE_ZIP_BOMB",
        category=ThreatCategory.RESOURCE_ABUSE,
        severity=Severity.CRITICAL,
    )


def test_archive_path_traversal_emission_matches_manifest(tmp_path: Path, bundled_registry: RuleRegistry) -> None:
    archive = tmp_path / "traversal.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("../../outside.txt", "inert fixture")

    result = _scan_archive(archive)

    _assert_emitted_contract(
        result,
        bundled_registry,
        rule_id="ARCHIVE_PATH_TRAVERSAL",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
    )


def test_office_vba_macro_emission_matches_manifest(tmp_path: Path, bundled_registry: RuleRegistry) -> None:
    archive = tmp_path / "macro.docx"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types />")
        zf.writestr("word/vbaProject.bin", b"inert VBA marker")

    result = _scan_archive(archive)

    _assert_emitted_contract(
        result,
        bundled_registry,
        rule_id="OFFICE_VBA_MACRO",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
    )


def test_office_embedded_ole_emission_matches_manifest(tmp_path: Path, bundled_registry: RuleRegistry) -> None:
    archive = tmp_path / "embedded.docx"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types />")
        zf.writestr("word/embeddings/oleObject1.bin", b"inert OLE marker")

    result = _scan_archive(archive)

    _assert_emitted_contract(
        result,
        bundled_registry,
        rule_id="OFFICE_EMBEDDED_OLE",
        category=ThreatCategory.OBFUSCATION,
        severity=Severity.HIGH,
    )


def _embedded_ooxml_bytes(
    *,
    main_part: str = "xl/workbook.xml",
    active_member: str | None = None,
    extra_members: dict[str, bytes | str] | None = None,
    content_types: str = "<Types />",
) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as nested:
        nested.writestr("[Content_Types].xml", content_types)
        nested.writestr(main_part, "<workbook />")
        if active_member:
            nested.writestr(active_member, b"inert active-content marker")
        for name, value in (extra_members or {}).items():
            nested.writestr(name, value)
    return stream.getvalue()


def _outer_presentation_with_embedding(tmp_path: Path, payload: bytes, *, name: str = "embedded.pptx") -> Path:
    archive = tmp_path / name
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types />")
        zf.writestr("ppt/presentation.xml", "<presentation />")
        zf.writestr("ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx", payload)
    return archive


def _embedding_classification(archive: Path) -> str:
    result = _scan_archive(archive)
    finding = next(finding for finding in result.findings if finding.rule_id == "OFFICE_EMBEDDED_OLE")
    return str(finding.metadata["embedded_objects"][0]["classification"])


def test_benign_embedded_ooxml_spreadsheet_is_not_classified_as_ole(tmp_path: Path) -> None:
    archive = tmp_path / "chart.pptx"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types />")
        zf.writestr("ppt/presentation.xml", "<presentation />")
        zf.writestr(
            "ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx",
            _embedded_ooxml_bytes(),
        )

    result = _scan_archive(archive)

    assert not [finding for finding in result.findings if finding.rule_id == "OFFICE_EMBEDDED_OLE"]


def test_active_embedded_ooxml_spreadsheet_remains_actionable(tmp_path: Path) -> None:
    archive = tmp_path / "active-chart.pptx"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types />")
        zf.writestr("ppt/presentation.xml", "<presentation />")
        zf.writestr(
            "ppt/embeddings/Microsoft_Excel_Worksheet1.xlsx",
            _embedded_ooxml_bytes(active_member="xl/vbaProject.bin"),
        )

    result = _scan_archive(archive)

    finding = next(finding for finding in result.findings if finding.rule_id == "OFFICE_EMBEDDED_OLE")
    assert finding.severity == Severity.HIGH
    assert finding.metadata["embedded_objects"][0]["classification"] == "active_ooxml_embedding"
    assert finding.metadata["embedded_objects"][0]["active_content"] is True
    assert any(item.rule_id == "OFFICE_VBA_MACRO" for item in result.findings)


@pytest.mark.parametrize(
    "extra_members",
    [
        {"xl/externalLinks/externalLink1.xml": "<externalLink />"},
        {"xl/queryTables/queryTable1.xml": "<queryTable />"},
        {"customUI/customUI.xml": "<customUI />"},
        {"xl/connections.xml": "<connections />"},
        {
            "xl/_rels/workbook.xml.rels": (
                '<Relationships><Relationship TargetMode="External" '
                'Target="https://outside.example/data" /></Relationships>'
            )
        },
        {
            "xl/_rels/workbook.xml.rels": (
                '<Relationships><Relationship Type="https://schemas.example/extern&#97;lLink" '
                'Target="https://outside.example/data" /></Relationships>'
            )
        },
        {
            "xl/_rels/workbook.xml.rels": (
                '<Relationships><Relationship Type="https://schemas.example/hyperlink" '
                'TargetMode="Extern&#97;l" Target="https://outside.example/data" /></Relationships>'
            )
        },
    ],
)
def test_active_or_external_embedded_ooxml_parts_remain_actionable(
    tmp_path: Path,
    extra_members: dict[str, str],
) -> None:
    archive = _outer_presentation_with_embedding(tmp_path, _embedded_ooxml_bytes(extra_members=extra_members))

    assert _embedding_classification(archive) == "active_ooxml_embedding"


def test_macro_enabled_nested_content_type_remains_actionable(tmp_path: Path) -> None:
    payload = _embedded_ooxml_bytes(
        content_types=(
            '<Types><Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.ms-excel.sheet.macroEnabled.main+xml" /></Types>'
        )
    )

    assert _embedding_classification(_outer_presentation_with_embedding(tmp_path, payload)) == (
        "active_ooxml_embedding"
    )


@pytest.mark.parametrize(
    ("payload_factory", "classification"),
    [
        (
            lambda: _embedded_ooxml_bytes(extra_members={"../escape.xml": "<escape />"}),
            "unsafe_ooxml_member_path",
        ),
        (
            lambda: _embedded_ooxml_bytes(extra_members={"xl/./workbook.xml": "<duplicate />"}),
            "duplicate_ooxml_member_name",
        ),
        (
            lambda: _embedded_ooxml_bytes(extra_members={"x" * 1_025: b"x"}),
            "invalid_ooxml_member_name",
        ),
    ],
)
def test_nested_ooxml_unsafe_inventory_fails_open_actionable(
    tmp_path: Path,
    payload_factory,
    classification: str,
) -> None:
    archive = _outer_presentation_with_embedding(tmp_path, payload_factory())

    assert _embedding_classification(archive) == classification


def test_nested_ooxml_encrypted_flag_fails_open_actionable(tmp_path: Path) -> None:
    payload = bytearray(_embedded_ooxml_bytes())
    central = payload.find(b"PK\x01\x02")
    assert central >= 0
    flags = struct.unpack_from("<H", payload, central + 8)[0]
    struct.pack_into("<H", payload, central + 8, flags | 0x1)

    archive = _outer_presentation_with_embedding(tmp_path, bytes(payload))

    assert _embedding_classification(archive) == "encrypted_ooxml_embedding"


def test_nested_ooxml_declared_zip_bomb_fails_open_actionable(tmp_path: Path) -> None:
    payload = bytearray(_embedded_ooxml_bytes())
    central = payload.find(b"PK\x01\x02")
    assert central >= 0
    struct.pack_into(
        "<L",
        payload,
        central + 24,
        ContentExtractor._MAX_EMBEDDED_OOXML_DECLARED_UNCOMPRESSED_BYTES + 1,
    )

    archive = _outer_presentation_with_embedding(tmp_path, bytes(payload))

    assert _embedding_classification(archive) == "oversized_ooxml_declared_content"


def test_nested_ooxml_member_count_limit_fails_open_actionable(tmp_path: Path) -> None:
    extras = {
        f"xl/worksheets/sheet-{index}.xml": "" for index in range(ContentExtractor._MAX_EMBEDDED_OOXML_MEMBER_COUNT - 1)
    }
    payload = _embedded_ooxml_bytes(extra_members=extras)

    archive = _outer_presentation_with_embedding(tmp_path, payload)

    assert _embedding_classification(archive) == "excessive_ooxml_member_count"


@pytest.mark.parametrize(
    ("payload", "classification", "inner_magic"),
    [
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1legacy", "legacy_ole", "ole_cfb"),
        (b"MZembedded executable", "embedded_executable", "pe"),
        (b"PK\x03\x04not-a-valid-ooxml", "malformed_ooxml_embedding", "zip"),
    ],
)
def test_dangerous_or_malformed_office_embeddings_remain_actionable(
    tmp_path: Path,
    payload: bytes,
    classification: str,
    inner_magic: str,
) -> None:
    archive = tmp_path / "embedded.pptx"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types />")
        zf.writestr("ppt/presentation.xml", "<presentation />")
        suffix = ".xlsx" if payload.startswith(b"PK") else ".bin"
        zf.writestr(f"ppt/embeddings/object1{suffix}", payload)

    result = _scan_archive(archive)

    finding = next(finding for finding in result.findings if finding.rule_id == "OFFICE_EMBEDDED_OLE")
    embedded = finding.metadata["embedded_objects"][0]
    assert embedded["classification"] == classification
    assert embedded["inner_magic"] == inner_magic


def test_archive_symlink_emission_matches_manifest(tmp_path: Path, bundled_registry: RuleRegistry) -> None:
    archive = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("outside-link")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(link, "/outside/target")

    result = _scan_archive(archive)

    _assert_emitted_contract(
        result,
        bundled_registry,
        rule_id="ARCHIVE_SYMLINK",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=Severity.CRITICAL,
    )
