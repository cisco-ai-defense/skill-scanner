# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

from skill_scanner.core.analyzability import compute_analyzability
from skill_scanner.core.models import Skill, SkillFile, SkillManifest
from skill_scanner.core.scan_policy import ScanPolicy


def _skill(tmp_path: Path, files: list[SkillFile]) -> Skill:
    skill_md = tmp_path / "SKILL.md"
    skill_md.write_text("---\nname: fixture\ndescription: inert fixture\n---\n", encoding="utf-8")
    return Skill(
        directory=tmp_path,
        manifest=SkillManifest(name="fixture", description="inert fixture"),
        skill_md_path=skill_md,
        instruction_body="",
        files=files,
    )


def test_extracted_child_does_not_attest_parent_complete_but_font_is_analyzable(tmp_path: Path) -> None:
    document = tmp_path / "reference.docx"
    document.write_bytes(b"PK\x03\x04fixture")
    font = tmp_path / "font1.odttf"
    font.write_bytes(b"obfuscated font bytes")
    skill = _skill(
        tmp_path,
        [
            SkillFile(
                path=document,
                relative_path="assets/reference.docx",
                file_type="binary",
                size_bytes=document.stat().st_size,
            ),
            SkillFile(
                path=font,
                relative_path="assets/reference.docx!/word/fonts/font1.odttf",
                file_type="binary",
                size_bytes=font.stat().st_size,
                extracted_from="assets/reference.docx",
                archive_depth=1,
            ),
        ],
    )

    report = compute_analyzability(skill, policy=ScanPolicy.default())

    # Seeing one bounded child does not prove the whole container was
    # inspected: extraction may have stopped at a member/byte limit.  The
    # parent therefore remains opaque while the exact inert font child gets
    # its own role-specific analyzability credit.
    assert 0.0 < report.score < 100.0
    assert report.unanalyzable_files == 1
    assert report.file_details[0].analysis_methods == []
    assert report.file_details[0].skip_reason == "Binary file (.docx) - cannot inspect content"
    assert report.file_details[1].analysis_methods == ["office_asset_role", "extension_validation"]


def test_presentation_embedded_font_data_is_analyzable_only_in_office_role(tmp_path: Path) -> None:
    font = tmp_path / "font1.fntdata"
    font.write_bytes(b"obfuscated font bytes")
    embedded = SkillFile(
        path=font,
        relative_path="assets/reference.pptx!/ppt/fonts/font1.fntdata",
        file_type="binary",
        size_bytes=font.stat().st_size,
        extracted_from="assets/reference.pptx",
        archive_depth=1,
    )
    unrelated = SkillFile(
        path=font,
        relative_path="scripts/font1.fntdata",
        file_type="binary",
        size_bytes=font.stat().st_size,
    )

    embedded_report = compute_analyzability(_skill(tmp_path, [embedded]), policy=ScanPolicy.default())
    unrelated_report = compute_analyzability(_skill(tmp_path, [unrelated]), policy=ScanPolicy.default())

    assert embedded_report.score == 100.0
    assert embedded_report.file_details[0].analysis_methods == ["office_asset_role", "extension_validation"]
    assert unrelated_report.score == 0.0
    assert unrelated_report.unanalyzable_files == 1


def test_unopened_ooxml_container_remains_opaque(tmp_path: Path) -> None:
    document = tmp_path / "corrupt.docx"
    document.write_bytes(b"not a zip")
    skill = _skill(
        tmp_path,
        [
            SkillFile(
                path=document,
                relative_path="assets/corrupt.docx",
                file_type="binary",
                size_bytes=document.stat().st_size,
            )
        ],
    )

    report = compute_analyzability(skill, policy=ScanPolicy.default())

    assert report.score == 0.0
    assert report.unanalyzable_files == 1
    assert report.file_details[0].skip_reason == "Binary file (.docx) - cannot inspect content"
