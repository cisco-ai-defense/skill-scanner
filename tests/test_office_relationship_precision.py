# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.data.packs.core.python.external_tool_checks import check_office_documents

_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"


def _document(path: Path, relationship: str, *, extra: dict[str, bytes | str] | None = None) -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr("word/document.xml", "<document/>")
        archive.writestr(
            "word/_rels/document.xml.rels",
            f'<Relationships xmlns="{_REL_NS}">{relationship}</Relationships>',
        )
        for name, content in (extra or {}).items():
            archive.writestr(name, content)
    return path


def _relationship(*, kind: str = "hyperlink", target: str = "https://example.com/reference") -> str:
    return (
        f'<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        f'relationships/{kind}" Target="{target}" TargetMode="External"/>'
    )


def _scan_with_external_relationship_indicator(tmp_path: Path, relationship: str, monkeypatch) -> list:
    skill_dir = tmp_path / "skill"
    assets = skill_dir / "assets"
    assets.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: office-reference\ndescription: Read the supplied reference document\n---\n\n"
        "Read [the reference](assets/reference.docx).\n",
        encoding="utf-8",
    )
    _document(assets / "reference.docx", relationship)

    class _OleId:
        def __init__(self, _path: str) -> None:
            pass

        def check(self):
            return [SimpleNamespace(id="ext_rels", value=1, name="External Relationships")]

    monkeypatch.setattr("oletools.oleid.OleID", _OleId)
    skill = SkillLoader().load_skill(skill_dir)
    return StaticAnalyzer(use_yara=False).analyze(skill)


def test_external_relationship_indicator_fails_open_even_for_https_hyperlink(
    tmp_path: Path,
    monkeypatch,
) -> None:
    findings = _scan_with_external_relationship_indicator(tmp_path, _relationship(), monkeypatch)

    hits = [finding for finding in findings if finding.rule_id == "OFFICE_DOCUMENT_THREAT"]
    assert len(hits) == 1
    assert hits[0].severity.value == "MEDIUM"


def test_office_analyzer_retains_active_external_template(
    tmp_path: Path,
    monkeypatch,
) -> None:
    findings = _scan_with_external_relationship_indicator(
        tmp_path,
        _relationship(kind="attachedTemplate"),
        monkeypatch,
    )

    hits = [finding for finding in findings if finding.rule_id == "OFFICE_DOCUMENT_THREAT"]
    assert len(hits) == 1
    assert hits[0].severity.value == "MEDIUM"


def _scan_with_macro_indicator(
    tmp_path: Path,
    monkeypatch,
    *,
    indicator_id: str,
    indicator_value: object,
) -> dict[str, list]:
    from oletools.oleid import Indicator

    skill_dir = tmp_path / "macro-skill"
    assets = skill_dir / "assets"
    assets.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "---\nname: macro-reference\ndescription: Read the supplied reference document\n---\n\n"
        "Read [the reference](assets/reference.docm).\n",
        encoding="utf-8",
    )
    _document(assets / "reference.docm", "")
    indicator = Indicator(indicator_id, value=indicator_value, name="Macro status")

    class _OleId:
        def __init__(self, _path: str) -> None:
            pass

        def check(self):
            return [indicator]

    monkeypatch.setattr("oletools.oleid.OleID", _OleId)
    skill = SkillLoader().load_skill(skill_dir)
    return {
        "static": StaticAnalyzer(use_yara=False).analyze(skill),
        "pack": check_office_documents(skill, ScanPolicy.default()),
    }


@pytest.mark.parametrize("indicator_id", ["vba", "xlm"])
def test_real_oleid_macro_indicator_ids_are_critical(
    tmp_path: Path,
    monkeypatch,
    indicator_id: str,
) -> None:
    results = _scan_with_macro_indicator(
        tmp_path,
        monkeypatch,
        indicator_id=indicator_id,
        indicator_value="Yes",
    )

    for findings in results.values():
        hits = [finding for finding in findings if finding.rule_id == "OFFICE_DOCUMENT_THREAT"]
        assert len(hits) == 1
        assert hits[0].severity.value == "CRITICAL"


def test_negative_oleid_macro_string_is_not_truthy(tmp_path: Path, monkeypatch) -> None:
    results = _scan_with_macro_indicator(
        tmp_path,
        monkeypatch,
        indicator_id="vba",
        indicator_value="No",
    )

    assert all(
        not [finding for finding in findings if finding.rule_id == "OFFICE_DOCUMENT_THREAT"]
        for findings in results.values()
    )


def test_inconclusive_oleid_macro_state_fails_open(tmp_path: Path, monkeypatch) -> None:
    results = _scan_with_macro_indicator(
        tmp_path,
        monkeypatch,
        indicator_id="vba",
        indicator_value="Error",
    )

    for findings in results.values():
        hits = [finding for finding in findings if finding.rule_id == "OFFICE_DOCUMENT_THREAT"]
        assert len(hits) == 1
        assert hits[0].severity.value == "HIGH"
