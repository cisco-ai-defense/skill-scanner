# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for bounded-cost processing of untrusted skill content."""

import io
import tarfile
import time
from pathlib import Path

import pytest

from skill_scanner.core.analyzers.pipeline_analyzer import PipelineAnalyzer
from skill_scanner.core.extractors.content_extractor import (
    ContentExtractor,
    ExtractionLimits,
)
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import SkillFile
from skill_scanner.utils.markdown import extract_markdown_links


def _write_skill(skill_dir: Path, body: str) -> None:
    skill_dir.mkdir()
    (skill_dir / "SKILL.md").write_text(
        "---\nname: dos-regression\ndescription: Regression test\n---\n\n" + body,
        encoding="utf-8",
    )


def _make_tar_bomb(path: Path, mode: str, uncompressed_size: int = 2 * 1024 * 1024) -> None:
    with tarfile.open(path, mode) as tf:
        member = tarfile.TarInfo("zeros.bin")
        member.size = uncompressed_size
        tf.addfile(member, io.BytesIO(bytes(uncompressed_size)))


def _scan_archive(path: Path, limits: ExtractionLimits | None = None):
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


def test_markdown_link_parser_handles_valid_links():
    assert extract_markdown_links("See [guide](docs/guide.md) and [script](scripts/run.py).") == [
        ("guide", "docs/guide.md"),
        ("script", "scripts/run.py"),
    ]


@pytest.mark.parametrize("separator", [" ", "\n"])
def test_markdown_link_parser_skips_malformed_candidate(separator):
    text = f"[broken](unterminated{separator}[guide](docs/guide.md)"

    assert extract_markdown_links(text) == [("guide", "docs/guide.md")]


def test_loader_discovers_reference_after_malformed_link(tmp_path):
    skill_dir = tmp_path / "skill"
    _write_skill(skill_dir, "[broken](unterminated\n[guide](docs/guide.md)")

    skill = SkillLoader().load_skill(skill_dir)

    assert "docs/guide.md" in skill.referenced_files


def test_markdown_link_parser_keeps_malformed_candidates_linear():
    text = "[broken](unterminated " * 20_000

    started = time.perf_counter()
    links = extract_markdown_links(text)
    elapsed = time.perf_counter() - started

    assert links == []
    assert elapsed < 1.0


def test_loader_rejects_quadratic_markdown_link_work(tmp_path):
    skill_dir = tmp_path / "skill"
    _write_skill(skill_dir, "[" * 200_000)

    started = time.perf_counter()
    skill = SkillLoader().load_skill(skill_dir)
    elapsed = time.perf_counter() - started

    assert skill.referenced_files == []
    assert elapsed < 1.0


def test_pipeline_extraction_rejects_quadratic_inline_code_work():
    started = time.perf_counter()
    pipelines = PipelineAnalyzer()._extract_pipelines("`" + "|" * 200_000, "SKILL.md")
    elapsed = time.perf_counter() - started

    assert pipelines == []
    assert elapsed < 1.0


@pytest.mark.parametrize(
    ("mode", "suffix"),
    [("w:gz", ".tar.gz"), ("w:bz2", ".tar.bz2"), ("w:xz", ".tar.xz")],
)
def test_compressed_tar_bomb_is_stopped_and_flagged(tmp_path, mode, suffix):
    archive_path = tmp_path / f"payload{suffix}"
    _make_tar_bomb(archive_path, mode)

    result = _scan_archive(archive_path)

    assert result.extracted_files == []
    assert any(finding.rule_id == "ARCHIVE_ZIP_BOMB" for finding in result.findings)


def test_tar_absolute_expansion_limit_is_enforced(tmp_path):
    archive_path = tmp_path / "payload.tar.gz"
    _make_tar_bomb(archive_path, "w:gz")
    limits = ExtractionLimits(
        max_total_size_bytes=64 * 1024,
        max_file_count=10,
        max_compression_ratio=1_000_000_000,
    )

    result = _scan_archive(archive_path, limits)

    assert result.extracted_files == []
    assert any(finding.rule_id == "ARCHIVE_ZIP_BOMB" for finding in result.findings)


def test_tar_member_count_is_bounded(tmp_path):
    archive_path = tmp_path / "many.tar"
    with tarfile.open(archive_path, "w") as tf:
        for index in range(4):
            tf.addfile(tarfile.TarInfo(f"empty-{index}.txt"), io.BytesIO())

    result = _scan_archive(archive_path, ExtractionLimits(max_file_count=3))

    assert result.extracted_files == []
    assert any(finding.rule_id == "ARCHIVE_ZIP_BOMB" for finding in result.findings)
