# Copyright 2026 Cisco Systems, Inc. and its affiliates
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

from pathlib import Path

import pytest

from skill_scanner.core.analyzers.base import BaseAnalyzer
from skill_scanner.core.models import Finding, Skill
from skill_scanner.core.scanner import SkillScanner


class RecordingAnalyzer(BaseAnalyzer):
    def __init__(self):
        super().__init__("recording")
        self.skills: list[Skill] = []

    def analyze(self, skill: Skill) -> list[Finding]:
        self.skills.append(skill)
        return []


@pytest.fixture
def recording_scanner():
    analyzer = RecordingAnalyzer()
    with SkillScanner(analyzers=[analyzer], cel_rules=[]) as scanner:
        yield scanner, analyzer


def write_skill(directory: Path, filename: str = "SKILL.md") -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / filename).write_text(
        f"---\nname: {directory.name}\ndescription: Formats local weather records.\nlicense: MIT\n---\n"
        "Read references/guide.md.\n"
    )


def write_markdown(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Guide\nReference: https://reference.example.invalid/guide\n")
    return path.resolve()


def symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks are unavailable")


def test_lenient_skips_markdown_descendants_of_a_manifest_skill(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    write_markdown(parent / "prompts" / "pipeline.md")
    write_markdown(parent / "resources" / "US" / "notes.md")
    expected_files = {p.resolve() for p in parent.rglob("*") if p.is_file()}

    report = scanner.scan_directory(tmp_path, recursive=True, lenient=True, check_overlap=True)

    assert [s.directory for s in analyzer.skills] == [parent]
    assert {f.path for f in analyzer.skills[0].files} == expected_files
    assert guide in expected_files
    assert len(report.scan_results) == 1
    assert not report.cross_skill_findings
    assert not report.skills_skipped


def test_lenient_keeps_independent_markdown_directory(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    write_markdown(parent / "references" / "guide.md")
    command = write_markdown(tmp_path / "commands" / "format.md")

    scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert {s.directory for s in analyzer.skills} == {parent, command.parent}
    assert command in {f.path for s in analyzer.skills for f in s.files}


def test_lenient_keeps_nested_manifest_skill(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    nested = parent / "nested"
    write_skill(parent)
    write_skill(nested)
    write_markdown(nested / "references" / "guide.md")

    report = scanner.scan_directory(tmp_path, recursive=True, lenient=True, check_overlap=True)

    assert {s.directory for s in analyzer.skills} == {parent, nested}
    assert any(f.rule_id == "TRIGGER_OVERLAP_RISK" for f in report.cross_skill_findings)


def test_custom_manifest_keeps_nested_skills(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    nested = parent / "nested"
    write_skill(parent, "COMMAND.md")
    write_skill(nested, "COMMAND.md")

    scanner.scan_directory(tmp_path, recursive=True, lenient=True, skill_file="COMMAND.md")

    assert {s.directory for s in analyzer.skills} == {parent, nested}


def test_lenient_skips_the_folder_that_contains_a_manifest_skill(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    write_markdown(parent / "references" / "guide.md")
    changelog = write_markdown(tmp_path / "CHANGELOG.md")

    scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert [s.directory for s in analyzer.skills] == [parent]
    assert changelog not in {f.path for s in analyzer.skills for f in s.files}


def test_rejected_parent_does_not_hide_markdown_descendant(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    (parent / "SKILL.md").write_bytes(b"\x00\xff\xfe")
    guide = write_markdown(parent / "references" / "guide.md")

    report = scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert [s.directory for s in analyzer.skills] == [guide.parent]
    assert guide in {f.path for s in analyzer.skills for f in s.files}
    assert any(item["skill"] == str(parent) for item in report.skills_skipped)


def test_uncovered_descendant_is_still_scanned(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    # The parent loader excludes .git contents; a nested candidate must not
    # be discarded solely because its resolved path is inside the parent.
    guide = write_markdown(parent / ".git" / "notes" / "guide.md")

    scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert {s.directory for s in analyzer.skills} == {parent, guide.parent}
    assert guide not in {f.path for f in analyzer.skills[0].files}
    assert guide in {f.path for s in analyzer.skills for f in s.files}


def test_failed_parent_analysis_does_not_hide_descendant(recording_scanner, tmp_path, monkeypatch):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    analyze = analyzer.analyze

    def fail_parent(skill):
        if skill.directory == parent:
            raise RuntimeError("parent analysis failed")
        return analyze(skill)

    monkeypatch.setattr(analyzer, "analyze", fail_parent)

    report = scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert any(item["skill"] == str(parent) for item in report.skills_skipped)
    assert [s.directory for s in analyzer.skills] == [guide.parent]


def test_parent_reporting_analyzer_failure_does_not_hide_descendant(recording_scanner, tmp_path, monkeypatch):
    scanner, analyzer = recording_scanner
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    scan = scanner._scan_single_skill

    def report_failure(skill, directory, **kwargs):
        result = scan(skill, directory, **kwargs)
        if directory == parent:
            result.analyzers_failed.append({"analyzer": "recording", "error": "incomplete analysis"})
        return result

    monkeypatch.setattr(scanner, "_scan_single_skill", report_failure)

    scanner.scan_directory(tmp_path, recursive=True, lenient=True)

    assert {s.directory for s in analyzer.skills} == {parent, guide.parent}


def test_external_markdown_symlink_is_still_scanned(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    scan_root = tmp_path / "scan"
    parent = scan_root / "weather"
    write_skill(parent)
    guide = write_markdown(tmp_path / "external" / "guide.md")
    symlink(parent / "linked-notes", guide.parent)

    scanner.scan_directory(scan_root, recursive=True, lenient=True)

    assert {s.directory.resolve() for s in analyzer.skills} == {parent, guide.parent}
    assert guide in {f.path for s in analyzer.skills for f in s.files}


def test_symlinked_manifest_and_cycle_keep_coverage(recording_scanner, tmp_path):
    scanner, analyzer = recording_scanner
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    parent = tmp_path / "weather"
    write_skill(parent)
    guide = write_markdown(parent / "references" / "guide.md")
    symlink(scan_root / "weather", parent)
    symlink(parent / "cycle", parent)

    scanner.scan_directory(scan_root, recursive=True, lenient=True)

    assert [s.directory.resolve() for s in analyzer.skills] == [parent]
    assert guide in {f.path for s in analyzer.skills for f in s.files}


def _issue_234_tree(root: Path) -> Path:
    """The reproduction tree from issue #234: one real skill inside a plugin."""
    plugin = root / "my-plugin"
    skill = plugin / "skills" / "demo-skill"
    for sub in ("references", "prompts", "resources/US", "scripts"):
        (skill / sub).mkdir(parents=True)
    (plugin / "CHANGELOG.md").write_text("# Changelog\n\n## 1.0.0\n- Initial release.\n")
    (skill / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Demo skill used to reproduce lenient discovery behaviour.\n---\n\n"
        "# Demo skill\n\nRead `references/guide.md` and follow `prompts/pipeline.md`.\n"
    )
    (skill / "references" / "guide.md").write_text(
        "# Guide\n\nLook the company up at https://registry.example-gov.test/search before continuing.\n"
    )
    (skill / "prompts" / "pipeline.md").write_text(
        "# Pipeline\n\n```bash\nout=$(python scripts/ingest.py)\necho $out | python scripts/route.py\n```\n"
    )
    (skill / "resources" / "US" / "notes.md").write_text("# Notes\n\nRegion notes.\n")
    for name in ("ingest.py", "route.py"):
        (skill / "scripts" / name).write_text('print("ok")\n')
    return plugin


def test_issue_234_lenient_matches_strict_discovery(tmp_path):
    from skill_scanner.core.analyzer_factory import build_analyzers
    from skill_scanner.core.scan_policy import ScanPolicy

    plugin = _issue_234_tree(tmp_path)
    policy = ScanPolicy.default()

    def scan(lenient: bool):
        analyzers = build_analyzers(policy, use_behavioral=True)
        with SkillScanner(analyzers=analyzers, policy=policy) as scanner:
            return scanner.scan_directory(plugin, recursive=True, check_overlap=True, lenient=lenient)

    strict, lenient = scan(False), scan(True)

    def keys(report):
        return sorted(
            (r.skill_name, f.rule_id, f.file_path, f.line_number) for r in report.scan_results for f in r.findings
        )

    assert [r.skill_name for r in lenient.scan_results] == ["demo-skill"]
    assert keys(lenient) == keys(strict)
    assert len(keys(lenient)) == len(set(keys(lenient)))
    assert not lenient.cross_skill_findings
    skill_dir = plugin / "skills" / "demo-skill"
    for result in lenient.scan_results:
        for finding in result.findings:
            if finding.file_path:
                assert (skill_dir / finding.file_path).exists(), finding.file_path
