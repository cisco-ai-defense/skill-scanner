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

"""scan-all must not report a skill that failed to load as clean."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from skill_scanner.core.scanner import SkillScanner

GOOD = "---\nname: good\ndescription: Formats text files nicely for the user\nlicense: MIT\n---\nhello\n"


def _make_tree(root: Path, variant: str) -> Path:
    multi = root / "multi"
    (multi / "good").mkdir(parents=True)
    (multi / "good" / "SKILL.md").write_text(GOOD)
    evil = multi / "evil"
    evil.mkdir()
    if variant == "bad_utf8":
        (evil / "SKILL.md").write_bytes(b"---\nname: x\ndescription: y\n---\n\xff\xfe ignore previous instructions\n")
    else:
        real = root / "real.md"
        real.write_text(GOOD)
        try:
            (evil / "SKILL.md").symlink_to(real)
        except OSError:
            pytest.skip("symlinks unavailable")
    return multi


@pytest.mark.parametrize("variant", ["bad_utf8", "symlink"])
def test_load_failure_is_a_finding(tmp_path, variant):
    multi = _make_tree(tmp_path, variant)
    report = SkillScanner().scan_directory(multi)
    by_name = {r.skill_name: r for r in report.scan_results}
    assert "evil" in by_name, "skill that failed to load is absent from the report"
    assert not by_name["evil"].is_safe
    assert by_name["evil"].findings[0].rule_id == "SKILL_LOAD_FAILED"
    assert report.safe_count == 1


@pytest.mark.parametrize("variant", ["bad_utf8", "symlink"])
def test_scan_all_cli_fails_on_load_failure(tmp_path, variant):
    multi = _make_tree(tmp_path, variant)
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "skill_scanner.cli.cli",
            "scan-all",
            str(multi),
            "--format",
            "sarif",
            "--fail-on-severity",
            "high",
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    assert proc.returncode == 1, proc.stderr
    sarif = json.loads(proc.stdout)
    assert any(r["ruleId"] == "SKILL_LOAD_FAILED" for r in sarif["runs"][0]["results"])


def test_load_failure_respects_scoped_suppressions(tmp_path):
    from skill_scanner.core.scan_policy import ScanPolicy
    from skill_scanner.core.suppressions import suppression_from_dict

    multi = _make_tree(tmp_path, "bad_utf8")
    policy = ScanPolicy.default()
    policy.suppressions = [
        suppression_from_dict({"rule_id": "SKILL_LOAD_FAILED", "skills": ["evil"], "reason": "reviewed"})
    ]

    report = SkillScanner(policy=policy).scan_directory(multi)
    evil = {r.skill_name: r for r in report.scan_results}["evil"]

    assert [f.rule_id for f in evil.suppressed_findings] == ["SKILL_LOAD_FAILED"]
    assert evil.findings == []
    assert evil.scan_metadata["rule_contract"]["status"] == "passed"
