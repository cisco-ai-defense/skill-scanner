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

"""scan-all must fail the gate when a skill was skipped because its analysis crashed."""

from skill_scanner.cli import cli
from skill_scanner.core.scanner import SkillScanner

SKILL = "---\nname: {n}\ndescription: Formats text files nicely for the user\nlicense: MIT\n---\nhello\n"


def test_scan_all_exits_nonzero_when_skill_skipped_on_crash(tmp_path, monkeypatch, capsys):
    for name in ("good", "crashy"):
        d = tmp_path / name
        d.mkdir()
        (d / "SKILL.md").write_text(SKILL.format(n=name))

    real = SkillScanner._scan_single_skill

    def flaky(self, skill, *args, **kwargs):
        if skill.name == "crashy":
            raise RuntimeError("analyzer exploded")
        return real(self, skill, *args, **kwargs)

    monkeypatch.setattr(SkillScanner, "_scan_single_skill", flaky)
    argv = ["skill-scanner", "scan-all", str(tmp_path), "--format", "summary", "--fail-on-severity", "high"]
    monkeypatch.setattr("sys.argv", argv)
    rc = cli.main()
    assert "crashy" in capsys.readouterr().out
    assert rc == 1
