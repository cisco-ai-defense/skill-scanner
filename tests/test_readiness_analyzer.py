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

import tempfile
from pathlib import Path

import pytest

from skill_scanner.core.analyzers.readiness_analyzer import ReadinessAnalyzer
from skill_scanner.core.loader import SkillLoader
from skill_scanner.core.models import Severity


@pytest.fixture
def analyzer():
    return ReadinessAnalyzer()


@pytest.fixture
def loader():
    return SkillLoader()


def create_skill_dir(content: str) -> Path:
    tmpdir = tempfile.mkdtemp()
    skill_md = Path(tmpdir) / "SKILL.md"
    skill_md.write_text(content)
    return Path(tmpdir)


class TestReadinessAnalyzer:
    def test_analyzer_name(self, analyzer):
        assert analyzer.get_name() == "readiness_analyzer"

    def test_valid_skill_no_findings(self, analyzer, loader):
        content = """---
name: valid-skill
description: A valid skill for testing. Use when testing the analyzer.
---

# Valid Skill

This is a valid skill with proper structure.
"""
        skill_dir = create_skill_dir(content)
        skill = loader.load_skill(skill_dir)
        findings = analyzer.analyze(skill)
        high_findings = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert len(high_findings) == 0

    def test_missing_trigger_context(self, analyzer, loader):
        content = """---
name: no-trigger-skill
description: A skill that does things with files.
---

# No Trigger Skill

Content here.
"""
        skill_dir = create_skill_dir(content)
        skill = loader.load_skill(skill_dir)
        findings = analyzer.analyze(skill)
        trigger_findings = [f for f in findings if f.rule_id == "SRDNS-005"]
        assert len(trigger_findings) == 1
        assert trigger_findings[0].severity == Severity.MEDIUM

    def test_first_person_description(self, analyzer, loader):
        content = """---
name: first-person-skill
description: I can help you process files. Use when needed.
---

# First Person Skill

Content here.
"""
        skill_dir = create_skill_dir(content)
        skill = loader.load_skill(skill_dir)
        findings = analyzer.analyze(skill)
        person_findings = [f for f in findings if f.rule_id == "SRDNS-006"]
        assert len(person_findings) == 1
        assert person_findings[0].severity == Severity.MEDIUM

    def test_short_description(self, analyzer, loader):
        content = """---
name: short-desc-skill
description: Short
---

# Short Description Skill

Content here.
"""
        skill_dir = create_skill_dir(content)
        skill = loader.load_skill(skill_dir)
        findings = analyzer.analyze(skill)
        length_findings = [f for f in findings if f.rule_id == "SRDNS-007"]
        assert len(length_findings) == 1
        assert length_findings[0].severity == Severity.HIGH

    def test_invalid_name_format(self, analyzer, loader):
        content = """---
name: Invalid_Name_Here
description: A skill with invalid name. Use when testing name validation.
---

# Invalid Name Skill

Content here.
"""
        skill_dir = create_skill_dir(content)
        skill = loader.load_skill(skill_dir)
        findings = analyzer.analyze(skill)
        name_findings = [f for f in findings if f.rule_id == "SRDNS-010"]
        assert len(name_findings) == 1
        assert name_findings[0].severity == Severity.MEDIUM

    def test_large_skill_no_refs(self, analyzer, loader):
        lines = "\n".join([f"Line {i}: Some content here." for i in range(150)])
        content = f"""---
name: large-skill
description: A large skill without progressive disclosure. Use when testing size limits.
---

# Large Skill

{lines}
"""
        skill_dir = create_skill_dir(content)
        skill = loader.load_skill(skill_dir)
        findings = analyzer.analyze(skill)
        disclosure_findings = [f for f in findings if f.rule_id == "SRDNS-003"]
        assert len(disclosure_findings) == 1
        assert disclosure_findings[0].severity == Severity.MEDIUM

    def test_exceeds_line_limit(self, analyzer, loader):
        lines = "\n".join([f"Line {i}: Some content here." for i in range(600)])
        content = f"""---
name: oversized-skill
description: An oversized skill. Use when testing line limits.
---

# Oversized Skill

{lines}
"""
        skill_dir = create_skill_dir(content)
        skill = loader.load_skill(skill_dir)
        findings = analyzer.analyze(skill)
        line_findings = [f for f in findings if f.rule_id == "SRDNS-001"]
        assert len(line_findings) == 1
        assert line_findings[0].severity == Severity.MEDIUM
