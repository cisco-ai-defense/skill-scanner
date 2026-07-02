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

"""Tests for unpinned-dependency detection in the static analyzer."""

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import Severity, ThreatCategory

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    tomllib = None

_RULE_ID = "SUPPLY_CHAIN_UNPINNED_DEPENDENCY"

requires_tomllib = pytest.mark.skipif(tomllib is None, reason="tomllib requires Python 3.11+")


@pytest.fixture(scope="module")
def analyzer() -> StaticAnalyzer:
    return StaticAnalyzer(use_yara=False)


class TestRequirementClassification:
    """Unit tests for the pure line classifier."""

    @pytest.mark.parametrize(
        "line",
        [
            "requests==2.31.0",
            "requests == 2.31.0",
            "requests[security]==2.31.0",
            "requests==2.31.0 ; python_version >= '3.10'",
            "flask===1.0",
            "  requests==2.31.0  # comment",
        ],
    )
    def test_pinned_not_flagged(self, line):
        assert StaticAnalyzer._classify_requirement(line) is not None
        assert StaticAnalyzer._classify_requirement(line)[1] == "pinned"

    @pytest.mark.parametrize(
        "line",
        [
            "requests",
            "requests>=2.31.0",
            "requests>2",
            "requests~=2.31.0",
            "requests!=2.0",
            "requests<3",
            "requests[security]>=2.31.0",
            "requests>=2.0 ; python_version < '3.11'",
        ],
    )
    def test_unpinned_flagged(self, line):
        result = StaticAnalyzer._classify_requirement(line)
        assert result is not None
        assert result[1] == "unpinned"

    @pytest.mark.parametrize("line", ["requests==2.*", "django==3.2.*"])
    def test_wildcard_pins(self, line):
        result = StaticAnalyzer._classify_requirement(line)
        assert result is not None
        assert result[1] == "wildcard"

    @pytest.mark.parametrize(
        "line",
        [
            "",
            "   ",
            "# just a comment",
            "-r base.txt",
            "--hash=sha256:abcdef",
            "-e .",
            "git+https://github.com/psf/requests.git@main#egg=requests",
            "requests @ https://example.com/requests-2.31.0.tar.gz",
        ],
    )
    def test_non_requirements_ignored(self, line):
        assert StaticAnalyzer._classify_requirement(line) is None


class TestDependencyPinningFindings:
    """Integration tests over synthetic skills."""

    def test_unpinned_requirements_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: dep-test\ndescription: A test skill\n---\n# dep-test\n",
                "requirements.txt": "requests>=2.31.0\nhttpx>=0.27.0\n",
            }
        )
        findings = analyzer._check_dependency_pinning(skill)
        assert len(findings) == 2
        assert all(f.rule_id == _RULE_ID for f in findings)
        assert all(f.category == ThreatCategory.SUPPLY_CHAIN_ATTACK for f in findings)
        assert all(f.severity == Severity.MEDIUM for f in findings)

    def test_pinned_requirements_clean(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: dep-test\ndescription: A test skill\n---\n# dep-test\n",
                "requirements.txt": "requests==2.31.0\nhttpx==0.27.0\n",
            }
        )
        assert analyzer._check_dependency_pinning(skill) == []

    def test_wildcard_pin_is_low_severity(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: dep-test\ndescription: A test skill\n---\n# dep-test\n",
                "requirements.txt": "requests==2.*\n",
            }
        )
        findings = analyzer._check_dependency_pinning(skill)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_lockfile_suppresses_findings(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: dep-test\ndescription: A test skill\n---\n# dep-test\n",
                "requirements.txt": "requests>=2.31.0\n",
                "uv.lock": "# resolved lockfile\n",
            }
        )
        assert analyzer._check_dependency_pinning(skill) == []

    def test_dev_requirements_scanned(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": "---\nname: dep-test\ndescription: A test skill\n---\n# dep-test\n",
                "requirements-dev.txt": "pytest>=8\n",
            }
        )
        findings = analyzer._check_dependency_pinning(skill)
        assert len(findings) == 1
        assert findings[0].file_path == "requirements-dev.txt"

    def test_manifest_metadata_dependencies(self, analyzer, make_skill):
        skill = make_skill({"SKILL.md": "---\nname: dep-test\ndescription: A test skill\n---\n# dep-test\n"})
        skill.manifest.metadata = {"dependencies": ["requests>=2", "flask==2.0.0"]}
        findings = analyzer._check_dependency_pinning(skill)
        assert len(findings) == 1
        assert "requests" in findings[0].description


_SKILL_MD = "---\nname: dep-test\ndescription: A test skill\n---\n# dep-test\n"


class TestManifestSourceCoverage:
    """Dependencies declared outside requirements.txt must also be scanned."""

    @requires_tomllib
    def test_pyproject_dependencies_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "pyproject.toml": (
                    "[project]\n"
                    'name = "s"\n'
                    'dependencies = ["requests>=2.0", "flask==2.0.0"]\n'
                    "\n[project.optional-dependencies]\n"
                    'dev = ["pytest>=8"]\n'
                ),
            }
        )
        findings = analyzer._check_dependency_pinning(skill)
        flagged = {f.description.split("'")[1] for f in findings}
        assert flagged == {"requests", "pytest"}
        assert all(f.file_path == "pyproject.toml" for f in findings)

    @requires_tomllib
    def test_pyproject_all_pinned_clean(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "pyproject.toml": '[project]\nname = "s"\ndependencies = ["requests==2.31.0"]\n',
            }
        )
        assert analyzer._check_dependency_pinning(skill) == []

    def test_setup_cfg_install_requires_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "setup.cfg": "[options]\ninstall_requires =\n    requests>=2.0\n    flask==2.0.0\n",
            }
        )
        findings = analyzer._check_dependency_pinning(skill)
        assert len(findings) == 1
        assert "requests" in findings[0].description
        assert findings[0].file_path == "setup.cfg"

    def test_setup_py_install_requires_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "setup.py": (
                    "from setuptools import setup\n"
                    "setup(name='s', install_requires=['requests>=2.0', 'flask==2.0.0'])\n"
                ),
            }
        )
        findings = analyzer._check_dependency_pinning(skill)
        assert len(findings) == 1
        assert "requests" in findings[0].description
        assert findings[0].file_path == "setup.py"

    @requires_tomllib
    def test_pipfile_packages_flagged(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "Pipfile": (
                    "[packages]\n"
                    'requests = "*"\n'
                    'flask = "==2.0.0"\n'
                    'httpx = {version = ">=0.27"}\n'
                    "\n[dev-packages]\n"
                    'pytest = "==8.0.0"\n'
                ),
            }
        )
        findings = analyzer._check_dependency_pinning(skill)
        flagged = {f.description.split("'")[1] for f in findings}
        assert flagged == {"requests", "httpx"}

    @requires_tomllib
    def test_pipfile_vcs_reference_skipped(self, analyzer, make_skill):
        skill = make_skill(
            {
                "SKILL.md": _SKILL_MD,
                "Pipfile": '[packages]\nrequests = {git = "https://github.com/psf/requests.git"}\n',
            }
        )
        assert analyzer._check_dependency_pinning(skill) == []
