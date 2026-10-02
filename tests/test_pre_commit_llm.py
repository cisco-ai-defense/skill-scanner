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

"""The pre-commit hook can run the LLM judge, and fails closed when it cannot."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from skill_scanner.core.analyzer_factory import AnalyzerConfigurationError
from skill_scanner.hooks import pre_commit

SAFE_SKILL_DIR = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"


@pytest.fixture(autouse=True)
def _no_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SKILL_SCANNER_LLM_API_KEY", "SKILL_SCANNER_LLM_MODEL", "SKILL_SCANNER_LLM_PROVIDER"):
        monkeypatch.delenv(name, raising=False)


def test_llm_keys_default_off(tmp_path: Path) -> None:
    config = pre_commit.load_config(tmp_path)
    assert config["use_llm"] is False
    assert config["llm_model"] is None
    assert config["llm_provider"] is None


def test_llm_config_reaches_the_analyzer_factory() -> None:
    config = {
        **pre_commit.DEFAULT_CONFIG,
        "use_llm": True,
        "llm_model": "claude-sonnet-5-5",
        "llm_provider": "anthropic",
    }
    with patch("skill_scanner.core.analyzer_factory.build_analyzers", return_value=[]) as build:
        pre_commit.scan_skill(SAFE_SKILL_DIR, config)

    kwargs = build.call_args.kwargs
    assert kwargs["use_llm"] is True
    assert kwargs["llm_model"] == "claude-sonnet-5-5"
    assert kwargs["llm_provider"] == "anthropic"


def test_unset_model_and_provider_fall_back_to_env() -> None:
    config = {**pre_commit.DEFAULT_CONFIG, "use_llm": True}
    with patch("skill_scanner.core.analyzer_factory.build_analyzers", return_value=[]) as build:
        pre_commit.scan_skill(SAFE_SKILL_DIR, config)

    assert build.call_args.kwargs["llm_model"] is None
    assert build.call_args.kwargs["llm_provider"] is None


def test_unbuildable_judge_raises_instead_of_scanning_rules_only() -> None:
    with pytest.raises(AnalyzerConfigurationError):
        pre_commit.scan_skill(SAFE_SKILL_DIR, {**pre_commit.DEFAULT_CONFIG, "use_llm": True})


def test_hook_exits_2_when_the_judge_cannot_be_built(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    skill_dir = tmp_path / ".claude" / "skills" / "formatter"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text("---\nname: formatter\ndescription: Formats code.\n---\n\nFormats code.\n")
    (tmp_path / ".skill_scannerrc").write_text(json.dumps({"use_llm": True}))
    monkeypatch.chdir(tmp_path)

    exit_code = pre_commit.main(["--scan-all"])

    assert exit_code == pre_commit.EXIT_CONFIGURATION_ERROR == 2
    assert "LLM analyzer could not be loaded" in capsys.readouterr().err
