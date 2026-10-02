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

"""A requested LLM analysis that cannot be built fails the scan instead of running static only."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from skill_scanner.core.analyzer_factory import AnalyzerConfigurationError, build_analyzers
from skill_scanner.core.scan_policy import ScanPolicy

SAFE_SKILL_DIR = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"


@pytest.fixture(autouse=True)
def _no_llm_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("SKILL_SCANNER_LLM_API_KEY", "SKILL_SCANNER_LLM_MODEL", "SKILL_SCANNER_LLM_PROVIDER"):
        monkeypatch.delenv(name, raising=False)


def test_factory_raises_when_llm_cannot_be_built() -> None:
    with pytest.raises(AnalyzerConfigurationError, match="SKILL_SCANNER_LLM_API_KEY"):
        build_analyzers(ScanPolicy.default(), use_llm=True)


def test_factory_without_llm_is_unchanged() -> None:
    names = {analyzer.get_name() for analyzer in build_analyzers(ScanPolicy.default())}
    assert "llm" not in names


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("SKILL_SCANNER_LLM")}
    return subprocess.run(
        [sys.executable, "-m", "skill_scanner.cli.cli", *args],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_cli_use_llm_without_key_exits_with_configuration_error() -> None:
    proc = _run_cli("scan", str(SAFE_SKILL_DIR), "--use-llm", "--format", "json")
    assert proc.returncode == 2
    assert "LLM analyzer could not be loaded" in proc.stderr
    assert proc.stdout.strip() == ""


def test_cli_unknown_policy_exits_with_configuration_error() -> None:
    proc = _run_cli("scan", str(SAFE_SKILL_DIR), "--policy", "no-such-policy")
    assert proc.returncode == 2
    assert "low-noise" in proc.stderr


def test_api_use_llm_without_key_is_a_client_error() -> None:
    pytest.importorskip("fastapi")
    import tempfile

    from fastapi.testclient import TestClient

    from skill_scanner.api import router
    from skill_scanner.api.api import app

    original = router._ALLOWED_ROOTS
    router._ALLOWED_ROOTS = [Path.cwd().resolve(), Path(tempfile.gettempdir()).resolve()]
    try:
        response = TestClient(app).post("/scan", json={"skill_directory": str(SAFE_SKILL_DIR), "use_llm": True})
    finally:
        router._ALLOWED_ROOTS = original
    assert response.status_code == 400
    assert "LLM analyzer could not be loaded" in response.json()["detail"]
