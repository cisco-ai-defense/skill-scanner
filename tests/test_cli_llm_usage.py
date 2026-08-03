# Copyright 2026 Cisco Systems, Inc.
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

"""
Integration tests: does ScanResult.llm_usage end up combining BOTH the
per-file LLM analyzer's token spend AND the MetaAnalyzer's token spend, when
driven through the real CLI entry points (`scan_command` / `scan_all_command`)?

These exercise the exact production code path (cli.py builds analyzers, runs
scanner.scan_skill()/scan_directory(), then runs MetaAnalyzer.analyze_with_findings()
separately) rather than calling internal helpers directly, to guard against the
llm_usage aggregation silently regressing to only counting the per-file analyzer
(see merge_meta_analyzer_usage in meta_analyzer.py).
"""

import argparse
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from skill_scanner.cli import cli

SAFE_SKILL_DIR = Path(__file__).parent.parent / "evals" / "test_skills" / "safe" / "simple-formatter"


def _fake_response(prompt_tokens: int, completion_tokens: int, content: str) -> MagicMock:
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    response.usage = MagicMock(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=prompt_tokens + completion_tokens,
    )
    return response


LLM_FINDING_CONTENT = (
    '{"overall_assessment": "unsafe", '
    '"findings": [{"title": "t", "description": "d", "severity": "high", '
    '"aitech": "AITech-1.1", "confidence": 0.9, "remediation": "r"}]}'
)
# Covers _index 0-9 unconditionally so meta_analyzer's coverage check never
# triggers a second "follow-up" LLM call regardless of how many findings the
# static + LLM analyzers happen to produce on the fixture skill(s).
_VALIDATED = ", ".join(
    f'{{"_index": {i}, "confidence": "HIGH", "confidence_reason": "r", "exploitability": "e", "impact": "i"}}'
    for i in range(10)
)
META_RESPONSE_CONTENT = (
    '{"overall_risk_assessment": {"risk_level": "HIGH", "summary": "s"}, '
    f'"validated_findings": [{_VALIDATED}], '
    '"false_positives": [], "correlations": [], '
    '"missed_threats": [], "recommendations": []}'
)


def _base_args(**overrides) -> argparse.Namespace:
    defaults = dict(
        skill_directory=str(SAFE_SKILL_DIR),
        output=None,
        format=None,
        use_llm=True,
        enable_meta=True,
        lenient=False,
        skill_file=None,
        rule_packs=None,
        custom_rules=None,
        use_behavioral=False,
        use_virustotal=False,
        use_aidefense=False,
        use_trigger=False,
        llm_provider=None,
        llm_consensus_runs=1,
        llm_max_tokens=None,
        verbose=True,  # keep meta-flagged findings in output for inspection
        policy=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestCLIScanCommandLLMUsage:
    """`skill-scanner scan` (single skill) with LLM analyzer + meta-analysis."""

    def test_llm_usage_combines_analyzer_and_meta_analyzer_spend(self, monkeypatch) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_API_KEY", "test-key")
        monkeypatch.setenv("SKILL_SCANNER_LLM_MODEL", "claude-3-5-sonnet-20241022")

        llm_response = _fake_response(1000, 200, LLM_FINDING_CONTENT)
        meta_response = _fake_response(5000, 500, META_RESPONSE_CONTENT)

        with (
            patch(
                "skill_scanner.core.analyzers.llm_request_handler.acompletion",
                AsyncMock(return_value=llm_response),
            ),
            patch(
                "skill_scanner.core.analyzers.meta_analyzer.acompletion",
                AsyncMock(return_value=meta_response),
            ),
        ):
            args = _base_args()
            exit_code = cli.scan_command(args)

        assert exit_code == 0
        result = args._result_or_report

        assert "llm_analyzer" in result.analyzers_used
        assert "meta_analyzer" in result.analyzers_used
        assert result.llm_usage == {
            "input_tokens": 1000 + 5000,
            "output_tokens": 200 + 500,
            "total_tokens": 1200 + 5500,
        }

    def test_llm_usage_omitted_when_llm_disabled(self, monkeypatch) -> None:
        monkeypatch.delenv("SKILL_SCANNER_LLM_API_KEY", raising=False)
        args = _base_args(use_llm=False, enable_meta=False)

        exit_code = cli.scan_command(args)

        assert exit_code == 0
        result = args._result_or_report
        assert result.llm_usage is None


class TestCLIScanAllCommandLLMUsage:
    """`skill-scanner scan-all` (batch) reuses one MetaAnalyzer across skills --
    verify merge_meta_analyzer_usage attributes tokens to the right ScanResult
    and doesn't leak totals across skills in the loop.
    """

    def test_llm_usage_combined_per_skill_in_batch_scan(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv("SKILL_SCANNER_LLM_API_KEY", "test-key")
        monkeypatch.setenv("SKILL_SCANNER_LLM_MODEL", "claude-3-5-sonnet-20241022")

        # Two independent skill directories so scan_directory() finds 2 skills.
        for name in ("skill-a", "skill-b"):
            skill_dir = tmp_path / name
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(
                f"---\nname: {name}\ndescription: test skill {name}.\n---\n\n# {name}\n"
            )

        llm_response = _fake_response(1000, 200, LLM_FINDING_CONTENT)
        meta_response = _fake_response(5000, 500, META_RESPONSE_CONTENT)

        with (
            patch(
                "skill_scanner.core.analyzers.llm_request_handler.acompletion",
                AsyncMock(return_value=llm_response),
            ),
            patch(
                "skill_scanner.core.analyzers.meta_analyzer.acompletion",
                AsyncMock(return_value=meta_response),
            ),
        ):
            args = _base_args(skills_directory=str(tmp_path), recursive=False)
            exit_code = cli.scan_all_command(args)

        assert exit_code == 0
        report = args._result_or_report
        assert report.total_skills_scanned == 2

        for result in report.scan_results:
            assert result.llm_usage == {
                "input_tokens": 1000 + 5000,
                "output_tokens": 200 + 500,
                "total_tokens": 1200 + 5500,
            }
