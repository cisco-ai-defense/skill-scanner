# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Deterministic contracts for local-only primary and Meta LLM analysis."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import subprocess
import sys
import textwrap
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from jsonschema import Draft202012Validator

from skill_scanner.core.analyzers import llm_request_handler
from skill_scanner.core.analyzers.llm_analyzer import (
    _MAX_STRUCTURED_CONTEXT_CHARS,
    LLMAnalyzer,
)
from skill_scanner.core.analyzers.llm_prompt_builder import source_evidence_id
from skill_scanner.core.analyzers.llm_provider_config import ProviderConfig
from skill_scanner.core.analyzers.llm_request_handler import (
    LLMRequestHandler,
    LLMResponseTruncatedError,
)
from skill_scanner.core.analyzers.llm_response_parser import ResponseParser
from skill_scanner.core.analyzers.meta_analyzer import (
    MetaAnalysisParseError,
    MetaAnalysisResult,
    MetaAnalyzer,
    _meta_evidence_id,
    _meta_request_sha256,
    _ollama_meta_response_format,
    _sha256_text,
    meta_contract_repair_policy_identity,
    ollama_meta_response_schema_sha256,
)
from skill_scanner.core.models import Finding, Severity, Skill, SkillFile, SkillManifest, ThreatCategory


def _skill(tmp_path: Path) -> Skill:
    skill_dir = tmp_path / "skill"
    skill_dir.mkdir(exist_ok=True)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text("---\nname: sample\ndescription: sample\n---\nDo the safe task.\n")
    return Skill(
        directory=skill_dir,
        manifest=SkillManifest(
            name="sample",
            description="sample",
            allowed_tools=["Read", "Bash"],
        ),
        skill_md_path=skill_md,
        instruction_body="Do the safe task.",
        files=[],
    )


def _finding(
    *,
    index: int = 0,
    analyzer: str = "static",
    severity: Severity = Severity.HIGH,
    context_kind: str | None = None,
    flows: list[dict] | None = None,
) -> Finding:
    semantic_facts: dict[str, object] = {}
    if context_kind is not None:
        semantic_facts["context_kind"] = context_kind
    if flows is not None:
        semantic_facts["flows"] = flows
    return Finding(
        id=f"finding-{index}",
        rule_id=f"RULE_{index:03d}",
        category=ThreatCategory.COMMAND_INJECTION,
        severity=severity,
        title=f"Finding {index}",
        description=f"Description {index} super-secret-value",
        file_path=f"scripts/file_{index}.py",
        line_number=index + 1,
        snippet="super-secret-value",
        analyzer=analyzer,
        metadata={"semantic_facts": semantic_facts} if semantic_facts else {},
    )


def _valid_primary(evidence_id: str) -> dict[str, object]:
    return {
        "findings": [
            {
                "severity": "HIGH",
                "verdict": "TRUE_POSITIVE",
                "category": "command_injection",
                "confidence": "HIGH",
                "evidence_ids": [evidence_id],
                "aitech": "AITech-9.1",
                "aisubtech": None,
                "title": "Connected execution chain",
                "description": "A concrete chain is present.",
                "location": "SKILL.md:4",
                "evidence": "The cited artifact establishes the chain.",
                "remediation": "Remove the unsafe chain.",
            }
        ],
        "overall_assessment": "Concrete execution behavior is present.",
        "verdict": "MALICIOUS",
        "primary_threats": ["command_injection"],
    }


def _valid_meta(index: int, evidence_id: str) -> dict[str, object]:
    return {
        "validated_findings": [
            {
                "_index": index,
                "confidence": "MEDIUM",
                "confidence_reason": "The active context supports retaining the finding.",
                "exploitability": "Requires the documented trigger.",
                "impact": "Could execute a command.",
                "evidence_ids": [evidence_id],
                "chain": None,
            }
        ],
        "false_positives": [],
        "missed_threats": [],
        "priority_order": [index],
        "correlations": [],
        "recommendations": [],
        "overall_risk_assessment": {
            "risk_level": "HIGH",
            "summary": "The existing finding is retained.",
            "top_priority": "Review the active command path.",
            "skill_verdict": "SUSPICIOUS",
            "verdict_reasoning": "Evidence supports risk but not a new Meta conclusion.",
            "meta_delta": "NONE_SUPPORTED",
        },
    }


def _false_positive_meta(index: int, evidence_id: str) -> dict[str, object]:
    value = _valid_meta(index, evidence_id)
    value["validated_findings"] = []
    value["false_positives"] = [
        {
            "_index": index,
            "false_positive_reason": "The cited context establishes an inert documented example.",
            "evidence_ids": [evidence_id],
        }
    ]
    assessment = value["overall_risk_assessment"]
    assessment["meta_delta"] = "FALSE_POSITIVE_SUPPRESSED"  # type: ignore[index]
    return value


def _missed_threat_meta(index: int, evidence_id: str) -> dict[str, object]:
    value = _valid_meta(index, evidence_id)
    value["missed_threats"] = [
        {
            "title": "Evidence-backed missed threat",
            "description": "The cited evidence establishes an omitted command-execution risk.",
            "severity": "HIGH",
            "category": "command_injection",
            "aitech": "AITech-9.1",
            "location": "SKILL.md",
            "evidence_ids": [evidence_id],
        }
    ]
    assessment = value["overall_risk_assessment"]
    assessment["meta_delta"] = "MISSED_THREAT_NAMED"  # type: ignore[index]
    return value


def _chain_meta(first_id: str, second_id: str) -> dict[str, object]:
    value = _valid_meta(0, first_id)
    second = _valid_meta(1, second_id)["validated_findings"][0]  # type: ignore[index]
    value["validated_findings"].append(second)  # type: ignore[union-attr]
    value["validated_findings"][0]["chain"] = ["sensitive source", "network sink"]  # type: ignore[index]
    value["correlations"] = [
        {
            "finding_indices": [0, 1],
            "relationship": "The cited findings establish a concrete source-to-sink chain.",
            "combined_severity": "HIGH",
            "evidence_ids": [first_id, second_id],
        }
    ]
    value["priority_order"] = [0, 1]
    assessment = value["overall_risk_assessment"]
    assessment["meta_delta"] = "CHAIN_VALIDATED"  # type: ignore[index]
    return value


def test_deterministic_scan_import_and_scan_do_not_import_litellm_or_open_network() -> None:
    """A non-LLM scan must not initialize LiteLLM or open a socket."""

    script = textwrap.dedent(
        """
        import pathlib
        import sys
        import tempfile

        def deny_network(event, args):
            if event in {"socket.connect", "socket.bind"}:
                raise RuntimeError(f"network audit event: {event}")

        sys.addaudithook(deny_network)
        from skill_scanner.core.analyzers.static import StaticAnalyzer
        from skill_scanner.core.rule_registry import RuleRegistry
        from skill_scanner.core.scanner import SkillScanner
        from skill_scanner.core.scan_policy import ScanPolicy

        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "SKILL.md").write_text(
                "---\\nname: safe\\ndescription: safe formatter\\n---\\nFormat the supplied text.\\n",
                encoding="utf-8",
            )
            policy = ScanPolicy.default()
            policy.cel.mode = type(policy.cel.mode).OFF
            scanner = SkillScanner(
                analyzers=[StaticAnalyzer(policy=policy)],
                policy=policy,
                rule_registry=RuleRegistry(),
                cel_rules=[],
            )
            scanner.scan_skill(root)

        assert "litellm" not in sys.modules
        assert not any(name.startswith("litellm.") for name in sys.modules)
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).resolve().parents[1],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr


def test_lazy_litellm_loader_forces_local_cost_map_before_import(monkeypatch) -> None:
    sentinel = object()
    observed: dict[str, str | None] = {}

    def fake_import(name: str) -> SimpleNamespace:
        observed["module"] = name
        observed["cost_map"] = os.environ.get("LITELLM_LOCAL_MODEL_COST_MAP")
        return SimpleNamespace(acompletion=sentinel)

    monkeypatch.setattr(llm_request_handler, "acompletion", None)
    monkeypatch.setattr(llm_request_handler, "LITELLM_AVAILABLE", True)
    monkeypatch.setattr(llm_request_handler.importlib, "import_module", fake_import)
    monkeypatch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "False")

    assert llm_request_handler._get_litellm_acompletion(local_only=True) is sentinel
    assert observed == {"module": "litellm", "cost_map": "True"}


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:11434",
        "https://127.0.0.1:11434",
        "http://127.0.0.2:11434",
        "http://[::ffff:127.0.0.1]:11434",
        "http://[::1%25lo0]:11434",
        "http://user:pass@127.0.0.1:11434",
        "http://127.0.0.1:11434/v1",
    ],
)
def test_ollama_rejects_nonliteral_or_ambiguous_endpoint(base_url: str) -> None:
    with pytest.raises(ValueError, match="Ollama base URL"):
        ProviderConfig(model="ollama/test", base_url=base_url, provider="ollama")


@pytest.mark.parametrize("base_url", ["http://127.0.0.1:11434", "http://[::1]:11434"])
def test_ollama_accepts_literal_loopback_endpoint(base_url: str) -> None:
    config = ProviderConfig(model="ollama/test", base_url=base_url, provider="ollama")
    assert config.is_ollama is True
    assert config.base_url == base_url
    assert config.get_request_params()["api_base"] == base_url


def test_structured_primary_context_is_bounded_normalized_and_deterministic() -> None:
    analyzer = LLMAnalyzer(
        model="ollama/test",
        provider="ollama",
        base_url="http://127.0.0.1:11434",
    )
    findings = [_finding(index=index) for index in range(100)]
    inventory = {
        "total_files": 10**9,
        "types": {f"type-{index}-" + "x" * 100: index for index in range(100)},
        "unreferenced_scripts": [f"scripts/{index}-" + "x" * 1000 for index in range(100)],
        "untrusted_map": {"super-secret-value": "must-not-project"},
    }
    magic_mismatches = [f"magic/{index}-" + "y" * 1000 for index in range(100)]
    manifest_capabilities = {
        "allowed_tools": [f"Tool-{index}-" + "z" * 100 for index in range(100)],
        "allowed_tools_declared": True,
        "compatibility_declared": False,
    }

    analyzer.set_enrichment_context(
        file_inventory=inventory,
        magic_mismatches=magic_mismatches,
        static_findings_summary=["super-secret-value"],
        analyzability_score=float("inf"),
        deterministic_findings=findings,
        manifest_capabilities=manifest_capabilities,
    )
    first = analyzer.enrichment_context
    first_ids = set(analyzer._deterministic_evidence_ids)
    analyzer.set_enrichment_context(
        file_inventory=inventory,
        magic_mismatches=magic_mismatches,
        static_findings_summary=["super-secret-value"],
        analyzability_score=float("inf"),
        deterministic_findings=list(reversed(findings)),
        manifest_capabilities=manifest_capabilities,
    )

    assert first == analyzer.enrichment_context
    assert first_ids == analyzer._deterministic_evidence_ids
    assert first is not None and len(first) <= _MAX_STRUCTURED_CONTEXT_CHARS
    assert "super-secret-value" not in first
    projected = json.loads(first)
    assert projected["projection"] == {"complete": False, "truncated": True}
    assert projected["package_facts"]["analyzability_score"] is None
    assert projected["package_facts"]["file_inventory"]["total_files"] == 1_000_000
    assert len(projected["manifest_capabilities"]["allowed_tools"]) <= 64


def test_primary_contract_accepts_known_id_and_rejects_unknown_id() -> None:
    analyzer = LLMAnalyzer(
        model="ollama/test",
        provider="ollama",
        base_url="http://127.0.0.1:11434",
    )
    known = source_evidence_id("SKILL.md")
    analyzer._allowed_evidence_ids = {known}
    analyzer._validate_primary_contract(_valid_primary(known))

    invalid = deepcopy(_valid_primary(known))
    invalid["findings"][0]["evidence_ids"] = ["SRC:0000000000000000"]  # type: ignore[index]
    with pytest.raises(ValueError, match="unknown evidence"):
        analyzer._validate_primary_contract(invalid)


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("severity", "INFO", "severity"),
        ("aitech", "AITech-99.9", "AITech taxonomy"),
        ("aisubtech", "AISubtech-99.9.9", "AISubtech taxonomy"),
        ("title", 7, "title and description"),
    ],
)
def test_primary_contract_rejects_invalid_schema_owned_finding_fields(
    field: str,
    value: object,
    error: str,
) -> None:
    analyzer = LLMAnalyzer(
        model="ollama/test",
        provider="ollama",
        base_url="http://127.0.0.1:11434",
    )
    known = source_evidence_id("SKILL.md")
    analyzer._allowed_evidence_ids = {known}
    invalid = deepcopy(_valid_primary(known))
    invalid["findings"][0][field] = value  # type: ignore[index]

    with pytest.raises(ValueError, match=error):
        analyzer._validate_primary_contract(invalid)


def test_primary_evidence_allowlist_contains_only_artifacts_in_final_prompt(tmp_path: Path) -> None:
    skill_dir = tmp_path / "budgeted-skill"
    references_dir = skill_dir / "references"
    references_dir.mkdir(parents=True)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text("safe instructions", encoding="utf-8")
    included_ref = references_dir / "included.md"
    included_ref.write_text("ref", encoding="utf-8")
    oversized_ref = references_dir / "oversized.md"
    oversized_ref.write_text("r" * 9, encoding="utf-8")
    files = [
        SkillFile(skill_dir / "included.py", "included.py", "python", content="pass"),
        SkillFile(skill_dir / "oversized.py", "oversized.py", "python", content="x" * 9),
        SkillFile(skill_dir / "notes.txt", "notes.txt", "other", content="notes"),
        SkillFile(included_ref, "references/included.md", "markdown", content="ref"),
        SkillFile(oversized_ref, "references/oversized.md", "markdown", content="r" * 9),
    ]
    skill = Skill(
        directory=skill_dir,
        manifest=SkillManifest(name="budgeted", description="budgeted"),
        skill_md_path=skill_md,
        instruction_body="safe instructions",
        files=files,
        referenced_files=["references/included.md", "references/oversized.md"],
    )
    analyzer = LLMAnalyzer(
        model="ollama/test",
        provider="ollama",
        base_url="http://127.0.0.1:11434",
    )
    analyzer.llm_policy.max_code_file_chars = 8
    analyzer.llm_policy.max_referenced_file_chars = 8
    analyzer.request_handler.make_request = AsyncMock(  # type: ignore[method-assign]
        return_value=json.dumps(
            {"findings": [], "overall_assessment": "Safe.", "verdict": "SAFE", "primary_threats": []}
        )
    )

    findings = asyncio.run(analyzer.analyze_async(skill))

    assert not any(finding.rule_id == "LLM_ANALYSIS_FAILED" for finding in findings)
    included_script_id = source_evidence_id("included.py")
    expected = {
        source_evidence_id("MANIFEST"),
        source_evidence_id("SKILL.md"),
        included_script_id,
        source_evidence_id("references/included.md"),
    }
    assert analyzer._allowed_evidence_ids == expected
    messages = analyzer.request_handler.make_request.await_args.args[0]
    prompt = messages[1]["content"]
    assert f"evidence_id={included_script_id}" in prompt
    assert f"evidence_id={source_evidence_id('references/included.md')}" in prompt
    assert f"evidence_id={source_evidence_id('oversized.py')}" not in prompt
    assert f"evidence_id={source_evidence_id('notes.txt')}" not in prompt
    assert f"evidence_id={source_evidence_id('references/oversized.md')}" not in prompt
    analyzer._validate_primary_contract(_valid_primary(included_script_id))
    for omitted_path in ("oversized.py", "notes.txt", "references/oversized.md"):
        with pytest.raises(ValueError, match="unknown evidence"):
            analyzer._validate_primary_contract(_valid_primary(source_evidence_id(omitted_path)))


def _litellm_primary_response(payload: dict[str, object]) -> SimpleNamespace:
    choice = SimpleNamespace(
        message=SimpleNamespace(content=json.dumps(payload)),
        finish_reason="stop",
        provider_specific_fields={},
    )
    return SimpleNamespace(choices=[choice], usage=None)


def test_non_ollama_schema_response_rejects_unknown_request_evidence(tmp_path: Path, monkeypatch) -> None:
    analyzer = LLMAnalyzer(model="gpt-4o", provider="openai", api_key="test-key")
    known = source_evidence_id("SKILL.md")
    invalid = deepcopy(_valid_primary(known))
    invalid["findings"][0]["evidence_ids"] = ["SRC:0000000000000000"]  # type: ignore[index]
    assert list(Draft202012Validator(analyzer.request_handler.response_schema).iter_errors(invalid)) == []

    completion = AsyncMock(return_value=_litellm_primary_response(invalid))
    monkeypatch.setattr(llm_request_handler, "acompletion", completion)

    findings = asyncio.run(analyzer.analyze_async(_skill(tmp_path)))

    assert not analyzer.provider_config.is_ollama
    assert [finding.rule_id for finding in findings] == ["LLM_ANALYSIS_FAILED"]
    assert findings[0].severity == Severity.INFO
    assert analyzer.last_error == "Primary finding cites unknown evidence IDs"
    assert completion.await_count == 1
    assert completion.await_args.kwargs["response_format"]["type"] == "json_schema"


@pytest.mark.parametrize(("field", "value"), [("severity", "INFO"), ("aitech", "AITech-99.9")])
def test_non_ollama_consensus_json_object_fallback_rejects_invalid_schema_fields(
    tmp_path: Path,
    monkeypatch,
    field: str,
    value: object,
) -> None:
    analyzer = LLMAnalyzer(model="gpt-4o", provider="openai", api_key="test-key", max_retries=0)
    analyzer.consensus_runs = 3
    invalid = _valid_primary(source_evidence_id("SKILL.md"))
    invalid["findings"][0][field] = value  # type: ignore[index]
    assert list(Draft202012Validator(analyzer.request_handler.response_schema).iter_errors(invalid))
    schema_error = RuntimeError("Missing required parameter: 'response_format.json_schema'.")
    provider_response = _litellm_primary_response(invalid)
    completion = AsyncMock(side_effect=[schema_error, provider_response, provider_response, provider_response])
    monkeypatch.setattr(llm_request_handler, "acompletion", completion)

    findings = asyncio.run(analyzer.analyze_async(_skill(tmp_path)))

    assert not analyzer.provider_config.is_ollama
    assert [finding.rule_id for finding in findings] == ["LLM_ANALYSIS_FAILED"]
    assert findings[0].severity == Severity.INFO
    assert analyzer.last_error == "Consensus analysis did not produce a valid response majority (0/3 successful runs)"
    assert completion.await_count == 4
    assert completion.await_args_list[0].kwargs["response_format"]["type"] == "json_schema"
    assert completion.await_args_list[1].kwargs["response_format"]["type"] == "json_object"
    assert completion.await_args_list[2].kwargs["response_format"]["type"] == "json_object"
    assert completion.await_args_list[3].kwargs["response_format"]["type"] == "json_object"


def test_json_extractors_handle_braces_in_strings_and_provider_prose() -> None:
    response = 'prefix {"overall_assessment":"literal } and { text","findings":[]} trailing'
    assert ResponseParser.parse(response)["overall_assessment"] == "literal } and { text"

    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    parsed = analyzer._extract_json_from_response('prefix {"summary":"literal } text"} trailing')
    assert parsed == {"summary": "literal } text"}


def test_primary_rejects_provider_truncation(monkeypatch) -> None:
    config = ProviderConfig(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
        provider="ollama",
    )
    handler = LLMRequestHandler(config, max_retries=0)
    choice = SimpleNamespace(
        message=SimpleNamespace(content='{"findings":'),
        finish_reason="length",
        provider_specific_fields={},
    )
    completion = AsyncMock(return_value=SimpleNamespace(choices=[choice], usage=None))
    monkeypatch.setattr(llm_request_handler, "acompletion", completion)

    with pytest.raises(LLMResponseTruncatedError):
        asyncio.run(handler.make_request([{"role": "user", "content": "analyze"}]))


def test_meta_skips_clear_deterministic_finding_without_model_call(tmp_path: Path) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    analyzer._make_llm_request = AsyncMock()  # type: ignore[method-assign]
    clear = _finding(analyzer="behavioral", severity=Severity.HIGH)

    result = asyncio.run(analyzer.analyze_with_findings(_skill(tmp_path), [clear], ["behavioral"]))

    assert result.routing == {
        "decision": "skip",
        "reason": "clear_deterministic_findings",
        "ambiguous_indices": [],
        "contract_repair": {"attempted": 0, "succeeded": 0, "failed": 0, "error_codes": {}},
    }
    analyzer._make_llm_request.assert_not_awaited()


def test_meta_routes_top_level_documentation_context_to_model(tmp_path: Path) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding(context_kind="documentation")
    evidence_id = _meta_evidence_id(finding)
    analyzer._make_llm_request = AsyncMock(  # type: ignore[method-assign]
        return_value=json.dumps(_valid_meta(0, evidence_id))
    )

    result = asyncio.run(analyzer.analyze_with_findings(_skill(tmp_path), [finding], ["static"]))

    assert result.routing == {
        "decision": "run",
        "reason": "ambiguous_finding_context",
        "ambiguous_indices": [0],
        "contract_repair": {"attempted": 0, "succeeded": 0, "failed": 0, "error_codes": {}},
    }
    analyzer._make_llm_request.assert_awaited_once()
    assert len(result.validated_findings) == 1


def test_non_ollama_meta_rejects_parseable_index_only_false_positive(tmp_path: Path) -> None:
    analyzer = MetaAnalyzer(model="gpt-4o", api_key="test-key")
    finding = _finding(context_kind="documentation")
    evidence_id = _meta_evidence_id(finding)
    invalid = _false_positive_meta(0, evidence_id)
    invalid["false_positives"] = [{"_index": 0}]
    analyzer._make_llm_request = AsyncMock(return_value=json.dumps(invalid))  # type: ignore[method-assign]

    result = asyncio.run(analyzer.analyze_with_findings(_skill(tmp_path), [finding], ["static"]))

    assert not analyzer.is_ollama
    assert result.false_positives == []
    assert len(result.validated_findings) == 1
    assert result.validated_findings[0]["meta_analysis_degraded"] is True
    assert [warning["code"] for warning in result.analysis_warnings] == ["META_BATCH_PARSE_FAILED"]
    assert result.routing["contract_repair"] == {
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "error_codes": {},
    }


def test_meta_evidence_allowlist_contains_only_rendered_artifacts(tmp_path: Path) -> None:
    skill_dir = tmp_path / "meta-budgeted-skill"
    references_dir = skill_dir / "references"
    references_dir.mkdir(parents=True)
    skill_md = skill_dir / "SKILL.md"
    skill_md.write_text("safe instructions", encoding="utf-8")
    included_script = skill_dir / "included.py"
    included_script.write_text("pass", encoding="utf-8")
    oversized_script = skill_dir / "oversized.py"
    oversized_script.write_text("x" * 9, encoding="utf-8")
    notes = skill_dir / "notes.txt"
    notes.write_text("notes", encoding="utf-8")
    referenced = references_dir / "guide.md"
    referenced.write_text("reference", encoding="utf-8")
    skill = Skill(
        directory=skill_dir,
        manifest=SkillManifest(name="meta-budgeted", description="meta-budgeted"),
        skill_md_path=skill_md,
        instruction_body="safe instructions",
        files=[
            SkillFile(included_script, "included.py", "python", size_bytes=4),
            SkillFile(oversized_script, "oversized.py", "python", size_bytes=9),
            SkillFile(notes, "notes.txt", "other", size_bytes=5),
            SkillFile(referenced, "references/guide.md", "markdown", size_bytes=9),
        ],
        referenced_files=["references/guide.md"],
    )
    analyzer = MetaAnalyzer(model="ollama/test", base_url="http://127.0.0.1:11434")
    analyzer.llm_policy.max_code_file_chars = 8
    analyzer.llm_policy.meta_budget_multiplier = 1.0

    context, skipped = analyzer._build_skill_context(skill)

    included_id = source_evidence_id("included.py")
    assert analyzer._allowed_evidence_ids == {
        source_evidence_id("MANIFEST"),
        source_evidence_id("SKILL.md"),
        included_id,
    }
    assert f"evidence_id={included_id}" in context
    for omitted_path in ("oversized.py", "notes.txt", "references/guide.md"):
        assert f"evidence_id={source_evidence_id(omitted_path)}" not in context
        assert source_evidence_id(omitted_path) not in analyzer._allowed_evidence_ids
    assert [item["path"] for item in skipped] == ["oversized.py"]


def test_meta_finding_allowlist_contains_only_rendered_evidence_ids() -> None:
    analyzer = MetaAnalyzer(model="ollama/test", base_url="http://127.0.0.1:11434")
    finding = _finding()
    metadata_ids = [source_evidence_id(f"artifact-{index}") for index in range(16)]
    finding.metadata = {"evidence_ids": metadata_ids}

    serialized = json.loads(analyzer._serialize_findings([finding]))

    rendered_ids = set(serialized[0]["evidence_ids"])
    assert len(rendered_ids) == 16
    assert analyzer._allowed_evidence_ids == rendered_ids
    assert {_meta_evidence_id(finding), *metadata_ids} - rendered_ids


@pytest.mark.parametrize("assessment_defect", ["missing", "extra"])
def test_local_meta_repairs_nested_assessment_contract_once(tmp_path: Path, assessment_defect: str) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding(context_kind="documentation")
    evidence_id = _meta_evidence_id(finding)
    invalid = _valid_meta(0, evidence_id)
    assessment = invalid["overall_risk_assessment"]
    if assessment_defect == "missing":
        del assessment["top_priority"]  # type: ignore[index]
    else:
        assessment["raw_response_secret_marker"] = "must-not-reflect"  # type: ignore[index]
    analyzer._make_llm_request = AsyncMock(  # type: ignore[method-assign]
        side_effect=[json.dumps(invalid), json.dumps(_valid_meta(0, evidence_id))]
    )

    result = asyncio.run(analyzer.analyze_with_findings(_skill(tmp_path), [finding], ["static"]))

    assert result.analysis_warnings == []
    assert result.routing["contract_repair"] == {
        "attempted": 1,
        "succeeded": 1,
        "failed": 0,
        "error_codes": {"META_CONTRACT_ASSESSMENT_FIELDS": 1},
    }
    assert analyzer.contract_repair_telemetry == result.routing["contract_repair"]
    assert analyzer._make_llm_request.await_count == 2
    repair_prompt = analyzer._make_llm_request.await_args_list[1].args[1]
    assert "Stable error code: `META_CONTRACT_ASSESSMENT_FIELDS`" in repair_prompt
    assert "overall_risk_assessment must contain exactly" in repair_prompt
    assert "raw_response_secret_marker" not in repair_prompt
    assert "must-not-reflect" not in repair_prompt


def test_local_meta_repairs_none_supported_contradiction_once(tmp_path: Path) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding(context_kind="documentation")
    evidence_id = _meta_evidence_id(finding)
    contradiction = _false_positive_meta(0, evidence_id)
    contradiction["overall_risk_assessment"]["meta_delta"] = "NONE_SUPPORTED"  # type: ignore[index]
    corrected = _false_positive_meta(0, evidence_id)
    analyzer._make_llm_request = AsyncMock(  # type: ignore[method-assign]
        side_effect=[json.dumps(contradiction), json.dumps(corrected)]
    )

    result = asyncio.run(analyzer.analyze_with_findings(_skill(tmp_path), [finding], ["static"]))

    assert result.analysis_warnings == []
    assert result.overall_risk_assessment["meta_delta"] == "FALSE_POSITIVE_SUPPRESSED"
    assert result.routing["contract_repair"] == {
        "attempted": 1,
        "succeeded": 1,
        "failed": 0,
        "error_codes": {"META_CONTRACT_DELTA_CONSISTENCY": 1},
    }


def test_local_meta_second_contract_failure_remains_fail_closed(tmp_path: Path) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding(context_kind="documentation")
    initial_response = '{"validated_findings": ["initial-raw-secret"'
    repair_response = '{"validated_findings": ["repair-raw-secret"'
    analyzer._make_llm_request = AsyncMock(  # type: ignore[method-assign]
        side_effect=[initial_response, repair_response]
    )

    result = asyncio.run(analyzer.analyze_with_findings(_skill(tmp_path), [finding], ["static"]))

    assert [warning["code"] for warning in result.analysis_warnings] == ["META_BATCH_PARSE_FAILED"]
    assert result.routing["contract_repair"] == {
        "attempted": 1,
        "succeeded": 0,
        "failed": 1,
        "error_codes": {"META_CONTRACT_JSON_OBJECT": 1},
    }
    assert analyzer._make_llm_request.await_count == 2
    diagnostic = result.analysis_warnings[0]["failure_diagnostic"]
    initial_request = analyzer._make_llm_request.await_args_list[0].args[1]
    repair_request = analyzer._make_llm_request.await_args_list[1].args[1]
    assert diagnostic == {
        "outer_error_code": "META_BATCH_PARSE_FAILED",
        "inner_error_code": "META_CONTRACT_JSON_OBJECT",
        "request_sha256": _meta_request_sha256(analyzer.system_prompt, initial_request),
        "response_sha256": _sha256_text(initial_response),
        "repair_attempted": 1,
        "repair_succeeded": 0,
        "repair_request_sha256": _meta_request_sha256(analyzer.system_prompt, repair_request),
        "repair_response_sha256": _sha256_text(repair_response),
        "repair_error_code": "META_CONTRACT_JSON_OBJECT",
    }
    serialized_diagnostic = json.dumps(diagnostic, sort_keys=True)
    assert "initial-raw-secret" not in serialized_diagnostic
    assert "repair-raw-secret" not in serialized_diagnostic


def test_local_meta_contract_repair_timeout_remains_fail_closed(tmp_path: Path) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding(context_kind="documentation")
    analyzer._make_llm_request = AsyncMock(  # type: ignore[method-assign]
        side_effect=['{"validated_findings": [', TimeoutError("local repair timeout")]
    )

    result = asyncio.run(analyzer.analyze_with_findings(_skill(tmp_path), [finding], ["static"]))

    assert [warning["code"] for warning in result.analysis_warnings] == ["META_BATCH_PARSE_FAILED"]
    assert result.routing["contract_repair"]["attempted"] == 1
    assert result.routing["contract_repair"]["succeeded"] == 0
    assert result.routing["contract_repair"]["failed"] == 1
    assert analyzer._make_llm_request.await_count == 2
    diagnostic = result.analysis_warnings[0]["failure_diagnostic"]
    assert diagnostic["inner_error_code"] == "META_CONTRACT_JSON_OBJECT"
    assert diagnostic["repair_error_code"] == "META_REPAIR_TIMEOUT"
    assert diagnostic["repair_attempted"] == 1
    assert diagnostic["repair_succeeded"] == 0
    assert "request_sha256" in diagnostic
    assert "response_sha256" in diagnostic
    assert "repair_request_sha256" in diagnostic
    assert "repair_response_sha256" not in diagnostic


@pytest.mark.parametrize("request_error", [TimeoutError("initial timeout"), ConnectionError("runtime unavailable")])
def test_local_meta_transport_or_runtime_error_does_not_trigger_contract_repair(
    tmp_path: Path,
    request_error: Exception,
) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding(context_kind="documentation")
    analyzer._make_llm_request = AsyncMock(side_effect=request_error)  # type: ignore[method-assign]

    result = asyncio.run(analyzer.analyze_with_findings(_skill(tmp_path), [finding], ["static"]))

    assert [warning["code"] for warning in result.analysis_warnings] == ["META_BATCH_REQUEST_FAILED"]
    assert result.routing["contract_repair"] == {
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "error_codes": {},
    }
    analyzer._make_llm_request.assert_awaited_once()


def test_meta_contract_rejects_echoed_finding_fields() -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding()
    evidence_id = _meta_evidence_id(finding)
    analyzer._allowed_evidence_ids = {evidence_id}
    value = _valid_meta(0, evidence_id)
    value["validated_findings"][0]["title"] = "Echoed original title"  # type: ignore[index]

    with pytest.raises(MetaAnalysisParseError, match="echoes or omits"):
        analyzer._parse_response(
            json.dumps(value),
            [finding],
            original_indices=[0],
            fallback_on_error=False,
        )


def test_meta_contract_accepts_none_supported_without_echo() -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding()
    evidence_id = _meta_evidence_id(finding)
    analyzer._allowed_evidence_ids = {evidence_id}

    result = analyzer._parse_response(
        json.dumps(_valid_meta(0, evidence_id)),
        [finding],
        original_indices=[0],
        fallback_on_error=False,
    )

    assert isinstance(result, MetaAnalysisResult)
    assert result.overall_risk_assessment["meta_delta"] == "NONE_SUPPORTED"

    schema = _ollama_meta_response_format()["json_schema"]["schema"]
    assert list(Draft202012Validator(schema).iter_errors(_valid_meta(0, evidence_id))) == []


def test_meta_schema_and_parser_reject_none_supported_with_substantive_delta() -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding()
    evidence_id = _meta_evidence_id(finding)
    analyzer._allowed_evidence_ids = {evidence_id}
    contradiction = _false_positive_meta(0, evidence_id)
    contradiction["overall_risk_assessment"]["meta_delta"] = "NONE_SUPPORTED"  # type: ignore[index]

    schema = _ollama_meta_response_format()["json_schema"]["schema"]
    errors = list(Draft202012Validator(schema).iter_errors(contradiction))
    assert any(error.validator == "maxItems" and list(error.path) == ["false_positives"] for error in errors)

    with pytest.raises(MetaAnalysisParseError, match="NONE_SUPPORTED conflicts with a substantive Meta delta"):
        analyzer._parse_response(
            json.dumps(contradiction),
            [finding],
            original_indices=[0],
            fallback_on_error=False,
        )


def test_meta_schema_and_parser_accept_false_positive_delta() -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding()
    evidence_id = _meta_evidence_id(finding)
    analyzer._allowed_evidence_ids = {evidence_id}
    value = _false_positive_meta(0, evidence_id)
    schema = _ollama_meta_response_format()["json_schema"]["schema"]

    assert list(Draft202012Validator(schema).iter_errors(value)) == []
    result = analyzer._parse_response(
        json.dumps(value),
        [finding],
        original_indices=[0],
        fallback_on_error=False,
    )
    assert result.overall_risk_assessment["meta_delta"] == "FALSE_POSITIVE_SUPPRESSED"
    assert len(result.false_positives) == 1


def test_meta_schema_and_parser_accept_missed_threat_delta() -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding()
    evidence_id = _meta_evidence_id(finding)
    analyzer._allowed_evidence_ids = {evidence_id}
    value = _missed_threat_meta(0, evidence_id)
    schema = _ollama_meta_response_format()["json_schema"]["schema"]

    assert list(Draft202012Validator(schema).iter_errors(value)) == []
    result = analyzer._parse_response(
        json.dumps(value),
        [finding],
        original_indices=[0],
        fallback_on_error=False,
    )
    assert result.overall_risk_assessment["meta_delta"] == "MISSED_THREAT_NAMED"
    assert len(result.missed_threats) == 1


def test_meta_schema_and_parser_accept_chain_delta() -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    findings = [_finding(index=0), _finding(index=1)]
    evidence_ids = [_meta_evidence_id(finding) for finding in findings]
    analyzer._allowed_evidence_ids = set(evidence_ids)
    value = _chain_meta(*evidence_ids)
    schema = _ollama_meta_response_format()["json_schema"]["schema"]

    assert list(Draft202012Validator(schema).iter_errors(value)) == []
    result = analyzer._parse_response(
        json.dumps(value),
        findings,
        original_indices=[0, 1],
        fallback_on_error=False,
    )
    assert result.overall_risk_assessment["meta_delta"] == "CHAIN_VALIDATED"
    assert len(result.correlations) == 1


def test_meta_contract_rejects_missing_required_assessment_fields() -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    finding = _finding()
    evidence_id = _meta_evidence_id(finding)
    analyzer._allowed_evidence_ids = {evidence_id}
    value = _valid_meta(0, evidence_id)
    assessment = value["overall_risk_assessment"]
    del assessment["top_priority"]  # type: ignore[index]
    del assessment["verdict_reasoning"]  # type: ignore[index]

    with pytest.raises(MetaAnalysisParseError, match="missing or unexpected fields"):
        analyzer._parse_response(
            json.dumps(value),
            [finding],
            original_indices=[0],
            fallback_on_error=False,
        )


def test_ollama_meta_schema_is_closed_strict_and_frozen() -> None:
    response_format = _ollama_meta_response_format()
    assert response_format["type"] == "json_schema"
    assert response_format["json_schema"]["name"] == "skill_meta_analysis"
    assert response_format["json_schema"]["strict"] is True
    schema = response_format["json_schema"]["schema"]

    def assert_closed_objects(value: object) -> None:
        if isinstance(value, dict):
            if value.get("type") == "object":
                assert value.get("additionalProperties") is False
                assert set(value.get("required", [])) == set(value.get("properties", {}))
            for child in value.values():
                assert_closed_objects(child)
        elif isinstance(value, list):
            for child in value:
                assert_closed_objects(child)

    assert_closed_objects(schema)
    properties = schema["properties"]
    assert set(properties) == {
        "overall_risk_assessment",
        "correlations",
        "recommendations",
        "false_positives",
        "validated_findings",
        "missed_threats",
        "priority_order",
    }
    validated = properties["validated_findings"]["items"]
    assert set(validated["required"]) == {
        "_index",
        "confidence",
        "confidence_reason",
        "exploitability",
        "impact",
        "evidence_ids",
        "chain",
    }
    assert validated["properties"]["chain"]["anyOf"][1] == {"type": "null"}
    delta_rules = schema["allOf"]
    assert [
        rule["if"]["properties"]["overall_risk_assessment"]["properties"]["meta_delta"]["const"] for rule in delta_rules
    ] == [
        "CHAIN_VALIDATED",
        "FALSE_POSITIVE_SUPPRESSED",
        "MISSED_THREAT_NAMED",
        "NONE_SUPPORTED",
    ]
    assert delta_rules[0]["then"]["properties"]["validated_findings"]["contains"]["properties"]["chain"] == {
        "type": "array",
        "minItems": 2,
    }
    assert delta_rules[3]["then"]["properties"]["validated_findings"]["items"]["properties"]["chain"] == {"const": None}
    canonical = json.dumps(response_format, sort_keys=True, separators=(",", ":")).encode()
    expected_sha256 = "d49aee837fef7937404cf7a73b9cebb7989ac1a7f519adffbd3fd8b0e7ea1a10"
    assert hashlib.sha256(canonical).hexdigest() == expected_sha256
    assert ollama_meta_response_schema_sha256() == expected_sha256


def test_meta_static_and_dynamic_prompts_freeze_exact_ollama_contract(tmp_path: Path) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    user_prompt = analyzer._build_user_prompt(
        _skill(tmp_path),
        "bounded context",
        '[{"_index": 0}]',
        ["static"],
        "<START>",
        "<END>",
    )
    exact_top_level = {
        "overall_risk_assessment",
        "correlations",
        "recommendations",
        "false_positives",
        "validated_findings",
        "missed_threats",
        "priority_order",
    }
    for field in exact_top_level:
        assert f"`{field}`" in analyzer.system_prompt
        assert f"`{field}`" in user_prompt
    for prompt in (analyzer.system_prompt, user_prompt):
        normalized_prompt = " ".join(prompt.split())
        assert "exactly these seven top-level keys" in prompt
        assert "JSON `null`" in prompt
        assert "2–8" in prompt
        assert "evidence_ids" in prompt
        assert "`NONE_SUPPORTED`" in prompt
        assert "empty `correlations`, `false_positives`, and `missed_threats`" in normalized_prompt
        assert (
            "Missed-threat severity must be exactly `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`" in normalized_prompt
        )
        assert "`SAFE` is forbidden" in prompt

    assert hashlib.sha256(analyzer.system_prompt.encode()).hexdigest() == (
        "d6a5e9a9c24a573cd3a7ca0eec71848b14ba6ab62b23c65ffb0a18b57305f4a5"
    )
    assert hashlib.sha256(user_prompt.encode()).hexdigest() == (
        "1c89c265fbd9411093cfe3c61c2932988cbcf2d1ccad44c4f4c7d437dbbe8e78"
    )


def test_ollama_meta_request_options_identity_is_frozen() -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
        temperature=0.0,
        max_tokens=16_384,
        timeout=120,
        max_retries=3,
    )

    assert analyzer.request_options_sha256 == "9aae3bd8903f3ad47e7c97d77539c4277882883bcf2b6a200abbd3aca1952c8d"


def test_ollama_meta_request_passes_exact_json_schema(monkeypatch) -> None:
    analyzer = MetaAnalyzer(
        model="ollama/test",
        base_url="http://127.0.0.1:11434",
    )
    choice = SimpleNamespace(
        message=SimpleNamespace(content="{}"),
        finish_reason="stop",
        provider_specific_fields={},
    )
    completion = AsyncMock(return_value=SimpleNamespace(choices=[choice], usage=None))
    monkeypatch.setattr("skill_scanner.core.analyzers.meta_analyzer.acompletion", completion)

    assert asyncio.run(analyzer._make_llm_request("system", "user")) == "{}"

    request = completion.await_args.kwargs
    assert request["response_format"] == _ollama_meta_response_format()
    assert request["reasoning_effort"] == "none"
    assert request["drop_params"] is True


def test_meta_contract_repair_policy_identity_is_bounded_and_frozen() -> None:
    assert meta_contract_repair_policy_identity() == {
        "version": 1,
        "max_attempts_per_batch": 1,
        "instruction_set_sha256": "5f325cf951ce6e36997ba1257988099a5df62447db99f831d017fa6bcaaea4c7",
    }
