# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Production discovery and immutable identity checks for bundled core CEL."""

from __future__ import annotations

import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml

from skill_scanner.core.cel.models import CelMode, CelRollout, expression_set_hash
from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.core.scan_policy import ScanPolicy
from skill_scanner.core.scanner import SkillScanner

from .expressions import BUNDLED_SCANNER_OWNED_SHADOW_GATES
from .test_immutable_generations import BUNDLED_EXPRESSION_SET_HASH

_CORE_PACK_DIR = Path(__file__).resolve().parents[2] / "skill_scanner" / "data" / "packs" / "core"
_CORE_MANIFEST_PATH = _CORE_PACK_DIR / "pack.yaml"
_BUNDLED_IDS = frozenset(BUNDLED_SCANNER_OWNED_SHADOW_GATES)


def _cel_rules(registry: Any) -> dict[str, Any]:
    return {
        rule_id: definition.cel for rule_id, definition in registry.all_rules().items() if definition.cel is not None
    }


def _reset_bundled_snapshot(monkeypatch: pytest.MonkeyPatch) -> None:
    import skill_scanner.core.rule_registry as registry_module

    monkeypatch.setattr(registry_module, "_BUILT_IN_PACK_SNAPSHOT", None)


def _assert_exact_bundled_generation(rules: dict[str, Any]) -> None:
    assert set(rules) == _BUNDLED_IDS
    assert expression_set_hash(rules.values()) == BUNDLED_EXPRESSION_SET_HASH
    assert all(rule.rollout is CelRollout.SHADOW for rule in rules.values())
    assert {rule_id: rules[rule_id].pack_name for rule_id in _BUNDLED_IDS} == {
        rule_id: "core" for rule_id in _BUNDLED_IDS
    }
    assert {rule_id: rule.expression for rule_id, rule in rules.items()} == dict(BUNDLED_SCANNER_OWNED_SHADOW_GATES)


def _copy_core_pack(tmp_path: Path) -> Path:
    copied = tmp_path / "core"
    shutil.copytree(_CORE_PACK_DIR, copied)
    return copied


def _rewrite_manifest(pack_path: Path, mutate: Any) -> None:
    manifest_path = pack_path / "pack.yaml"
    data = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    mutate(data)
    manifest_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def test_scanner_owned_shadow_subset_lives_in_authoritative_core_v2_manifest() -> None:
    document = yaml.safe_load(_CORE_MANIFEST_PATH.read_text(encoding="utf-8"))
    manifest_cel = {rule_id: rule["cel"] for rule_id, rule in document["rules"].items() if "cel" in rule}

    assert document["schema_version"] == 2
    assert set(manifest_cel) == _BUNDLED_IDS
    assert all(cel["rollout"] == "shadow" for cel in manifest_cel.values())
    assert {rule_id: cel["expression"] for rule_id, cel in manifest_cel.items()} == dict(
        BUNDLED_SCANNER_OWNED_SHADOW_GATES
    )


def test_default_registry_discovers_exact_reviewed_bundled_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset_bundled_snapshot(monkeypatch)
    _assert_exact_bundled_generation(_cel_rules(PackLoader().build_registry()))


def test_core_manifest_is_authoritative_for_scanner_owned_cel_identity() -> None:
    document = yaml.safe_load(_CORE_MANIFEST_PATH.read_text(encoding="utf-8"))
    pack = PackLoader().load_bundled_pack(_CORE_PACK_DIR)

    for rule_id in _BUNDLED_IDS:
        declared = document["rules"][rule_id]
        definition = pack.rules[rule_id]
        assert (definition.source_type, definition.category, definition.default_severity) == (
            declared["source"],
            declared["category"],
            declared["severity"],
        )
        assert definition.cel is not None


def test_normal_scanner_uses_core_bundled_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset_bundled_snapshot(monkeypatch)
    monkeypatch.setattr("skill_scanner.core.cel.gate.validate_cel_go_generation", lambda rules: "v0.32.0;helper=test")
    policy = ScanPolicy.default()
    policy.cel.mode = CelMode.OFF
    with SkillScanner(analyzers=[], policy=policy) as scanner:
        _assert_exact_bundled_generation(scanner.cel_gate.rules)


def test_normal_cli_scanner_discovers_core_bundled_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    from skill_scanner.cli.cli import _create_skill_scanner

    _reset_bundled_snapshot(monkeypatch)
    monkeypatch.setattr("skill_scanner.core.cel.gate.validate_cel_go_generation", lambda rules: "v0.32.0;helper=test")
    with _create_skill_scanner(
        [], ScanPolicy.default(), SimpleNamespace(trusted_rule_pack=None), lambda _: None
    ) as scanner:
        _assert_exact_bundled_generation(scanner.cel_gate.rules)


def test_normal_api_scanner_discovers_core_bundled_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi")
    from skill_scanner.api.router import _create_api_scanner

    _reset_bundled_snapshot(monkeypatch)
    monkeypatch.setattr("skill_scanner.core.cel.gate.validate_cel_go_generation", lambda rules: "v0.32.0;helper=test")
    with _create_api_scanner([], ScanPolicy.default()) as scanner:
        _assert_exact_bundled_generation(scanner.cel_gate.rules)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda data: data["rules"]["FIND_EXEC_PATTERN"].__setitem__("category", "prompt_injection"),
            "Category metadata mismatch",
        ),
        (
            lambda data: data["rules"]["FIND_EXEC_PATTERN"].__setitem__("source", "yara"),
            "Bundled signature implementation.*not declared",
        ),
        (lambda data: data["rules"]["FIND_EXEC_PATTERN"].__setitem__("severity", "LOW"), "Severity metadata mismatch"),
        (
            lambda data: data["rules"]["FIND_EXEC_PATTERN"]["cel"].__setitem__(
                "expression", "f.candidate.rule_id.matches(f.candidate.file_path)"
            ),
            "Invalid CEL expression",
        ),
        (lambda data: data["rules"]["FIND_EXEC_PATTERN"].__setitem__("unexpected", True), "Unknown field"),
    ],
)
def test_authoritative_manifest_rejects_identity_or_cel_drift_atomically(
    tmp_path: Path, mutate: Any, message: str
) -> None:
    pack_path = _copy_core_pack(tmp_path)
    _rewrite_manifest(pack_path, mutate)
    with pytest.raises(ValueError, match=message):
        PackLoader().load_bundled_pack(pack_path)


def test_authoritative_manifest_rejects_duplicate_keys(tmp_path: Path) -> None:
    pack_path = _copy_core_pack(tmp_path)
    manifest_path = pack_path / "pack.yaml"
    manifest = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(manifest.replace("rules:\n", "rules:\nrules:\n", 1), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate YAML key"):
        PackLoader().load_bundled_pack(pack_path)
