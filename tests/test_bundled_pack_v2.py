# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Strict validation gates for release-owned schema-v2 rule packs."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from skill_scanner.core.models import Severity, ThreatCategory
from skill_scanner.core.python_rule_inventory import BundledPythonImplementation
from skill_scanner.core.rule_registry import PackLoader, RuleDefinition
from skill_scanner.core.rules.patterns import RuleLoader

_PACKS = Path(__file__).resolve().parents[1] / "skill_scanner" / "data" / "packs"
_COMMUNITY_BEHAVIOR_DIGEST = "f83d8fce9d7ad23d24f36020bf4f381fba810c8a544b9f06ab075a3bf2b6f39e"


def _minimal_manifest() -> dict:
    return {
        "schema_version": 2,
        "name": "bundled-test",
        "version": "1.0",
        "description": "A release-owned test pack",
        "rules": {
            "TEST_RULE": {
                "source": "signature",
                "category": "command_injection",
                "severity": "HIGH",
                "knobs": {"enabled": True},
                "description": "Detects a test marker",
            }
        },
    }


def _minimal_signature() -> dict:
    return {
        "id": "TEST_RULE",
        "category": "command_injection",
        "severity": "HIGH",
        "patterns": ["test-marker"],
        "description": "Detects a test marker",
    }


def _write_pack(root: Path, manifest: dict, signatures: list[dict]) -> Path:
    root.mkdir()
    (root / "pack.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    (root / "signatures.yaml").write_text(yaml.safe_dump(signatures, sort_keys=False), encoding="utf-8")
    return root


def test_all_bundled_manifests_are_strict_v2_without_promotion_blockers() -> None:
    packs = {
        path.name: PackLoader().load_bundled_pack(path) for path in _PACKS.iterdir() if (path / "pack.yaml").is_file()
    }

    assert set(packs) == {"atr", "core", "promptguard"}
    assert len(packs["atr"].rules) == 712
    assert len(packs["promptguard"].rules) == 26
    for pack in packs.values():
        assert pack.schema_version == 2
        assert pack.validation_report is not None
        assert pack.validation_report.schema_status == "v2"
        assert pack.validation_report.validation_scope == "strict_bundled_v2"
        assert pack.validation_report.promotion_blockers == ()
        assert pack.validation_report.signature_implementation_count == sum(
            definition.source_type == "signature" for definition in pack.rules.values()
        )
        assert pack.validation_report.yara_implementation_count == sum(
            definition.source_type == "yara" for definition in pack.rules.values()
        )
        assert pack.validation_report.python_implementation_count == sum(
            definition.source_type == "python" for definition in pack.rules.values()
        )
        for definition in pack.rules.values():
            assert definition.source_type in {"signature", "yara", "python"}
            assert definition.category in {category.value for category in ThreatCategory}
            assert definition.default_severity in {severity.value for severity in Severity}


def test_category_normalization_changes_no_atr_or_promptguard_runtime_rule_behavior() -> None:
    rows: list[dict[str, object]] = []
    for name, expected_count in (("atr", 712), ("promptguard", 26)):
        loader = RuleLoader(rules_file=_PACKS / name / "signatures", strict=True)
        rules = loader.load_rules()
        assert len(rules) == expected_count
        assert loader.category_normalization_metrics.native_rules == expected_count
        assert loader.category_normalization_metrics.legacy_mapped_rules == 0
        for rule in rules:
            rows.append(
                {
                    "id": rule.id,
                    "category": rule.category.value,
                    "severity": rule.severity.value,
                    "patterns": [getattr(pattern, "pattern", str(pattern)) for pattern in rule.patterns],
                    "exclude_patterns": [
                        getattr(pattern, "pattern", str(pattern)) for pattern in rule.exclude_patterns
                    ],
                    "file_types": sorted(rule.file_types),
                }
            )

    payload = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(payload).hexdigest() == _COMMUNITY_BEHAVIOR_DIGEST


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"unknown": True}), "Unknown field"),
        (lambda value: value.update({"schema_version": 1}), "schema_version"),
        (lambda value: value["rules"]["TEST_RULE"].update({"unknown": True}), "Unknown field"),
        (lambda value: value["rules"]["TEST_RULE"].update({"source": "cel"}), "Unknown rule source"),
        (lambda value: value["rules"]["TEST_RULE"].update({"category": "agent_manipulation"}), "Unknown category"),
        (lambda value: value["rules"]["TEST_RULE"].update({"severity": "URGENT"}), "Unknown severity"),
        (
            lambda value: value["rules"]["TEST_RULE"].update({"knobs": {"enabled": True, "unknown": 1}}),
            "Unknown field",
        ),
    ],
)
def test_bundled_v2_rejects_unknown_schema_values(tmp_path: Path, mutation, message: str) -> None:
    manifest = deepcopy(_minimal_manifest())
    mutation(manifest)
    pack = _write_pack(tmp_path / "pack", manifest, [_minimal_signature()])

    with pytest.raises(ValueError, match=message):
        PackLoader().load_bundled_pack(pack)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("category", "obfuscation", "Category metadata mismatch"),
        ("severity", "LOW", "Severity metadata mismatch"),
    ],
)
def test_bundled_v2_rejects_signature_metadata_drift(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    signature = _minimal_signature()
    signature[field] = value
    pack = _write_pack(tmp_path / "pack", _minimal_manifest(), [signature])

    with pytest.raises(ValueError, match=message):
        PackLoader().load_bundled_pack(pack)


def test_bundled_v2_python_source_requires_known_analyzer_but_local_pack_cannot_import_python(
    tmp_path: Path,
) -> None:
    manifest = _minimal_manifest()
    manifest["rules"] = {
        "PYTHON_RULE": {
            "source": "python",
            "analyzer": "static",
            "category": "policy_violation",
            "severity": "LOW",
            "knobs": {"enabled": True},
        }
    }
    pack = _write_pack(tmp_path / "pack", manifest, [])

    with pytest.raises(ValueError, match="Only the release-owned core pack"):
        PackLoader().load_bundled_pack(pack)
    trusted_manifest = deepcopy(manifest)
    trusted_manifest["rules"]["PYTHON_RULE"].pop("analyzer")
    trusted_pack = _write_pack(tmp_path / "trusted-pack", trusted_manifest, [])
    with pytest.raises(ValueError, match="may not load Python"):
        PackLoader().load_trusted_pack(trusted_pack)


@pytest.mark.parametrize(
    ("demotions", "message"),
    [
        ("MEDIUM", "must be a list"),
        (["URGENT"], "Unknown severity"),
        (["HIGH"], "only severities below"),
        (["CRITICAL"], "only severities below"),
        (["MEDIUM", "MEDIUM"], "contains duplicates"),
    ],
)
def test_core_v2_rejects_invalid_allowed_severity_demotions(
    tmp_path: Path,
    demotions: object,
    message: str,
) -> None:
    manifest = _minimal_manifest()
    manifest["name"] = "core"
    definition = manifest["rules"]["TEST_RULE"]
    definition["source"] = "python"
    definition["analyzer"] = "static"
    definition["allowed_severity_demotions"] = demotions
    pack = _write_pack(tmp_path / "core", manifest, [])

    with pytest.raises(ValueError, match=message):
        PackLoader().load_bundled_pack(pack)


def _write_literal_python_finding(
    root: Path,
    *,
    analyzer: str = '"static"',
    category: str = "ThreatCategory.POLICY_VIOLATION",
    severity: str = "Severity.HIGH",
    extra_calls: str = "",
) -> None:
    (root / "implementation.py").write_text(
        "\n".join(
            [
                "from skill_scanner.core.models import Finding, Severity, ThreatCategory",
                "",
                "def emit(selected_severity):",
                "    Finding(",
                '        rule_id="TEST_RULE",',
                f"        analyzer={analyzer},",
                f"        category={category},",
                f"        severity={severity},",
                '        id="test", title="test", description="test",',
                "    )",
                extra_calls,
            ]
        ),
        encoding="utf-8",
    )


def _literal_python_definition(*, demotions: frozenset[str] = frozenset()) -> dict[str, RuleDefinition]:
    return {
        "TEST_RULE": RuleDefinition(
            id="TEST_RULE",
            source_type="python",
            pack_name="core",
            category=ThreatCategory.POLICY_VIOLATION.value,
            default_severity=Severity.HIGH.value,
            allowed_severity_demotions=demotions,
            analyzer="static",
        )
    }


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("analyzer", '"pipeline"', "Bundled Python analyzer metadata mismatch"),
        ("category", "ThreatCategory.DATA_EXFILTRATION", "Bundled Python category metadata mismatch"),
        ("category", "ThreatCategory" + ".INVENTED", "Bundled Python category metadata mismatch"),
        ("severity", "Severity.CRITICAL", "Bundled Python severity metadata mismatch"),
        ("severity", "Severity.MEDIUM", "Bundled Python severity metadata mismatch"),
        ("severity", "Severity.URGENT", "Bundled Python severity metadata mismatch"),
    ],
)
def test_bundled_python_literal_metadata_drift_fails_startup(
    tmp_path: Path,
    field: str,
    value: str,
    message: str,
) -> None:
    arguments = {field: value}
    _write_literal_python_finding(tmp_path, **arguments)

    with pytest.raises(ValueError, match=message):
        PackLoader._validate_bundled_python_implementations(
            _literal_python_definition(),
            source_root=tmp_path,
            indirect_implementations={},
        )


def test_bundled_python_literal_declared_demotion_and_dynamic_severity_pass_startup(tmp_path: Path) -> None:
    extra_calls = """
    Finding(
        rule_id="TEST_RULE",
        analyzer="static",
        category=ThreatCategory.POLICY_VIOLATION,
        severity=selected_severity,
        id="dynamic", title="dynamic", description="dynamic",
    )
"""
    _write_literal_python_finding(
        tmp_path,
        severity="Severity.MEDIUM",
        extra_calls=extra_calls,
    )

    assert (
        PackLoader._validate_bundled_python_implementations(
            _literal_python_definition(demotions=frozenset({Severity.MEDIUM.value})),
            source_root=tmp_path,
            indirect_implementations={},
        )
        == 1
    )


def test_bundled_python_positional_literal_metadata_drift_fails_startup(tmp_path: Path) -> None:
    (tmp_path / "implementation.py").write_text(
        "\n".join(
            [
                "from skill_scanner.core.models import Finding, Severity, ThreatCategory",
                "Finding(",
                '    "test", "TEST_RULE", ThreatCategory.POLICY_VIOLATION,',
                '    Severity.CRITICAL, "test", "test",',
                ")",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Bundled Python severity metadata mismatch"):
        PackLoader._validate_bundled_python_implementations(
            _literal_python_definition(),
            source_root=tmp_path,
            indirect_implementations={},
        )


def _indirect_implementation(
    *,
    rule_id: str = "TEST_RULE",
    analyzer: str = "static",
    category: ThreatCategory = ThreatCategory.POLICY_VIOLATION,
    max_severity: Severity = Severity.HIGH,
    demotions: frozenset[Severity] = frozenset(),
) -> BundledPythonImplementation:
    return BundledPythonImplementation(
        rule_id=rule_id,
        analyzer=analyzer,
        category=category,
        max_severity=max_severity,
        allowed_severity_demotions=demotions,
    )


@pytest.mark.parametrize(
    ("definition", "implementation", "message"),
    [
        (
            _literal_python_definition(),
            _indirect_implementation(analyzer="pipeline"),
            "Bundled indirect Python analyzer metadata mismatch",
        ),
        (
            _literal_python_definition(),
            _indirect_implementation(category=ThreatCategory.DATA_EXFILTRATION),
            "Bundled indirect Python category metadata mismatch",
        ),
        (
            _literal_python_definition(),
            _indirect_implementation(max_severity=Severity.CRITICAL),
            "Bundled indirect Python severity metadata mismatch",
        ),
        (
            _literal_python_definition(demotions=frozenset({Severity.MEDIUM.value})),
            _indirect_implementation(),
            "Bundled indirect Python severity-demotion metadata mismatch",
        ),
    ],
)
def test_bundled_indirect_python_metadata_drift_fails_startup(
    tmp_path: Path,
    definition: dict[str, RuleDefinition],
    implementation: BundledPythonImplementation,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        PackLoader._validate_bundled_python_implementations(
            definition,
            source_root=tmp_path,
            indirect_implementations={implementation.rule_id: implementation},
        )


def test_bundled_indirect_python_missing_inventory_entry_fails_startup(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Missing bundled Python implementation.*TEST_RULE"):
        PackLoader._validate_bundled_python_implementations(
            _literal_python_definition(),
            source_root=tmp_path,
            indirect_implementations={},
        )


def test_bundled_indirect_python_extra_inventory_entry_fails_startup(tmp_path: Path) -> None:
    (tmp_path / "implementation.py").write_text(
        "\n".join(
            [
                "from skill_scanner.core.models import Finding, Severity, ThreatCategory",
                "Finding(",
                '    id="other", rule_id="OTHER_RULE",',
                "    category=ThreatCategory.POLICY_VIOLATION, severity=Severity.HIGH,",
                '    title="other", description="other", analyzer="static",',
                ")",
            ]
        ),
        encoding="utf-8",
    )
    definitions = {
        "OTHER_RULE": RuleDefinition(
            id="OTHER_RULE",
            source_type="python",
            pack_name="core",
            category=ThreatCategory.POLICY_VIOLATION.value,
            default_severity=Severity.HIGH.value,
            analyzer="static",
        )
    }
    extra = _indirect_implementation()

    with pytest.raises(ValueError, match="not declared in pack.yaml.*TEST_RULE"):
        PackLoader._validate_bundled_python_implementations(
            definitions,
            source_root=tmp_path,
            indirect_implementations={extra.rule_id: extra},
        )


def test_bundled_indirect_python_inventory_identity_mismatch_fails_startup(tmp_path: Path) -> None:
    implementation = _indirect_implementation(rule_id="OTHER_RULE")
    with pytest.raises(ValueError, match="inventory identity mismatch"):
        PackLoader._validate_bundled_python_implementations(
            _literal_python_definition(),
            source_root=tmp_path,
            indirect_implementations={"TEST_RULE": implementation},
        )


def test_bundled_yara_runtime_uses_manifest_authoritative_metadata() -> None:
    from skill_scanner.core.analyzers.static import StaticAnalyzer

    analyzer = StaticAnalyzer()
    assert analyzer.yara_scanner is not None
    overrides = analyzer.yara_scanner._metadata_overrides
    core = PackLoader().load_bundled_pack(_PACKS / "core")
    declared = {
        definition.id.removeprefix("YARA_"): {
            "category": definition.category,
            "severity": definition.default_severity,
            "description": definition.description,
        }
        for definition in core.rules.values()
        if definition.source_type == "yara"
    }
    assert overrides == declared
