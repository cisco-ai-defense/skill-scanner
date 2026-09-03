# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Fail-fast validation tests for explicitly trusted schema-v2 rule packs."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path

import pytest
import yaml

from skill_scanner.core.cel.models import CelRollout
from skill_scanner.core.rule_registry import PackLoader
from skill_scanner.core.rules.patterns import RuleLoader


def _manifest(rule_id: str = "TRUSTED_FETCH") -> dict:
    return {
        "schema_version": 2,
        "name": "trusted-test",
        "version": "1.0",
        "description": "Test-only trusted pack",
        "rules": {
            rule_id: {
                "source": "signature",
                "category": "command_injection",
                "severity": "high",
                "knobs": {"enabled": True},
                "description": "Detect a test fetch",
                "file_types": ["python"],
                "remediation": "Remove it",
                "cel": {
                    "fact_schema": "v1",
                    "rollout": "shadow",
                    "expression": f'f.candidate.rule_id == "{rule_id}"',
                },
            }
        },
    }


def _signature(rule_id: str = "TRUSTED_FETCH") -> dict:
    return {
        "id": rule_id,
        "category": "command_injection",
        "severity": "HIGH",
        "patterns": [r"curl\s+https://"],
        "exclude_patterns": [r"example\.invalid"],
        "file_types": ["python"],
        "description": "Detect a test fetch",
        "remediation": "Remove it",
    }


def _write_pack(
    root: Path,
    *,
    manifest: dict | None = None,
    signatures: list[dict] | None = None,
) -> Path:
    root.mkdir()
    (root / "pack.yaml").write_text(yaml.safe_dump(manifest or _manifest(), sort_keys=False), encoding="utf-8")
    if signatures is not None:
        (root / "signatures.yaml").write_text(yaml.safe_dump(signatures, sort_keys=False), encoding="utf-8")
    return root


def test_load_trusted_pack_v2_validates_and_exposes_cel(tmp_path: Path) -> None:
    pack_dir = _write_pack(tmp_path / "pack", signatures=[_signature()])

    pack = PackLoader().load_trusted_pack(pack_dir)

    assert pack.trusted is True
    assert pack.schema_version == 2
    definition = pack.rules["TRUSTED_FETCH"]
    assert definition.default_severity == "HIGH"
    assert definition.cel is not None
    assert definition.cel.rollout is CelRollout.SHADOW
    assert definition.cel.pack_name == "trusted-test"


def test_rule_loader_publishes_manifest_authoritative_trusted_rule(tmp_path: Path) -> None:
    pack_dir = _write_pack(tmp_path / "pack", signatures=[_signature()])
    primary = tmp_path / "primary.yaml"
    primary.write_text("[]\n", encoding="utf-8")

    loader = RuleLoader(rules_file=primary, trusted_pack_dirs=[pack_dir])
    rules = loader.load_rules()

    assert [rule.id for rule in rules] == ["TRUSTED_FETCH"]
    assert rules[0].severity.value == "HIGH"
    assert rules[0].category.value == "command_injection"


def test_strict_rule_loader_rejects_invalid_legacy_regex(tmp_path: Path) -> None:
    rules_file = tmp_path / "invalid.yaml"
    signature = _signature()
    signature["patterns"] = ["("]
    rules_file.write_text(yaml.safe_dump([signature]), encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid regex"):
        RuleLoader(rules_file=rules_file, strict=True).load_rules()


def test_strict_rule_loader_rejects_duplicate_legacy_ids(tmp_path: Path) -> None:
    rules_file = tmp_path / "duplicate.yaml"
    rules_file.write_text(yaml.safe_dump([_signature(), _signature()]), encoding="utf-8")

    with pytest.raises(ValueError, match="Duplicate signature rule ID"):
        RuleLoader(rules_file=rules_file, strict=True).load_rules()


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"mystery": True}), "Unknown field"),
        (lambda value: value.update({"author": 42}), "author must be a string"),
        (lambda value: value.update({"source_url": "  "}), "source_url must be a non-empty string"),
        (lambda value: value.update({"schema_version": 1}), "schema_version"),
        (lambda value: value["rules"]["TRUSTED_FETCH"].update({"mystery": True}), "Unknown field"),
        (lambda value: value["rules"]["TRUSTED_FETCH"].update({"source": "remote"}), "Unknown rule source"),
        (lambda value: value["rules"]["TRUSTED_FETCH"].update({"source": "python"}), "may not load Python"),
        (lambda value: value["rules"]["TRUSTED_FETCH"].update({"category": "new_category"}), "Unknown category"),
        (lambda value: value["rules"]["TRUSTED_FETCH"].update({"severity": "urgent"}), "Unknown severity"),
        (
            lambda value: value["rules"]["TRUSTED_FETCH"].update({"knobs": {"enabled": True, "magic": 1}}),
            "Unknown field",
        ),
        (
            lambda value: value["rules"]["TRUSTED_FETCH"]["cel"].update({"extension": "unsafe"}),
            "Unknown field",
        ),
        (
            lambda value: value["rules"]["TRUSTED_FETCH"]["cel"].update({"expression": "other.value"}),
            "Invalid CEL expression",
        ),
        (
            lambda value: value["rules"]["TRUSTED_FETCH"]["cel"].pop("fact_schema"),
            "fact_schema must be a non-empty string",
        ),
        (
            lambda value: value["rules"]["TRUSTED_FETCH"]["cel"].pop("rollout"),
            "rollout must be a non-empty string",
        ),
    ],
)
def test_trusted_v2_rejects_invalid_manifest_fields(tmp_path: Path, mutation, message: str) -> None:
    manifest = deepcopy(_manifest())
    mutation(manifest)
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=[_signature()])

    with pytest.raises(ValueError, match=message):
        PackLoader().load_trusted_pack(pack_dir)


def test_trusted_v2_rejects_duplicate_yaml_rule_keys(tmp_path: Path) -> None:
    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    (pack_dir / "pack.yaml").write_text(
        """\
schema_version: 2
name: duplicate-test
rules:
  DUPLICATE:
    source: signature
    category: malware
    severity: high
  DUPLICATE:
    source: signature
    category: malware
    severity: high
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate YAML key"):
        PackLoader().load_trusted_pack(pack_dir)


def test_legacy_loader_never_silently_reinterprets_declared_schemas(tmp_path: Path) -> None:
    v2_pack = _write_pack(tmp_path / "v2", signatures=[_signature()])
    with pytest.raises(ValueError, match="strict trusted-pack loader"):
        PackLoader().load_pack(v2_pack)

    unsupported = deepcopy(_manifest())
    unsupported["schema_version"] = 99
    unsupported_pack = _write_pack(
        tmp_path / "unsupported",
        manifest=unsupported,
        signatures=[_signature()],
    )
    with pytest.raises(ValueError, match="Unsupported rule-pack schema_version"):
        PackLoader().load_pack(unsupported_pack)


def test_trusted_v2_requires_nonempty_rules_mapping(tmp_path: Path) -> None:
    manifest = deepcopy(_manifest())
    manifest["rules"] = {}
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=[])

    with pytest.raises(ValueError, match="at least one rule"):
        PackLoader().load_trusted_pack(pack_dir)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("name", " trusted-test", "surrounding whitespace"),
    ],
)
def test_trusted_v2_rejects_ambiguous_pack_identity(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    manifest = deepcopy(_manifest())
    manifest[field] = value
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=[_signature()])

    with pytest.raises(ValueError, match=message):
        PackLoader().load_trusted_pack(pack_dir)


def test_trusted_v2_rejects_rule_ids_with_surrounding_whitespace(tmp_path: Path) -> None:
    manifest = _manifest(" TRUSTED_FETCH")
    signature = _signature(" TRUSTED_FETCH")
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=[signature])

    with pytest.raises(ValueError, match="surrounding whitespace"):
        PackLoader().load_trusted_pack(pack_dir)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("patterns", [""], "non-empty list of non-empty strings"),
        ("exclude_patterns", [""], "list of non-empty strings"),
        ("description", 7, "description must be a string"),
        ("remediation", ["remove"], "remediation must be a string"),
        ("file_types", ["python", ""], "list of non-empty strings"),
    ],
)
def test_trusted_v2_rejects_malformed_signature_fields(
    tmp_path: Path,
    field: str,
    value: object,
    message: str,
) -> None:
    signature = _signature()
    signature[field] = value
    manifest = _manifest()
    if field in {"description", "remediation", "file_types"}:
        manifest["rules"]["TRUSTED_FETCH"].pop(field, None)
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=[signature])

    with pytest.raises(ValueError, match=message):
        PackLoader().load_trusted_pack(pack_dir)


def test_legacy_bundled_loader_also_rejects_duplicate_rule_ids(tmp_path: Path) -> None:
    pack_dir = tmp_path / "legacy-pack"
    pack_dir.mkdir()
    (pack_dir / "pack.yaml").write_text(
        """\
name: legacy-duplicate-test
rules:
  - id: DUPLICATE
    source: signature
  - id: DUPLICATE
    source: signature
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Duplicate rule ID"):
        PackLoader().load_pack(pack_dir)


def test_legacy_bundled_loader_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    pack_dir = tmp_path / "legacy-pack"
    pack_dir.mkdir()
    (pack_dir / "pack.yaml").write_text(
        """\
name: legacy-duplicate-test
rules:
  DUPLICATE:
    source: signature
  DUPLICATE:
    source: signature
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate YAML key"):
        PackLoader().load_pack(pack_dir)


def test_legacy_bundled_validation_rejects_unknown_or_cel_only_sources(tmp_path: Path) -> None:
    for index, source in enumerate(("cel", "remote")):
        pack_dir = tmp_path / f"legacy-pack-{index}"
        pack_dir.mkdir()
        (pack_dir / "pack.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": f"legacy-source-{index}",
                    "rules": {
                        "INVALID_SOURCE": {
                            "source": source,
                            "knobs": {"enabled": True},
                            "description": "Invalid source",
                        }
                    },
                },
                sort_keys=False,
            ),
            encoding="utf-8",
        )

        with pytest.raises(ValueError, match="Unknown rule source"):
            PackLoader().load_pack(pack_dir, validate_implementations=True)


def test_legacy_bundled_validation_rejects_mapping_identity_disagreement(tmp_path: Path) -> None:
    pack_dir = tmp_path / "legacy-pack"
    pack_dir.mkdir()
    (pack_dir / "pack.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "legacy-identity",
                "rules": {
                    "MAPPING_ID": {
                        "id": "DIFFERENT_ID",
                        "source": "python",
                        "analyzer": "static",
                        "knobs": {"enabled": True},
                        "description": "Identity mismatch",
                    }
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Rule identity mismatch"):
        PackLoader().load_pack(pack_dir, validate_implementations=True)


@pytest.mark.parametrize(
    ("rule_data", "message"),
    [
        ({"source": "python", "knobs": {"enabled": True}, "description": "Missing analyzer"}, "analyzer"),
        (
            {
                "source": "python",
                "analyzer": "static",
                "knobs": {"enabled": "yes"},
                "description": "Bad knob",
            },
            "enabled must be a boolean",
        ),
        (
            {
                "source": "python",
                "analyzer": "static",
                "knobs": {"enabled": True},
                "description": "Bad severity",
                "severity": "urgent",
            },
            "Unknown severity",
        ),
    ],
)
def test_legacy_bundled_validation_rejects_malformed_declared_rule_metadata(
    tmp_path: Path,
    rule_data: dict,
    message: str,
) -> None:
    pack_dir = tmp_path / "legacy-pack"
    pack_dir.mkdir()
    (pack_dir / "pack.yaml").write_text(
        yaml.safe_dump(
            {"name": "legacy-metadata", "rules": {"PYTHON_RULE": rule_data}},
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=message):
        PackLoader().load_pack(pack_dir, validate_implementations=True)


def test_trusted_v2_rejects_bad_regex(tmp_path: Path) -> None:
    signature = _signature()
    signature["patterns"] = ["("]
    pack_dir = _write_pack(tmp_path / "pack", signatures=[signature])

    with pytest.raises(ValueError, match="Invalid regex"):
        PackLoader().load_trusted_pack(pack_dir)


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("category", "malware", "Category metadata mismatch"),
        ("severity", "LOW", "Severity metadata mismatch"),
        ("description", "Different description", "description metadata mismatch"),
    ],
)
def test_trusted_v2_rejects_metadata_mismatch(
    tmp_path: Path,
    field_name: str,
    value: str,
    message: str,
) -> None:
    signature = _signature()
    signature[field_name] = value
    pack_dir = _write_pack(tmp_path / "pack", signatures=[signature])

    with pytest.raises(ValueError, match=message):
        PackLoader().load_trusted_pack(pack_dir)


def test_trusted_v2_requires_exact_implementation_coverage(tmp_path: Path) -> None:
    missing_pack = _write_pack(tmp_path / "missing", signatures=[])
    with pytest.raises(ValueError, match="Missing signature implementation"):
        PackLoader().load_trusted_pack(missing_pack)

    orphan_pack = _write_pack(tmp_path / "orphan", signatures=[_signature(), _signature("ORPHAN")])
    with pytest.raises(ValueError, match="not declared"):
        PackLoader().load_trusted_pack(orphan_pack)


def test_trusted_v2_rejects_rule_id_collision_with_builtins(tmp_path: Path) -> None:
    manifest = _manifest("FIND_EXEC_PATTERN")
    signature = _signature("FIND_EXEC_PATTERN")
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=[signature])

    with pytest.raises(ValueError, match="collision"):
        PackLoader().build_registry(trusted_dirs=[pack_dir])


def test_trusted_v2_rejects_invalid_yara(tmp_path: Path) -> None:
    manifest = _manifest("YARA_bad_rule")
    rule = manifest["rules"]["YARA_bad_rule"]
    rule["source"] = "yara"
    rule.pop("file_types")
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=None)
    yara_dir = pack_dir / "yara"
    yara_dir.mkdir()
    (yara_dir / "bad.yara").write_text("rule bad_rule { condition: this is not valid !!! }\n", encoding="utf-8")

    with pytest.raises(ValueError, match="Invalid YARA implementation"):
        PackLoader().load_trusted_pack(pack_dir)


def test_trusted_v2_rejects_yara_metadata_mismatch(tmp_path: Path) -> None:
    manifest = _manifest("YARA_metadata_rule")
    rule = manifest["rules"]["YARA_metadata_rule"]
    rule["source"] = "yara"
    rule.pop("file_types")
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=None)
    yara_dir = pack_dir / "yara"
    yara_dir.mkdir()
    (yara_dir / "metadata.yara").write_text(
        """\
rule metadata_rule {
  meta:
    threat_type = "command_injection"
    severity = "LOW"
    description = "Detect a test fetch"
  condition:
    true
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Severity metadata mismatch"):
        PackLoader().load_trusted_pack(pack_dir)


def test_trusted_v2_yara_coverage_uses_compiled_rules_not_comment_text(tmp_path: Path) -> None:
    manifest = _manifest("YARA_real_rule")
    rule = manifest["rules"]["YARA_real_rule"]
    rule["source"] = "yara"
    rule.pop("file_types")
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=None)
    yara_dir = pack_dir / "yara"
    yara_dir.mkdir()
    (yara_dir / "comments.yara").write_text(
        """\
/*
rule commented_out_rule { condition: true }
*/
rule real_rule { condition: true }
""",
        encoding="utf-8",
    )

    pack = PackLoader().load_trusted_pack(pack_dir)

    assert set(pack.rules) == {"YARA_real_rule"}


def test_trusted_v2_rejects_yara_source_without_compiled_rules(tmp_path: Path) -> None:
    manifest = _manifest("YARA_real_rule")
    rule = manifest["rules"]["YARA_real_rule"]
    rule["source"] = "yara"
    rule.pop("file_types")
    pack_dir = _write_pack(tmp_path / "pack", manifest=manifest, signatures=None)
    yara_dir = pack_dir / "yara"
    yara_dir.mkdir()
    (yara_dir / "comments-only.yara").write_text("/* no active rules */\n", encoding="utf-8")

    with pytest.raises(ValueError, match="contains no rules"):
        PackLoader().load_trusted_pack(pack_dir)


def test_trusted_v2_rejects_symlinked_implementation_directory(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "rules.yaml").write_text(yaml.safe_dump([_signature()]), encoding="utf-8")
    pack_dir = _write_pack(tmp_path / "pack", signatures=None)
    (pack_dir / "signatures").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink"):
        PackLoader().load_trusted_pack(pack_dir)


def _write_legacy_bundled_signature_pack(
    root: Path,
    *,
    manifest_category: str = "command_injection",
    manifest_severity: str = "HIGH",
    implementation_category: str = "command_injection",
    implementation_severity: str = "HIGH",
) -> Path:
    root.mkdir()
    manifest = {
        "name": "legacy-bundled-test",
        "rules": {
            "LEGACY_RULE": {
                "source": "signature",
                "category": manifest_category,
                "severity": manifest_severity,
            },
            "LEGACY_PYTHON_GAP": {
                "source": "python",
                "analyzer": "static",
                "knobs": {"enabled": True},
            },
        },
    }
    implementation = {
        "id": "LEGACY_RULE",
        "category": implementation_category,
        "severity": implementation_severity,
        "patterns": ["legacy"],
        "description": "Legacy test rule",
    }
    (root / "pack.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    (root / "signatures.yaml").write_text(yaml.safe_dump([implementation], sort_keys=False), encoding="utf-8")
    return root


@pytest.mark.parametrize(
    ("manifest_field", "manifest_value", "implementation_value", "message"),
    [
        ("category", "obfuscation", "command_injection", "Category metadata mismatch"),
        ("severity", "LOW", "HIGH", "Severity metadata mismatch"),
    ],
)
def test_bundled_legacy_validation_rejects_declared_metadata_drift(
    tmp_path: Path,
    manifest_field: str,
    manifest_value: str,
    implementation_value: str,
    message: str,
) -> None:
    kwargs = {
        f"manifest_{manifest_field}": manifest_value,
        f"implementation_{manifest_field}": implementation_value,
    }
    pack_dir = _write_legacy_bundled_signature_pack(tmp_path / "pack", **kwargs)

    with pytest.raises(ValueError, match=message):
        PackLoader().load_pack(pack_dir, validate_implementations=True)


def test_bundled_legacy_validation_reports_truthful_promotion_gap(tmp_path: Path) -> None:
    pack_dir = _write_legacy_bundled_signature_pack(tmp_path / "pack")

    pack = PackLoader().load_pack(pack_dir, validate_implementations=True)

    report = pack.validation_report
    assert report is not None
    assert report.schema_status == "legacy"
    assert report.validation_scope == "implementation_identity_and_declared_metadata"
    assert report.signature_implementation_count == 1
    assert report.metadata_incomplete_rule_ids == ("LEGACY_PYTHON_GAP",)
    assert report.promotion_blockers == (
        "manifest does not declare schema_version: 2",
        "1 rule(s) lack manifest category/severity (python=1)",
    )


def test_bundled_legacy_validation_rejects_missing_and_orphan_signatures(tmp_path: Path) -> None:
    missing_pack = _write_legacy_bundled_signature_pack(tmp_path / "missing")
    (missing_pack / "signatures.yaml").write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="Missing bundled signature implementation"):
        PackLoader().load_pack(missing_pack, validate_implementations=True)

    orphan_pack = _write_legacy_bundled_signature_pack(tmp_path / "orphan")
    implementations = [_signature("LEGACY_RULE"), _signature("UNDECLARED_RULE")]
    (orphan_pack / "signatures.yaml").write_text(
        yaml.safe_dump(implementations, sort_keys=False),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not declared in pack.yaml"):
        PackLoader().load_pack(orphan_pack, validate_implementations=True)


def test_bundled_legacy_validation_rejects_regex_with_rule_file_identity(tmp_path: Path) -> None:
    pack_dir = _write_legacy_bundled_signature_pack(tmp_path / "invalid-regex")
    implementation = {
        "id": "LEGACY_RULE",
        "category": "command_injection",
        "severity": "HIGH",
        "patterns": ["("],
        "description": "Legacy test rule",
    }
    (pack_dir / "signatures.yaml").write_text(
        yaml.safe_dump([implementation], sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match=r"Invalid regex.*LEGACY_RULE.*signatures\.yaml:patterns\[0\]",
    ):
        PackLoader().load_pack(pack_dir, validate_implementations=True)


def test_all_bundled_packs_are_strict_v2_with_complete_metadata() -> None:
    packs = {pack.name: pack for pack in PackLoader().discover_packs()}

    assert set(packs) == {"atr", "core", "promptguard"}
    for pack in packs.values():
        report = pack.validation_report
        assert report is not None
        assert pack.schema_version == 2
        assert report.schema_status == "v2"
        assert report.validation_scope == "strict_bundled_v2"
        assert report.metadata_incomplete_rule_ids == ()
        assert report.promotion_blockers == ()
        assert report.signature_implementation_count == sum(
            rule.source_type == "signature" for rule in pack.rules.values()
        )
        assert report.yara_implementation_count == sum(rule.source_type == "yara" for rule in pack.rules.values())
        assert report.python_implementation_count == sum(rule.source_type == "python" for rule in pack.rules.values())

    core_report = packs["core"].validation_report
    assert core_report is not None
    assert core_report.signature_implementation_count == len(RuleLoader(strict=True).load_rules())
