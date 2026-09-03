# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Shadow-stage CEL expressions for high-volume precision candidates.

These fixtures deliberately live outside bundled manifests until each rule has
benchmark evidence and satisfies the promotion gates.  They are still checked
by the exact bounded validator used for trusted packs.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

_DOCUMENT_OR_EXAMPLE_FILTER = """\
f.candidate.file_path == "SKILL.md" ||
(f.candidate.file.role != "documentation" &&
 f.candidate.file.role != "test_or_example")
"""

_UNANALYZABLE_BINARY_FILTER = """\
!f.candidate.file.analyzable &&
(f.candidate.file.hidden ||
 f.candidate.file.executable ||
 f.candidate.file.magic_mismatch ||
 "FILE_MAGIC_MISMATCH" in f.candidate.cooccurring_rule_ids ||
 (f.candidate.file.referenced &&
  f.candidate.file.role != "asset" &&
  f.candidate.file.role != "documentation" &&
  f.candidate.file.role != "test_or_example") ||
 f.candidate.cooccurring_rule_ids.exists(r, r.startsWith("YARA_")) ||
 f.skill.flows.exists(x,
   x.source_path == f.candidate.file_path ||
   x.sink_path == f.candidate.file_path))
"""

_ALLOWED_TOOLS_NETWORK_USAGE_SHADOW = """\
f.candidate.evidence_kind != "capability_mismatch" ||
f.candidate.context_kind != "manifest" ||
f.candidate.flow.source_class != "skill_code" ||
f.candidate.flow.sink_class != "external_network" ||
!f.skill.declares_network
"""

_UNANALYZABLE_BINARY_SHADOW = """\
f.candidate.evidence_kind != "file_analyzability" ||
f.candidate.evidence_value_class != "opaque_binary" ||
f.candidate.context_kind != "binary" ||
(!f.candidate.file.analyzable &&
 (f.candidate.file.hidden ||
  f.candidate.file.executable ||
  f.candidate.file.magic_mismatch ||
  "FILE_MAGIC_MISMATCH" in f.candidate.cooccurring_rule_ids ||
  (f.candidate.file.referenced &&
   f.candidate.file.role != "asset" &&
   f.candidate.file.role != "documentation" &&
   f.candidate.file.role != "test_or_example") ||
  f.candidate.cooccurring_rule_ids.exists(r, r.startsWith("YARA_"))))
"""

_EMBEDDED_SHEBANG_BINARY_SHADOW = """\
f.candidate.evidence_kind != "binary_signature" ||
f.candidate.context_kind != "binary" ||
(f.candidate.evidence_value_class != "embedded_shebang_offset_65_4095" &&
 f.candidate.evidence_value_class != "embedded_shebang_offset_4096_plus") ||
(f.candidate.evidence_value_class == "embedded_shebang_offset_65_4095" &&
 f.candidate.evidence_count < 65u) ||
(f.candidate.evidence_value_class == "embedded_shebang_offset_4096_plus" &&
 f.candidate.evidence_count != 4096u) ||
f.candidate.file.kind != "binary" ||
f.candidate.file.analyzable ||
f.candidate.file.hidden ||
f.candidate.file.executable ||
f.candidate.file.magic_mismatch ||
"FILE_MAGIC_MISMATCH" in f.candidate.cooccurring_rule_ids ||
(f.candidate.file.referenced &&
 f.candidate.file.role != "asset" &&
 f.candidate.file.role != "documentation" &&
 f.candidate.file.role != "test_or_example") ||
f.candidate.cooccurring_rule_ids.exists(r, r.startsWith("YARA_"))
"""

_HIDDEN_EXECUTABLE_ROLE_SHADOW = """\
f.candidate.evidence_kind != "file_inventory" ||
f.candidate.context_kind != "code" ||
!f.candidate.file.hidden ||
f.candidate.file.executable ||
(f.candidate.file.referenced &&
 f.candidate.file.role != "asset" &&
 f.candidate.file.role != "documentation" &&
 f.candidate.file.role != "test_or_example") ||
f.candidate.cooccurring_rule_ids.exists(r, r != "BINARY_FILE_DETECTED")
"""

_COMPOUND_FIND_EXEC_DOCUMENTATION_SHADOW = """\
f.candidate.evidence_kind != "command_sequence" ||
f.candidate.context_kind != "documentation" ||
f.candidate.flow.source_class != "filesystem" ||
f.candidate.flow.sink_class != "execution" ||
f.candidate.command.executable != "find" ||
!f.candidate.command.executes ||
!("exec_action" in f.candidate.command.argument_classes)
"""

_REMOTE_MINER_CONTEXT_SHADOW = """\
f.candidate.evidence_kind != "correlated_behavior" ||
f.candidate.evidence_value_class != "remote_miner_acquire_execute" ||
f.candidate.context_kind == "active_instruction" ||
f.candidate.context_kind == "code" ||
f.candidate.context_kind == "unknown" ||
(f.candidate.context_kind != "prohibition" &&
 f.candidate.context_kind != "negative_example" &&
 f.candidate.context_kind != "example")
"""

_CORRELATED_SENSITIVE_NETWORK_CONTEXT_SHADOW = """\
(f.candidate.evidence_kind != "correlated_behavior" &&
 f.candidate.evidence_kind != "fenced_code_flow") ||
(f.candidate.flow.source_class != "credential_file" &&
 f.candidate.flow.source_class != "sensitive_environment" &&
 f.candidate.flow.source_class != "sensitive_file") ||
f.candidate.flow.sink_class != "network" ||
(f.candidate.context_kind != "prohibition" &&
 f.candidate.context_kind != "negative_example")
"""

_CORRELATED_NETWORK_EXECUTION_CONTEXT_SHADOW = """\
(f.candidate.evidence_kind != "correlated_behavior" &&
 f.candidate.evidence_kind != "fenced_code_flow") ||
f.candidate.flow.source_class != "network" ||
f.candidate.flow.sink_class != "code_execution" ||
(f.candidate.context_kind != "prohibition" &&
 f.candidate.context_kind != "negative_example")
"""

_CORRELATED_OBFUSCATION_EXECUTION_CONTEXT_SHADOW = """\
(f.candidate.evidence_kind != "correlated_behavior" &&
 f.candidate.evidence_kind != "fenced_code_flow") ||
f.candidate.flow.source_class != "obfuscation" ||
f.candidate.flow.sink_class != "code_execution" ||
(f.candidate.context_kind != "prohibition" &&
 f.candidate.context_kind != "negative_example")
"""

_SIGNATURE_INERT_CONTEXT_SHADOW = """\
f.candidate.evidence_kind != "signature_pattern" ||
f.candidate.context_kind == "active_instruction" ||
f.candidate.context_kind == "code" ||
f.candidate.context_kind == "unknown" ||
(f.candidate.context_kind != "prohibition" &&
 f.candidate.context_kind != "negative_example" &&
 f.candidate.file.role != "documentation" &&
 f.candidate.file.role != "test_or_example")
"""


def _freeze_disjoint_generation(
    *groups: Mapping[str, str],
) -> Mapping[str, str]:
    """Merge reviewed groups immutably and reject accidental key overwrite."""

    generation: dict[str, str] = {}
    for group in groups:
        overlap = generation.keys() & group.keys()
        if overlap:
            duplicate_ids = ", ".join(sorted(overlap))
            raise ValueError(f"CEL generation contains duplicate rule IDs: {duplicate_ids}")
        generation.update(group)
    return MappingProxyType(generation)


PRECISION_GATES: dict[str, str] = {
    "GLOB_HIDDEN_FILE_TARGETING": _SIGNATURE_INERT_CONTEXT_SHADOW,
    "HIDDEN_EXECUTABLE_SCRIPT": """\
f.candidate.file.hidden &&
f.skill.signals.exists(s,
  s.kind == "unreferenced_executable" &&
  s.file_path == f.candidate.file_path)
""",
    "FIND_EXEC_PATTERN": _SIGNATURE_INERT_CONTEXT_SHADOW,
    "COMPOUND_FIND_EXEC": 'f.candidate.context_kind != "documentation"',
    "HOMOGLYPH_ATTACK": """\
f.candidate.evidence_kind == "unicode_confusable" &&
f.candidate.context_kind == "code" &&
f.candidate.file.role != "documentation" &&
f.candidate.file.role != "test_or_example"
""",
    "UNANALYZABLE_BINARY": _UNANALYZABLE_BINARY_FILTER,
    "BINARY_FILE_DETECTED": _UNANALYZABLE_BINARY_FILTER,
    "YARA_embedded_shebang_in_binary": """\
f.candidate.evidence_kind == "binary_signature" &&
f.candidate.context_kind == "binary" &&
f.candidate.file.kind == "binary" &&
!f.candidate.file.analyzable &&
f.skill.signals.exists(s,
  s.kind == "embedded_shebang" &&
  s.file_path == f.candidate.file_path)
""",
    "TOOL_ABUSE_UNDECLARED_NETWORK": """\
f.candidate.evidence_kind == "capability_mismatch" &&
f.candidate.context_kind == "manifest" &&
!f.skill.declares_network &&
f.candidate.flow.source_class == "skill_code" &&
f.candidate.flow.sink_class == "external_network"
""",
    "ALLOWED_TOOLS_NETWORK_USAGE": _ALLOWED_TOOLS_NETWORK_USAGE_SHADOW,
}


def _tool_gate(tool: str) -> str:
    return f"""\
f.candidate.evidence_kind == "capability_mismatch" &&
f.candidate.context_kind == "manifest" &&
f.candidate.command.executable == "{tool}" &&
!("{tool}" in f.skill.declared_tools) &&
!("{tool.lower()}" in f.skill.declared_tools)
"""


for _tool in ("Read", "Write", "Bash", "Grep", "Glob"):
    PRECISION_GATES[f"ALLOWED_TOOLS_{_tool.upper()}_VIOLATION"] = _tool_gate(_tool)


# This is an isolated scanner-owned development shadow generation. It uses
# only analyzer-emitted normalized facts. The rules below have complete
# real-candidate fixtures and are bundled for production shadow telemetry;
# they remain non-enforcing until labeled promotion evidence satisfies the
# recall, false-positive, fallback, stability, and latency gates.
BUNDLED_SCANNER_OWNED_SHADOW_GATES: Mapping[str, str] = MappingProxyType(
    {
        "ALLOWED_TOOLS_NETWORK_USAGE": _ALLOWED_TOOLS_NETWORK_USAGE_SHADOW,
        "COMPOUND_FIND_EXEC": _COMPOUND_FIND_EXEC_DOCUMENTATION_SHADOW,
        "FIND_EXEC_PATTERN": _SIGNATURE_INERT_CONTEXT_SHADOW,
        "GLOB_HIDDEN_FILE_TARGETING": _SIGNATURE_INERT_CONTEXT_SHADOW,
        "HIDDEN_EXECUTABLE_SCRIPT": _HIDDEN_EXECUTABLE_ROLE_SHADOW,
        "UNANALYZABLE_BINARY": _UNANALYZABLE_BINARY_SHADOW,
        "YARA_SUSP_Multi_RemoteMiner_AcquireExec_Sep26": _REMOTE_MINER_CONTEXT_SHADOW,
        "YARA_embedded_shebang_in_binary": _EMBEDDED_SHEBANG_BINARY_SHADOW,
    }
)

# The remaining scanner-owned gates stay development-only. Keeping the full
# set separately named prevents a benchmark or manifest update from silently
# treating experimental flow/role gates as bundled policy.
SCANNER_OWNED_SHADOW_GATES: Mapping[str, str] = _freeze_disjoint_generation(
    BUNDLED_SCANNER_OWNED_SHADOW_GATES,
    {
        "CORRELATED_NETWORK_EXECUTION_FLOW": _CORRELATED_NETWORK_EXECUTION_CONTEXT_SHADOW,
        "CORRELATED_OBFUSCATION_EXECUTION_FLOW": _CORRELATED_OBFUSCATION_EXECUTION_CONTEXT_SHADOW,
        "CORRELATED_SENSITIVE_NETWORK_FLOW": _CORRELATED_SENSITIVE_NETWORK_CONTEXT_SHADOW,
    },
)
