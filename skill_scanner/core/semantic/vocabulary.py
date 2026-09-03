# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Closed vocabularies for suppression-relevant semantic classifications.

These values are deliberately boring enums. Analyzer snippets and arbitrary
metadata must never be copied into the typed CEL projection merely because
they happen to be strings.
"""

from __future__ import annotations

CONTEXT_KINDS = frozenset(
    {
        "active_instruction",
        "binary",
        "code",
        "dependency_file",
        "documentation",
        "example",
        "instruction",
        "manifest",
        "negative_example",
        "package",
        "prohibition",
    }
)
EVIDENCE_KINDS = frozenset(
    {
        "archive_inventory",
        "binary_signature",
        "capability_mismatch",
        "command",
        "command_pipeline",
        "command_sequence",
        "correlated_behavior",
        "dependency_advisory",
        "dependency_declaration",
        "emoji_sequence",
        "fenced_code_flow",
        "file_analyzability",
        "file_inventory",
        "file_magic",
        "hidden_html_instruction",
        "pattern_match",
        "regional_indicator_sequence",
        "signature_pattern",
        "skill_chain_stage",
        "subshell_candidate",
        "unicode_confusable",
        "unicode_smuggling",
        "visual_spoof_candidate",
    }
)
SOURCE_SINK_CLASSES = frozenset(
    {
        "agent_read",
        "archive",
        "code_execution",
        "command_action",
        "content_search",
        "credential_file",
        "credential_reference",
        "document",
        "environment_reference",
        "execution",
        "external_network",
        "filesystem",
        "filesystem_enumeration",
        "filesystem_path",
        "filesystem_read",
        "filesystem_write",
        "network",
        "none",
        "obfuscation",
        "parameter_literal",
        "process_execution",
        "resource_consumption",
        "scheduler",
        "sensitive_data",
        "sensitive_environment",
        "shell_execution",
        "signature_candidate",
        "skill_code",
        "sql_parser",
        "template_render",
        "template_value",
        "user_input",
    }
)
DOMAIN_CLASSES = frozenset(
    {
        "configured_service",
        "declared_service",
        "dynamic",
        "external",
        "ip_address",
        "known_installer",
        "legitimate",
        "local",
        "private_ip",
        "public",
        "provider_bound_service",
        "suspicious",
        "untrusted",
    }
)
DIRECTIONS = frozenset({"inbound", "outbound", "reference"})
HTTP_METHODS = frozenset({"delete", "get", "patch", "post", "put"})
TRANSFORMS = frozenset({"decode", "document_conversion", "extraction", "interpolation", "obfuscation", "pipe"})
SIGNAL_KINDS = frozenset(
    {
        "archive_binary",
        "archived_executable",
        "compound_flow",
        "correlated_behavior",
        "embedded_shebang",
        "fenced_code_language",
        "file_role",
        "file_magic_mismatch",
        "finding",
        "hidden_executable",
        "hidden_file",
        "known_vulnerability",
        "manifest_capability_mismatch",
        "nested_archive_script",
        "package_reference",
        "signature_polarity",
        "skill_chain_active_stage",
        "taint_flow",
        "unanalyzable_binary",
        "undeclared_capability",
        "undeclared_network",
        "undeclared_tool",
        "undocumented_network",
        "unicode_homoglyph",
        "unpinned_dependency",
        "unreferenced_executable",
    }
)
REFERENCE_KINDS = frozenset({"instruction_reference", "package_reference"})
FILE_KINDS = frozenset(
    {
        "archive",
        "bash",
        "binary",
        "config",
        "javascript",
        "markdown",
        "other",
        "python",
        "typescript",
        "unknown",
    }
)
FILE_ROLES = frozenset({"asset", "code", "documentation", "instruction", "package", "test_or_example"})
ARGUMENT_CLASSES = frozenset(
    {
        "archive_path",
        "command_substitution",
        "credential_authentication",
        "credential_payload",
        "delete_action",
        "dynamic",
        "destination_configured_service",
        "destination_declared_service",
        "destination_dynamic",
        "destination_external",
        "destination_legitimate",
        "destination_provider_bound_service",
        "destination_suspicious",
        "environment_reference",
        "exec_action",
        "executable_permission",
        "inline_code",
        "literal",
        "output_path",
        "pipe",
        "request_body",
        "request_header",
        "request_method",
        "script_path",
        "sensitive_path",
        "standard_stream",
        "url",
        "wildcard",
    }
)

EVIDENCE_VALUE_CLASSES = frozenset(
    {
        "active_backtick_substitution",
        "active_cjk_compatibility_identifier",
        "active_cyrillic_spoof_token",
        "active_dollar_subshell",
        "active_interpolated_execution",
        "active_mixed_script_code",
        "active_mixed_script_domain",
        "active_mixed_script_identifier",
        "active_prompt_access",
        "active_prompt_override",
        "argument_hint_placeholder",
        "ambiguous_truncate_term",
        "ambiguous_rgi_sequence",
        "bidi_control",
        "bmp_pictograph_sequence",
        "broad_scope_literal",
        "command_option_name",
        "comment_syntax",
        "communication_action_term",
        "contextual_country_flag_sequence",
        "contextual_forex_flag_sequence",
        "credential_file_to_external_network",
        "decoded_injection_payload",
        "destructive_action_term",
        "egress_action_stage",
        "embedded_shebang_offset_4096_plus",
        "embedded_shebang_offset_65_4095",
        "encoded_archive_hidden_stage_execute",
        "encoded_shell_decode_execute",
        "encoding_transform_stage",
        "environment_access",
        "external_endpoint_scheduled_persistence",
        "execution_action_term",
        "execution_api",
        "external_destination_stage",
        "fence_language_marker",
        "file_mutation_api",
        "financial_action_term",
        "generic_environment_reference",
        "hidden_comment_override_execution",
        "hidden_comment_override_sensitive_action",
        "hidden_element_override_execution",
        "hidden_element_override_sensitive_action",
        "identifier_substring",
        "identity_comparison_guard",
        "injection_context",
        "known_vulnerable_dependency",
        "large_value_literal",
        "layout_symbol_only",
        "markdown_html_attribute",
        "markdown_inline_code",
        "markdown_relative_link",
        "mixed_zero_width_active_intent",
        "multiple_regional_indicator_runs",
        "natural_cjk_prose",
        "natural_cyrillic_prose",
        "natural_cyrillic_short_token",
        "network_api",
        "non_privilege_root_assignment",
        "non_rgi_letter_run",
        "null_byte_marker",
        "numeric_escape_prefix",
        "opaque_binary",
        "privilege_action_term",
        "privilege_configuration",
        "privilege_system_path",
        "policy_taxonomy_stage",
        "passive_non_sql_truncate",
        "prose_list_separator",
        "prose_truncate_term",
        "prompt_authoring_reference",
        "prompt_runtime_reference",
        "punycode_domain",
        "relative_path_traversal",
        "regex_literal_privilege_pattern",
        "raw_ip_download_execute",
        "remote_config_stage_execute",
        "remote_miner_acquire_execute",
        "secret_access",
        "secret_identifier",
        "sensitive_environment_reference",
        "sensitive_source_stage",
        "sensitive_template_interpolation",
        "shell_injection_sequence",
        "shell_interpolation",
        "shell_stdin_capture_assignment",
        "sql_privilege_statement",
        "sql_injection_sequence",
        "string_interpolation",
        "supplementary_emoji_sequence",
        "template_directive",
        "template_placeholder",
        "cryptomining_config_execute",
        "template_to_execution",
        "template_to_path",
        "template_to_sql",
        "trusted_documented_installer",
        "trusted_installer_code",
        "unicode_tag_cooccurrence",
        "unclassified",
        "unpinned_dependency",
        "untrusted_fetch_execute",
        "zero_width_active_intent",
        "wildcard_dependency",
        "non_fetch_execute",
    }
)

SIGNAL_VALUE_CLASSES = frozenset(
    {
        "active",
        "autonomy_abuse",
        "bash",
        "binary",
        "code_execution",
        "command_injection",
        "config",
        "credential_file_to_external_network",
        "cryptomining_config_execute",
        "data_exfiltration",
        "documented_installer",
        "embedded_shebang_offset_4096_plus",
        "embedded_shebang_offset_65_4095",
        "encoded_archive_hidden_stage_execute",
        "encoded_shell_decode_execute",
        "encoding_transform_stage",
        "execution",
        "external_endpoint_scheduled_persistence",
        "external_network",
        "file",
        "glob",
        "grep",
        "hardcoded_secrets",
        "harmful_content",
        "javascript",
        "malware",
        "markdown",
        "network",
        "negative",
        "nested_archive",
        "obfuscation",
        "other",
        "policy_violation",
        "prompt_injection",
        "python",
        "raw_ip_download_execute",
        "read",
        "remote_config_stage_execute",
        "remote_miner_acquire_execute",
        "resource_abuse",
        "sensitive_file_read",
        "sensitive_source",
        "sensitive_source_stage",
        "illustrative",
        "skill_discovery_abuse",
        "social_engineering",
        "supply_chain_attack",
        "tool_chaining_abuse",
        "transitive_trust_abuse",
        "typescript",
        "unauthorized_tool_use",
        "unicode_steganography",
        "unknown",
        "write",
    }
)


def classification_values(container: str, leaf: str) -> frozenset[str] | None:
    """Return the closed catalog for a typed classification leaf."""

    if container == "candidate" and leaf == "context_kind":
        return CONTEXT_KINDS
    if container == "candidate" and leaf == "evidence_kind":
        return EVIDENCE_KINDS
    if container == "candidate" and leaf == "evidence_value_class":
        return EVIDENCE_VALUE_CLASSES
    if leaf in {"source_class", "sink_class"}:
        return SOURCE_SINK_CLASSES
    if container in {"url", "urls"} and leaf == "domain_class":
        return DOMAIN_CLASSES
    if container in {"url", "urls"} and leaf == "direction":
        return DIRECTIONS
    if container in {"url", "urls"} and leaf == "method":
        return HTTP_METHODS
    if container in {"flow", "flows"} and leaf == "transforms":
        return TRANSFORMS
    if container in {"command", "commands"} and leaf == "argument_classes":
        return ARGUMENT_CLASSES
    if container == "signals" and leaf == "kind":
        return SIGNAL_KINDS
    if container == "signals" and leaf == "value_class":
        return SIGNAL_VALUE_CLASSES | EVIDENCE_VALUE_CLASSES
    if container == "reference_edges" and leaf == "kind":
        return REFERENCE_KINDS
    if container in {"file", "files"} and leaf == "kind":
        return FILE_KINDS
    if container in {"file", "files"} and leaf == "role":
        return FILE_ROLES
    return None
