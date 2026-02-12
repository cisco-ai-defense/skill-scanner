# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Bytecode integrity checks.

Rules: BYTECODE_NO_SOURCE, BYTECODE_SOURCE_MISMATCH.

Note: These rules remain implemented inline in BytecodeAnalyzer because
they are tightly coupled to the bytecode decompilation/comparison process.
This module re-exports the rule IDs and metadata for registry/audit
purposes but does NOT duplicate the logic.

The actual implementations live in:
  skill_scanner/core/analyzers/bytecode_analyzer.py
"""

# Rule IDs provided by the bytecode analyzer (for documentation only)
BYTECODE_RULE_IDS = [
    "BYTECODE_NO_SOURCE",
    "BYTECODE_SOURCE_MISMATCH",
]
