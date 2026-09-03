# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
from pathlib import Path

EVIDENCE_FILE = (
    Path(__file__).parent / "fixtures" / "correlation_official_goodware_precision_msb_non_test_2026-09-02.json"
)


def test_correlation_precision_evidence_is_hash_bound_and_recall_safe() -> None:
    evidence_bytes = EVIDENCE_FILE.read_bytes()
    evidence = json.loads(evidence_bytes)
    sidecar = EVIDENCE_FILE.with_suffix(".json.sha256").read_text(encoding="utf-8").split()

    assert sidecar == [hashlib.sha256(evidence_bytes).hexdigest(), EVIDENCE_FILE.name]
    assert evidence["safety"] == {
        "raw_sample_content_embedded": False,
        "sample_content_executed": False,
        "sample_network_access": False,
        "sealed_test_rows_scanned": 0,
        "vendor_allowlist_used": False,
    }
    assert set(evidence["rules"]) == {
        "CORRELATED_NETWORK_EXECUTION_FLOW",
        "CORRELATED_SENSITIVE_NETWORK_FLOW",
    }

    official = evidence["official_goodware"]
    assert official["denominator"] == official["scanned"] == 110
    assert official["load_errors"] == official["analyzer_partial_failures"] == 0
    assert official["targeted_high_plus_before"] == 2
    assert official["targeted_high_plus_after"] == 0
    assert official["targeted_medium_after"] == 1
    assert official["off_shadow_finding_identities_equal"] is True
    assert official["shadow_fallbacks"] == official["shadow_projection_incomplete"] == 0

    msb = evidence["malicious_skill_bench"]
    assert msb["revision"] == "d4b42ce5766a6e0359c987cf59c1007cb3795a90"
    assert msb["declared_samples"] == 6597
    assert msb["usable_samples"] == 6594
    assert msb["quarantined_or_unavailable"] == 3
    assert msb["correlation_finding_identity_differences"] == 0
    assert msb["malicious_package_block_losses"] == 0
    assert msb["malicious_any_signal_losses"] == 0
    assert msb["malicious_critical_high_finding_losses"] == 0
