# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: one very long line must not make signature scanning super-linear."""

from __future__ import annotations

import time

from skill_scanner.core.rules.patterns import RuleLoader


def test_long_comment_line_scans_in_bounded_time():
    rules = {r.id: r for r in RuleLoader().load_rules()}
    rule = rules["COMMAND_INJECTION_USER_INPUT"]
    content = "#" * (200 * 1024) + "\n"

    start = time.perf_counter()
    rule.scan_content(content, "scripts/run.sh")
    elapsed = time.perf_counter() - start

    assert elapsed < 2.0, f"scan of a single 200 KB line took {elapsed:.1f}s"


def test_eval_exclude_still_applies_to_commented_lines():
    rule = {r.id: r for r in RuleLoader().load_rules()}["COMMAND_INJECTION_USER_INPUT"]
    assert rule.scan_content('eval "$1"\n', "a.sh")
    assert not rule.scan_content('# eval "$1"\n', "a.sh")
    assert not rule.scan_content('x=1 # eval "$1"\n', "a.sh")


def test_ransomware_chain_long_identifier_line_scans_in_bounded_time():
    rule = {r.id: r for r in RuleLoader().load_rules()}["MALWARE_RANSOMWARE_IMPLEMENTATION_CHAIN"]
    content = "#" + "a" * (64 * 1024) + "\n"

    start = time.perf_counter()
    rule.scan_content(content, "scripts/run.py")
    elapsed = time.perf_counter() - start

    assert elapsed < 2.0, f"scan of a single 64 KB line took {elapsed:.1f}s"


def test_ransomware_chain_still_detected():
    rule = {r.id: r for r in RuleLoader().load_rules()}["MALWARE_RANSOMWARE_IMPLEMENTATION_CHAIN"]
    code = (
        "for f in root.rglob('*'):\n    data = Fernet(key).encrypt(f.read_bytes())\n    open(RANSOM_NOTE).write(msg)\n"
    )
    assert rule.scan_content(code, "a.py")
