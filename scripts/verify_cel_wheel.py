#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Verify the exact native helper in one Skill Scanner platform wheel."""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import tempfile
import zipfile
from pathlib import Path

from cel_go_packaging import CEL_GO_VERSION, HELPER_PROTOCOL_VERSION, infer_host_target, resolve_target, verify_wheel


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--project-version")
    parser.add_argument("--smoke", action="store_true", help="Execute the helper; requires a matching native host")
    args = parser.parse_args()

    target = resolve_target(args.target)
    matches = sorted(args.wheel_dir.glob(f"*-{target.wheel_tag}.whl"))
    if len(matches) != 1:
        raise SystemExit(f"expected one wheel for {target.name}/{target.wheel_tag}, found {len(matches)}")
    wheel = matches[0]
    manifest = verify_wheel(wheel, target)
    helper = manifest["helper"]
    if args.project_version is not None and helper.get("helper_version") != args.project_version:
        raise SystemExit(
            f"helper version mismatch: expected {args.project_version!r}, found {helper.get('helper_version')!r}"
        )

    if args.smoke:
        host = infer_host_target()
        if host != target:
            raise SystemExit(f"cannot execute {target.name} helper on {host.name}")
        with tempfile.TemporaryDirectory(prefix="skill-scanner-cel-smoke-") as temp_dir:
            member = f"skill_scanner/core/cel/_bin/{target.filename}"
            with zipfile.ZipFile(wheel) as archive:
                extracted = Path(archive.extract(member, temp_dir))
            if target.goos != "windows":
                extracted.chmod(extracted.stat().st_mode | stat.S_IXUSR)
            env = {"PATH": os.environ.get("PATH", ""), "SYSTEMROOT": os.environ.get("SYSTEMROOT", "")}
            result = subprocess.run(
                [str(extracted), "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
            output = result.stdout.strip()
            expected_fragments = (
                f"helper={helper['helper_version']}",
                f"cel-go={CEL_GO_VERSION}",
                f"protocol={HELPER_PROTOCOL_VERSION}",
            )
            if not all(fragment in output for fragment in expected_fragments):
                raise SystemExit(f"unexpected CEL helper version output: {output!r}")
    print(f"verified {wheel.name}: {target.name} {helper['sha256']}")


if __name__ == "__main__":
    main()
