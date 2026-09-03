#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Build a qualified cel-go helper for development or release packaging."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from cel_go_packaging import build_helper, project_root, resolve_target, write_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target",
        choices=("host", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64", "windows-amd64"),
        default="host",
    )
    parser.add_argument("--output-dir", type=Path, help="Directory for the binary and manifest")
    parser.add_argument(
        "--in-place", action="store_true", help="Write to skill_scanner/core/cel/_bin for source checkout use"
    )
    parser.add_argument("--helper-version", default="source-tree", help="Version recorded by the helper and manifest")
    args = parser.parse_args()
    if args.in_place and args.output_dir is not None:
        parser.error("--in-place and --output-dir are mutually exclusive")

    root = project_root()
    target = resolve_target(None if args.target == "host" else args.target)
    if args.in_place:
        output_dir = root / "skill_scanner" / "core" / "cel" / "_bin"
    elif args.output_dir is not None:
        output_dir = args.output_dir.resolve()
    else:
        output_dir = Path(tempfile.mkdtemp(prefix="skill-scanner-cel-go-"))

    binary = output_dir / target.filename
    helper = build_helper(
        root=root,
        target=target,
        output=binary,
        helper_version=args.helper_version,
    )
    write_manifest(output_dir / "manifest.json", helper)
    print(json.dumps({"binary": str(binary), "manifest": str(output_dir / "manifest.json"), **helper}, sort_keys=True))


if __name__ == "__main__":
    main()
