#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Regenerate Formula/skill-scanner.rb from PyPI metadata.

Usage:
    python scripts/update_brew_formula.py --version 2.0.0
    python scripts/update_brew_formula.py          # reads version from skill_scanner/_version.py

Requires: Python 3.10+, uv (for dependency resolution).
No third-party Python packages needed (stdlib only).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import textwrap
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PYPI_PACKAGE = "cisco-ai-skill-scanner"
FORMULA_PATH = Path(__file__).resolve().parent.parent / "Formula" / "skill-scanner.rb"
VERSION_PATH = Path(__file__).resolve().parent.parent / "skill_scanner" / "_version.py"

# Packages provided by Homebrew or the system Python; skip these as resources.
SKIP_PACKAGES = frozenset(
    {
        "cisco-ai-skill-scanner",
        "pip",
        "setuptools",
        "wheel",
        "distribute",
    }
)

# Homebrew system dependencies (Ruby DSL).
SYSTEM_DEPS = [
    'depends_on "rust" => :build',
    'depends_on "python@3.12"',
]

# ---------------------------------------------------------------------------
# PyPI helpers
# ---------------------------------------------------------------------------


def pypi_json(name: str, version: str | None = None) -> dict:
    """Fetch package metadata from the PyPI JSON API."""
    if version:
        url = f"https://pypi.org/pypi/{name}/{version}/json"
    else:
        url = f"https://pypi.org/pypi/{name}/json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def find_artifact(pypi_data: dict) -> tuple[str, str]:
    """Return (url, sha256) for the best artifact.

    Preference order:
      1. sdist .tar.gz
      2. sdist (any format)
      3. Pure-Python wheel (py3-none-any)
      4. macOS ARM wheel (for Homebrew on Apple Silicon)
      5. macOS x86_64 wheel
      6. Any wheel (last resort)
    """
    urls = pypi_data.get("urls", [])

    # 1. Prefer sdist .tar.gz
    for entry in urls:
        if entry["packagetype"] == "sdist" and entry["filename"].endswith(".tar.gz"):
            return entry["url"], entry["digests"]["sha256"]

    # 2. Any sdist
    for entry in urls:
        if entry["packagetype"] == "sdist":
            return entry["url"], entry["digests"]["sha256"]

    # 3. Pure-Python wheel (works everywhere)
    for entry in urls:
        if entry["packagetype"] == "bdist_wheel" and entry["filename"].endswith("-py3-none-any.whl"):
            return entry["url"], entry["digests"]["sha256"]

    # 4-5. Platform-specific wheels -- prefer macOS for Homebrew
    #   Collect all wheels and pick the best one for macOS.
    wheels = [e for e in urls if e["packagetype"] == "bdist_wheel"]
    for tag_substr in ("macosx", "manylinux", ""):
        for entry in wheels:
            if tag_substr in entry["filename"]:
                return entry["url"], entry["digests"]["sha256"]

    # 6. Anything at all
    if urls:
        return urls[0]["url"], urls[0]["digests"]["sha256"]

    raise RuntimeError(f"No usable artifact found for {pypi_data['info']['name']} {pypi_data['info']['version']}")


# ---------------------------------------------------------------------------
# Dependency resolution via uv
# ---------------------------------------------------------------------------


def resolve_dependencies() -> list[tuple[str, str]]:
    """Use ``uv pip compile`` to resolve all transitive dependencies.

    Returns a sorted list of (normalised-name, version) tuples.
    """
    project_root = Path(__file__).resolve().parent.parent
    result = subprocess.run(
        [
            "uv",
            "pip",
            "compile",
            "pyproject.toml",
            "--no-header",
            "--no-annotate",
            "--python-version",
            "3.12",
        ],
        capture_output=True,
        text=True,
        cwd=project_root,
    )
    if result.returncode != 0:
        print("uv pip compile failed:", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(1)

    deps: list[tuple[str, str]] = []
    for line in result.stdout.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Lines look like: package==1.2.3
        match = re.match(r"^([a-zA-Z0-9_.-]+)==([^\s;]+)", line)
        if match:
            name = normalise(match.group(1))
            version = match.group(2)
            deps.append((name, version))
    return sorted(deps, key=lambda t: t[0].lower())


def normalise(name: str) -> str:
    """PEP 503 normalise a package name."""
    return re.sub(r"[-_.]+", "-", name).lower()


# ---------------------------------------------------------------------------
# Formula templating
# ---------------------------------------------------------------------------


def brew_resource_name(name: str) -> str:
    """Convert a normalised package name to the Homebrew resource name.

    Homebrew convention is to use the PyPI display name (often with caps).
    We fetch the canonical name from PyPI metadata.
    """
    return name


def render_resource(display_name: str, url: str, sha256: str) -> str:
    """Render a single Homebrew ``resource`` block (indented for class body)."""
    return f'  resource "{display_name}" do\n    url "{url}"\n    sha256 "{sha256}"\n  end'


def render_formula(
    *,
    main_url: str,
    main_sha256: str,
    resources: list[tuple[str, str, str]],
) -> str:
    """Render the full Formula/skill-scanner.rb file.

    ``resources`` is a list of (display_name, url, sha256).
    """
    resource_blocks = "\n\n".join(render_resource(name, url, sha256) for name, url, sha256 in resources)

    deps_block = "\n".join(f"  {dep}" for dep in SYSTEM_DEPS)

    # Use a raw string for the test block so Ruby's #{bin} isn't interpreted
    # as a Python f-string interpolation.
    test_cmd = "#{bin}/skill-scanner --help"

    lines = [
        "class SkillScanner < Formula",
        "  include Language::Python::Virtualenv",
        "",
        '  desc "Security scanner for AI Agent Skills and MCP servers"',
        '  homepage "https://github.com/cisco-ai-defense/skill-scanner"',
        f'  url "{main_url}"',
        f'  sha256 "{main_sha256}"',
        '  license "Apache-2.0"',
        "",
        deps_block,
        "",
        resource_blocks,
        "",
        "  def install",
        "    virtualenv_install_with_resources",
        "  end",
        "",
        "  test do",
        f'    assert_match "usage:", shell_output("{test_cmd}")',
        "  end",
        "end",
        "",  # trailing newline
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------


def read_local_version() -> str:
    """Read __version__ from skill_scanner/_version.py."""
    text = VERSION_PATH.read_text()
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', text)
    if not match:
        print(f"Could not parse version from {VERSION_PATH}", file=sys.stderr)
        sys.exit(1)
    return match.group(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description="Regenerate the Homebrew formula from PyPI metadata.")
    parser.add_argument(
        "--version",
        default=None,
        help="Package version to generate the formula for (default: read from _version.py)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the formula to stdout instead of writing the file.",
    )
    args = parser.parse_args()

    version = args.version or read_local_version()
    print(f"Generating Homebrew formula for {PYPI_PACKAGE}=={version}")

    # 1. Fetch main package metadata from PyPI
    print("  Fetching main package metadata from PyPI...")
    try:
        main_data = pypi_json(PYPI_PACKAGE, version)
    except Exception as exc:
        print(f"  ERROR: Could not fetch {PYPI_PACKAGE}=={version} from PyPI: {exc}", file=sys.stderr)
        sys.exit(1)
    main_url, main_sha256 = find_artifact(main_data)
    print(f"  Main artifact: {main_url.rsplit('/', 1)[-1]}")

    # 2. Resolve transitive dependencies
    print("  Resolving transitive dependencies via uv...")
    all_deps = resolve_dependencies()
    print(f"  Resolved {len(all_deps)} total packages")

    # 3. Fetch PyPI metadata for each dependency
    resources: list[tuple[str, str, str]] = []
    errors: list[str] = []
    wheel_only: list[str] = []
    for name, dep_version in all_deps:
        if normalise(name) in SKIP_PACKAGES:
            continue
        try:
            data = pypi_json(name, dep_version)
            url, sha256 = find_artifact(data)
            # Use the PyPI canonical display name for the resource block
            display_name = data["info"]["name"]
            resources.append((display_name, url, sha256))
            # Warn if this package has no sdist (wheel-only)
            has_sdist = any(u["packagetype"] == "sdist" for u in data.get("urls", []))
            marker = " (wheel)" if not has_sdist else ""
            print(f"    {display_name}=={dep_version}{marker}")
            if not has_sdist:
                wheel_only.append(f"{display_name}=={dep_version}")
        except Exception as exc:
            errors.append(f"{name}=={dep_version}: {exc}")
            print(f"    ERROR: {name}=={dep_version}: {exc}", file=sys.stderr)

    if errors:
        print(f"\nFailed to fetch {len(errors)} package(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    if wheel_only:
        print(f"\n  WARNING: {len(wheel_only)} package(s) have no sdist (wheel only):")
        for w in wheel_only:
            print(f"    - {w}")
        print("  These may need manual review for cross-platform Homebrew builds.")

    # 4. Render the formula
    formula = render_formula(
        main_url=main_url,
        main_sha256=main_sha256,
        resources=resources,
    )

    # 5. Write or print
    if args.dry_run:
        print("\n" + formula)
    else:
        FORMULA_PATH.parent.mkdir(parents=True, exist_ok=True)
        FORMULA_PATH.write_text(formula)
        print(f"\nWrote {FORMULA_PATH} ({len(resources)} resources)")

    print("Done.")


if __name__ == "__main__":
    main()
