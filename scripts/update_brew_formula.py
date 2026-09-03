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

Requires: CPython 3.11-3.14, uv (for dependency resolution).
No third-party Python packages needed (stdlib only).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath
from typing import cast

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PYPI_PACKAGE = "cisco-ai-skill-scanner"
FORMULA_PATH = Path(__file__).resolve().parent.parent / "Formula" / "skill-scanner.rb"
VERSION_PATH = Path(__file__).resolve().parent.parent / "skill_scanner" / "_version.py"
CEL_WHEEL_TAGS = {
    "darwin-amd64": "cp311.cp312.cp313.cp314-none-macosx_13_0_x86_64",
    "darwin-arm64": "cp311.cp312.cp313.cp314-none-macosx_13_0_arm64",
}
MAX_SDIST_BYTES = 50 * 1024 * 1024
MAX_PYPROJECT_BYTES = 1024 * 1024

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
    'depends_on "go" => :build',
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
        return cast(dict, json.loads(resp.read()))


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


def validate_cel_project_wheels(pypi_data: dict) -> dict[str, tuple[str, str]]:
    """Require one exact CPython/macOS wheel for both Homebrew CPUs."""

    urls = pypi_data.get("urls", [])
    selected: dict[str, tuple[str, str]] = {}
    for target, wheel_tag in CEL_WHEEL_TAGS.items():
        matches = [
            entry
            for entry in urls
            if entry.get("packagetype") == "bdist_wheel"
            and isinstance(entry.get("filename"), str)
            and entry["filename"].endswith(f"-{wheel_tag}.whl")
        ]
        if len(matches) != 1:
            raise RuntimeError(f"expected exactly one {target} release wheel tagged {wheel_tag}; found {len(matches)}")
        entry = matches[0]
        sha256 = entry.get("digests", {}).get("sha256")
        if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise RuntimeError(f"{target} release wheel is missing a valid SHA-256 digest")
        selected[target] = (entry["url"], sha256)
    return selected


def _wheel_is_cpython312_compatible(filename: str) -> bool:
    try:
        _distribution, python_tag, abi_tag, _platform_tag = filename.removesuffix(".whl").rsplit("-", 3)
    except ValueError:
        return False
    tags = python_tag.split(".")
    if "cp312" in tags or (abi_tag == "none" and "py3" in tags):
        return True
    if abi_tag != "abi3":
        return False
    for tag in tags:
        match = re.fullmatch(r"cp(\d)(\d+)", tag)
        if match and (int(match.group(1)), int(match.group(2))) <= (3, 12):
            return True
    return False


def _macos_wheel_rank(filename: str, architecture: str) -> tuple[int, int, int, str] | None:
    try:
        _distribution, _python_tag, _abi_tag, platform_tag = filename.removesuffix(".whl").rsplit("-", 3)
    except ValueError:
        return None
    candidates: list[tuple[int, int, int, str]] = []
    for tag in platform_tag.split("."):
        match = re.fullmatch(r"macosx_(\d+)_(\d+)_(arm64|x86_64|universal2)", tag)
        if match is None or match.group(3) not in {architecture, "universal2"}:
            continue
        # Prefer the lowest deployment floor, then a native architecture over
        # universal2. The filename makes the selection deterministic.
        candidates.append((int(match.group(1)), int(match.group(2)), match.group(3) == "universal2", filename))
    return min(candidates) if candidates else None


def select_macos_wheel_resources(pypi_data: dict) -> dict[str, tuple[str, str]]:
    """Select CPython 3.12-compatible wheels for both Homebrew CPUs."""

    selected: dict[str, tuple[str, str]] = {}
    for target, architecture in (("darwin-arm64", "arm64"), ("darwin-amd64", "x86_64")):
        matches: list[tuple[tuple[int, int, int, str], dict]] = []
        for entry in pypi_data.get("urls", []):
            filename = entry.get("filename")
            if entry.get("packagetype") != "bdist_wheel" or not isinstance(filename, str):
                continue
            if not _wheel_is_cpython312_compatible(filename):
                continue
            rank = _macos_wheel_rank(filename, architecture)
            if rank is not None:
                matches.append((rank, entry))
        if not matches:
            name = pypi_data.get("info", {}).get("name", "dependency")
            version = pypi_data.get("info", {}).get("version", "unknown")
            raise RuntimeError(f"{name}=={version} has no CPython 3.12 wheel for {target}")
        entry = min(matches, key=lambda item: item[0])[1]
        sha256 = entry.get("digests", {}).get("sha256")
        url = entry.get("url")
        if not isinstance(url, str) or not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise RuntimeError(f"{target} dependency wheel is missing a URL or valid SHA-256 digest")
        selected[target] = (url, sha256)
    return selected


def require_project_sdist(pypi_data: dict, version: str) -> tuple[str, str, str]:
    """Return the one exact release sdist URL, digest, and filename.

    Homebrew builds the project source while injecting a qualified Darwin
    helper. Falling back to a wheel or resolving dependencies from the current
    checkout would let ``--version`` silently describe a different release.
    """

    info = pypi_data.get("info")
    if not isinstance(info, dict):
        raise RuntimeError("PyPI release metadata is missing its info object")
    if normalise(str(info.get("name", ""))) != normalise(PYPI_PACKAGE):
        raise RuntimeError(f"PyPI metadata does not describe {PYPI_PACKAGE}")
    if info.get("version") != version:
        raise RuntimeError(f"PyPI metadata version {info.get('version')!r} does not match requested {version!r}")

    matches = [
        entry
        for entry in pypi_data.get("urls", [])
        if entry.get("packagetype") == "sdist"
        and isinstance(entry.get("filename"), str)
        and entry["filename"].endswith(".tar.gz")
    ]
    if len(matches) != 1:
        raise RuntimeError(f"expected exactly one .tar.gz source distribution for {version}; found {len(matches)}")
    entry = matches[0]
    url = entry.get("url")
    sha256 = entry.get("digests", {}).get("sha256")
    filename = entry["filename"]
    if not isinstance(url, str) or urllib.parse.urlparse(url).scheme != "https":
        raise RuntimeError("release source distribution must use an HTTPS URL")
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise RuntimeError("release source distribution is missing a valid SHA-256 digest")
    if Path(urllib.parse.urlparse(url).path).name != filename:
        raise RuntimeError("release source distribution URL and filename disagree")
    return url, sha256, filename


def download_verified_sdist(url: str, expected_sha256: str) -> bytes:
    """Download a bounded source distribution and verify the PyPI digest."""

    request = urllib.request.Request(url, headers={"Accept": "application/octet-stream"})
    with urllib.request.urlopen(request, timeout=60) as response:
        length = response.headers.get("Content-Length")
        if length is not None and int(length) > MAX_SDIST_BYTES:
            raise RuntimeError(f"release source distribution exceeds {MAX_SDIST_BYTES} bytes")
        payload = cast(bytes, response.read(MAX_SDIST_BYTES + 1))
    if len(payload) > MAX_SDIST_BYTES:
        raise RuntimeError(f"release source distribution exceeds {MAX_SDIST_BYTES} bytes")
    actual_sha256 = hashlib.sha256(payload).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"release source distribution SHA-256 mismatch: expected {expected_sha256}, found {actual_sha256}"
        )
    return payload


def read_sdist_pyproject(payload: bytes) -> bytes:
    """Read the release pyproject without extracting or executing the sdist."""

    pyprojects: list[tarfile.TarInfo] = []
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz")
    except (tarfile.TarError, OSError) as exc:
        raise RuntimeError(f"release source distribution is not a valid gzip tar archive: {exc}") from exc
    with archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "\\" in member.name:
                raise RuntimeError(f"unsafe source distribution member: {member.name!r}")
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise RuntimeError(f"unsupported source distribution member type: {member.name!r}")
            if member.isfile() and len(path.parts) == 2 and path.name == "pyproject.toml":
                pyprojects.append(member)
        if len(pyprojects) != 1:
            raise RuntimeError(
                f"release source distribution must contain one top-level pyproject.toml; found {len(pyprojects)}"
            )
        member = pyprojects[0]
        if member.size > MAX_PYPROJECT_BYTES:
            raise RuntimeError(f"release pyproject.toml exceeds {MAX_PYPROJECT_BYTES} bytes")
        stream = archive.extractfile(member)
        if stream is None:
            raise RuntimeError("could not read release pyproject.toml")
        pyproject = stream.read(MAX_PYPROJECT_BYTES + 1)
    if len(pyproject) > MAX_PYPROJECT_BYTES:
        raise RuntimeError(f"release pyproject.toml exceeds {MAX_PYPROJECT_BYTES} bytes")
    return pyproject


# ---------------------------------------------------------------------------
# Dependency resolution via uv
# ---------------------------------------------------------------------------


def resolve_dependencies(project_file: Path) -> list[tuple[str, str]]:
    """Resolve dependencies from the exact release's extracted pyproject.

    Returns a sorted list of (normalised-name, version) tuples.
    """
    project_file = project_file.resolve(strict=True)
    result = subprocess.run(
        [
            "uv",
            "pip",
            "compile",
            str(project_file),
            "--no-header",
            "--no-annotate",
            "--python-version",
            "3.12",
        ],
        capture_output=True,
        text=True,
        cwd=project_file.parent,
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


def render_cel_helper_resources(
    cel_helper_wheels: dict[str, tuple[str, str]],
    architecture_resources: dict[str, list[tuple[str, str, str]]] | None = None,
) -> str:
    blocks: list[str] = []
    for condition, target in (("on_arm", "darwin-arm64"), ("on_intel", "darwin-amd64")):
        url, sha256 = cel_helper_wheels[target]
        blocks.append(f"  {condition} do")
        resources = [("cel-helper", url, sha256), *((architecture_resources or {}).get(target, []))]
        for name, resource_url, resource_sha256 in resources:
            blocks.extend(
                [
                    f'    resource "{name}" do',
                    f'      url "{resource_url}"',
                    f'      sha256 "{resource_sha256}"',
                    "    end",
                ]
            )
        blocks.append("  end")
    return "\n".join(blocks)


def render_formula(
    *,
    main_url: str,
    main_sha256: str,
    resources: list[tuple[str, str, str]],
    cel_helper_wheels: dict[str, tuple[str, str]],
    architecture_resources: dict[str, list[tuple[str, str, str]]] | None = None,
) -> str:
    """Render the full Formula/skill-scanner.rb file.

    ``resources`` is a list of (display_name, url, sha256).
    """
    resource_blocks = "\n\n".join(render_resource(name, url, sha256) for name, url, sha256 in resources)
    cel_helper_blocks = render_cel_helper_resources(cel_helper_wheels, architecture_resources)

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
        cel_helper_blocks,
        "",
        resource_blocks,
        "",
        "  def install",
        '    ENV["SKILL_SCANNER_CEL_GO_TARGET"] = Hardware::CPU.arm? ? "darwin-arm64" : "darwin-amd64"',
        '    helper_dir = buildpath/"cel-helper"',
        '    resource("cel-helper").stage(helper_dir)',
        '    ENV["SKILL_SCANNER_CEL_GO_PREBUILT_DIR"] = helper_dir/"skill_scanner/core/cel/_bin"',
        '    virtualenv_install_with_resources(without: "cel-helper")',
        "  end",
        "",
        "  test do",
        f'    assert_match "usage:", shell_output("{test_cmd}")',
        '    system "#{bin}/skill-scanner", "validate-rules"',
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
    text = VERSION_PATH.read_text(encoding="utf-8")
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
    validated_wheels = validate_cel_project_wheels(main_data)
    for target, (wheel_url, _) in sorted(validated_wheels.items()):
        print(f"  Verified {target} wheel: {wheel_url.rsplit('/', 1)[-1]}")
    main_url, main_sha256, main_filename = require_project_sdist(main_data, version)
    print(f"  Main source artifact: {main_filename}")

    # 2. Resolve transitive dependencies only from the hash-verified source
    # distribution for the requested version. The checked-out branch and its
    # local pyproject are deliberately not dependency inputs.
    print("  Downloading and verifying the exact release source distribution...")
    try:
        release_pyproject = read_sdist_pyproject(download_verified_sdist(main_url, main_sha256))
    except Exception as exc:
        print(f"  ERROR: Could not validate {main_filename}: {exc}", file=sys.stderr)
        sys.exit(1)
    print("  Resolving transitive dependencies from the release sdist via uv...")
    with tempfile.TemporaryDirectory(prefix="skill-scanner-brew-release-") as temp_dir:
        project_file = Path(temp_dir) / "pyproject.toml"
        project_file.write_bytes(release_pyproject)
        all_deps = resolve_dependencies(project_file)
    print(f"  Resolved {len(all_deps)} total packages")

    # 3. Fetch PyPI metadata for each dependency
    resources: list[tuple[str, str, str]] = []
    errors: list[str] = []
    wheel_only: list[str] = []
    architecture_resources: dict[str, list[tuple[str, str, str]]] = {
        "darwin-amd64": [],
        "darwin-arm64": [],
    }
    for name, dep_version in all_deps:
        if normalise(name) in SKIP_PACKAGES:
            continue
        try:
            data = pypi_json(name, dep_version)
            # Use the PyPI canonical display name for the resource block
            display_name = data["info"]["name"]
            has_sdist = any(u["packagetype"] == "sdist" for u in data.get("urls", []))
            has_pure_wheel = any(
                u.get("packagetype") == "bdist_wheel"
                and isinstance(u.get("filename"), str)
                and u["filename"].endswith("-py3-none-any.whl")
                for u in data.get("urls", [])
            )
            if has_sdist or has_pure_wheel:
                url, sha256 = find_artifact(data)
                resources.append((display_name, url, sha256))
            else:
                selected = select_macos_wheel_resources(data)
                for target, (url, sha256) in selected.items():
                    architecture_resources[target].append((display_name, url, sha256))
            marker = " (architecture-specific wheels)" if not has_sdist and not has_pure_wheel else ""
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
        print("  Platform-specific entries were bound independently to each Homebrew CPU.")

    # 4. Render the formula
    formula = render_formula(
        main_url=main_url,
        main_sha256=main_sha256,
        resources=resources,
        cel_helper_wheels=validated_wheels,
        architecture_resources=architecture_resources,
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
