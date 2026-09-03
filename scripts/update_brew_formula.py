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
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import tomllib
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
HOMEBREW_PYTHON_PLATFORMS = {
    "darwin-amd64": "x86_64-apple-darwin",
    "darwin-arm64": "aarch64-apple-darwin",
}
HOMEBREW_MACOS_DEPLOYMENT_TARGET = "14.0"
MAX_SDIST_BYTES = 50 * 1024 * 1024
MAX_PYPROJECT_BYTES = 1024 * 1024

# The project is installed from the formula build path and Homebrew invokes pip
# from its Python formula. All other resolved packages—including setuptools on
# Python 3.12—must be explicit, hash-pinned wheel resources.
SKIP_PACKAGES = frozenset(
    {
        "cisco-ai-skill-scanner",
        "pip",
    }
)

# Homebrew system dependencies (Ruby DSL).
SYSTEM_DEPS = [
    "depends_on macos: :sonoma",
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
    qualified_floor = tuple(int(part) for part in HOMEBREW_MACOS_DEPLOYMENT_TARGET.split("."))
    for tag in platform_tag.split("."):
        match = re.fullmatch(r"macosx_(\d+)_(\d+)_(arm64|x86_64|universal2)", tag)
        if match is None or match.group(3) not in {architecture, "universal2"}:
            continue
        deployment_floor = int(match.group(1)), int(match.group(2))
        if deployment_floor > qualified_floor:
            continue
        # Prefer the lowest deployment floor, then a native architecture over
        # universal2. The filename makes the selection deterministic.
        candidates.append((*deployment_floor, match.group(3) == "universal2", filename))
    return min(candidates) if candidates else None


def _pure_wheel_rank(filename: str) -> tuple[int, str] | None:
    try:
        _distribution, python_tag, abi_tag, platform_tag = filename.removesuffix(".whl").rsplit("-", 3)
    except ValueError:
        return None
    if platform_tag != "any" or abi_tag != "none" or not _wheel_is_cpython312_compatible(filename):
        return None
    # Prefer the most portable Python 3 wheel when a release also publishes a
    # CPython-minor-specific pure wheel. The filename is a deterministic tie-breaker.
    return (0 if "py3" in python_tag.split(".") else 1, filename)


def select_macos_wheel_resource(pypi_data: dict, target: str) -> tuple[str, str]:
    """Select one installable CPython 3.12 wheel for a Homebrew target.

    Dependency resources must be wheels: the formula installs them directly
    before building the project with PEP 517 isolation disabled. Accepting an
    sdist here would reintroduce an undeclared build-backend graph or a network
    fetch during the sandboxed Homebrew build.
    """

    architectures = {"darwin-arm64": "arm64", "darwin-amd64": "x86_64"}
    try:
        architecture = architectures[target]
    except KeyError as exc:
        raise ValueError(f"unsupported Homebrew target: {target}") from exc

    pure_matches: list[tuple[tuple[int, str], dict]] = []
    native_matches: list[tuple[tuple[int, int, int, str], dict]] = []
    for entry in pypi_data.get("urls", []):
        filename = entry.get("filename")
        if entry.get("packagetype") != "bdist_wheel" or not isinstance(filename, str):
            continue
        pure_rank = _pure_wheel_rank(filename)
        if pure_rank is not None:
            pure_matches.append((pure_rank, entry))
            continue
        if not _wheel_is_cpython312_compatible(filename):
            continue
        native_rank = _macos_wheel_rank(filename, architecture)
        if native_rank is not None:
            native_matches.append((native_rank, entry))

    if pure_matches:
        entry = min(pure_matches, key=lambda item: item[0])[1]
    elif native_matches:
        entry = min(native_matches, key=lambda item: item[0])[1]
    else:
        name = pypi_data.get("info", {}).get("name", "dependency")
        version = pypi_data.get("info", {}).get("version", "unknown")
        raise RuntimeError(f"{name}=={version} has no CPython 3.12 wheel for {target}")

    filename = entry.get("filename")
    sha256 = entry.get("digests", {}).get("sha256")
    url = entry.get("url")
    parsed_url = urllib.parse.urlparse(url) if isinstance(url, str) else None
    if (
        not isinstance(filename, str)
        or not filename.endswith(".whl")
        or parsed_url is None
        or parsed_url.scheme != "https"
        or Path(parsed_url.path).name != filename
        or not isinstance(sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", sha256)
    ):
        raise RuntimeError(f"{target} dependency wheel is missing a URL or valid SHA-256 digest")
    assert isinstance(url, str)
    return url, sha256


def select_macos_wheel_resources(pypi_data: dict) -> dict[str, tuple[str, str]]:
    """Select CPython 3.12-compatible wheels for both Homebrew CPUs."""

    return {target: select_macos_wheel_resource(pypi_data, target) for target in HOMEBREW_PYTHON_PLATFORMS}


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


def read_build_system_requirements(project_file: Path) -> tuple[str, ...]:
    """Return the exact release's PEP 517 build requirements.

    Homebrew installs from the release sdist with network access disabled for
    Python package resolution. Its resources therefore need the build backend
    and backend plug-ins as well as the project's runtime dependency graph.
    """

    try:
        document = tomllib.loads(project_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError(f"could not parse release pyproject.toml: {exc}") from exc
    build_system = document.get("build-system")
    if not isinstance(build_system, dict):
        raise RuntimeError("release pyproject.toml is missing [build-system]")
    requires = build_system.get("requires")
    if not isinstance(requires, list) or not requires:
        raise RuntimeError("release pyproject.toml has no build-system.requires")
    if not all(isinstance(requirement, str) and requirement.strip() for requirement in requires):
        raise RuntimeError("release pyproject.toml build-system.requires must contain non-empty strings")
    return tuple(requirement.strip() for requirement in requires)


def resolve_dependencies(project_file: Path, *, python_platform: str) -> list[tuple[str, str]]:
    """Resolve runtime and build dependencies for one Darwin target.

    Returns a sorted list of (normalised-name, version) tuples.
    """
    if python_platform not in HOMEBREW_PYTHON_PLATFORMS.values():
        raise ValueError(f"unsupported Homebrew Python platform: {python_platform}")
    project_file = project_file.resolve(strict=True)
    build_requirements = read_build_system_requirements(project_file)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        prefix="skill-scanner-build-system-",
        suffix=".in",
        dir=project_file.parent,
        delete=False,
    ) as stream:
        stream.write("\n".join(build_requirements) + "\n")
        build_requirements_file = Path(stream.name)
    try:
        result = subprocess.run(
            [
                "uv",
                "pip",
                "compile",
                str(project_file),
                str(build_requirements_file),
                "--no-header",
                "--no-annotate",
                "--only-binary",
                ":all:",
                "--python-version",
                "3.12",
                "--python-platform",
                python_platform,
            ],
            capture_output=True,
            text=True,
            cwd=project_file.parent,
            env={**os.environ, "MACOSX_DEPLOYMENT_TARGET": HOMEBREW_MACOS_DEPLOYMENT_TARGET},
        )
    finally:
        build_requirements_file.unlink(missing_ok=True)
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
    return f'  resource "{display_name}" do\n    url "{url}", using: :nounzip\n    sha256 "{sha256}"\n  end'


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
                    (
                        f'      url "{resource_url}"'
                        if name == "cel-helper"
                        else f'      url "{resource_url}", using: :nounzip'
                    ),
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
        '    ENV["PIP_NO_INDEX"] = "1"',
        '    ENV["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"',
        '    ENV["SKILL_SCANNER_CEL_GO_TARGET"] = Hardware::CPU.arm? ? "darwin-arm64" : "darwin-amd64"',
        '    helper_dir = buildpath/"cel-helper"',
        '    resource("cel-helper").stage(helper_dir)',
        '    ENV["SKILL_SCANNER_CEL_GO_PREBUILT_DIR"] = helper_dir/"skill_scanner/core/cel/_bin"',
        '    venv = virtualenv_create(libexec, "python3.12")',
        '    dependency_resources = resources.reject { |resource| resource.name == "cel-helper" }',
        '    wheelhouse = buildpath/"dependency-wheelhouse"',
        "    wheelhouse.mkpath",
        "    dependency_resources.each { |resource| resource.stage(wheelhouse) }",
        "    dependency_wheels = wheelhouse.children.sort",
        '    odie "Dependency wheelhouse is incomplete" unless dependency_wheels.length == dependency_resources.length &&',
        '                                                   dependency_wheels.all? { |wheel| wheel.file? && wheel.extname == ".whl" }',
        '    venv.pip_install dependency_wheels.join("\\n"), build_isolation: false',
        "    venv.pip_install_and_link buildpath, build_isolation: false",
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
    print("  Resolving target-specific transitive dependencies from the release sdist via uv...")
    dependency_graphs: dict[str, list[tuple[str, str]]] = {}
    with tempfile.TemporaryDirectory(prefix="skill-scanner-brew-release-") as temp_dir:
        project_file = Path(temp_dir) / "pyproject.toml"
        project_file.write_bytes(release_pyproject)
        for target, python_platform in HOMEBREW_PYTHON_PLATFORMS.items():
            dependency_graphs[target] = resolve_dependencies(project_file, python_platform=python_platform)
            print(f"    {target}: {len(dependency_graphs[target])} packages")

    # 3. Fetch one compatible, hash-pinned wheel for every dependency in each
    # Darwin graph. Keeping complete graphs in the mutually exclusive CPU
    # blocks handles marker/version divergence without consulting the Linux
    # host that runs formula generation.
    errors: list[str] = []
    metadata_cache: dict[tuple[str, str], dict] = {}
    architecture_resources: dict[str, list[tuple[str, str, str]]] = {target: [] for target in HOMEBREW_PYTHON_PLATFORMS}
    for target, dependencies in dependency_graphs.items():
        for name, dep_version in dependencies:
            if normalise(name) in SKIP_PACKAGES:
                continue
            try:
                cache_key = name, dep_version
                data = metadata_cache.get(cache_key)
                if data is None:
                    data = pypi_json(name, dep_version)
                    metadata_cache[cache_key] = data
                display_name = data["info"]["name"]
                url, sha256 = select_macos_wheel_resource(data, target)
                architecture_resources[target].append((display_name, url, sha256))
                print(f"    {target}: {display_name}=={dep_version}")
            except Exception as exc:
                error = f"{target}: {name}=={dep_version}: {exc}"
                errors.append(error)
                print(f"    ERROR: {error}", file=sys.stderr)

    if errors:
        print(f"\nFailed to fetch {len(errors)} package(s):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        sys.exit(1)

    # 4. Render the formula
    formula = render_formula(
        main_url=main_url,
        main_sha256=main_sha256,
        resources=[],
        cel_helper_wheels=validated_wheels,
        architecture_resources=architecture_resources,
    )

    # 5. Write or print
    if args.dry_run:
        print("\n" + formula)
    else:
        FORMULA_PATH.parent.mkdir(parents=True, exist_ok=True)
        FORMULA_PATH.write_text(formula)
        resource_count = sum(len(resources) for resources in architecture_resources.values())
        print(f"\nWrote {FORMULA_PATH} ({resource_count} target-specific dependency wheel resources)")

    print("Done.")


if __name__ == "__main__":
    main()
