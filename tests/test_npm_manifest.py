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

"""Tests for the npm manifest (``package.json``) dependency parser.

Every function is pure over file content; no network or filesystem access
occurs.
"""

from __future__ import annotations

import json

import pytest

from skill_scanner.core.analyzers.npm_manifest import (
    classify_spec,
    entries_from_package_json,
    exact_version,
    is_npm_manifest,
)


class TestExactVersion:
    """Only a spec naming one exact release is queryable."""

    @pytest.mark.parametrize(
        "spec,expected",
        [
            ("1.2.3", "1.2.3"),
            ("  1.2.3  ", "1.2.3"),
            ("=1.2.3", "1.2.3"),
            ("= 1.2.3", "1.2.3"),
            ("v1.2.3", "1.2.3"),
            ("1.2.3-beta.1", "1.2.3-beta.1"),
            ("1.2.3+build.5", "1.2.3+build.5"),
        ],
    )
    def test_accepts_exact_specs(self, spec, expected):
        assert exact_version(spec) == expected

    @pytest.mark.parametrize(
        "spec",
        [
            "^1.2.3",
            "~1.2.3",
            ">=1.0.0",
            ">1.0.0 <2.0.0",
            "1.2.3 - 2.0.0",
            "1.2.3 || 2.0.0",
            "*",
            "",
            "latest",
            "next",
            "1.x",
            "1.2.x",
            "1.2.*",
            "1.2",
        ],
    )
    def test_rejects_ranges_and_tags(self, spec):
        assert exact_version(spec) is None

    @pytest.mark.parametrize(
        "spec",
        [
            "file:../local",
            "link:../local",
            "workspace:*",
            "git+https://example.test/r.git",
            "git://example.test/r.git",
            "github:owner/repo",
            "owner/repo",
            "owner/repo#semver:^1.0.0",
            "https://example.test/pkg.tgz",
        ],
    )
    def test_rejects_non_registry_references(self, spec):
        assert exact_version(spec) is None


class TestClassifySpec:
    """The static unpinned-dependency check needs a verdict per spec."""

    @pytest.mark.parametrize("spec", ["1.2.3", "=1.2.3", "v1.2.3", "1.2.3-beta.1"])
    def test_exact_specs_are_pinned(self, spec):
        assert classify_spec(spec) == "pinned"

    @pytest.mark.parametrize("spec", ["1.x", "1.X", "1.*", "1.2.x", "1.2.*"])
    def test_partial_version_is_wildcard(self, spec):
        assert classify_spec(spec) == "wildcard"

    @pytest.mark.parametrize(
        "spec",
        ["^1.2.3", "~1.2.3", ">=1.0.0", "1.2.3 - 2.0.0", "*", "", "latest", "1.2"],
    )
    def test_open_ranges_and_tags_are_unpinned(self, spec):
        assert classify_spec(spec) == "unpinned"

    @pytest.mark.parametrize("spec", ["file:../local", "git+https://example.test/r.git", "owner/repo"])
    def test_non_registry_references_are_not_classified(self, spec):
        # Already bound to a specific artifact, like a Python URL/VCS requirement.
        assert classify_spec(spec) is None


def _by_name(entries) -> dict[str, str]:
    return {entry.name: entry.spec for entry in entries}


class TestEntriesFromPackageJson:
    def test_collects_runtime_dependencies(self):
        content = json.dumps({"dependencies": {"lodash": "^4.17.0", "react": "18.2.0"}})
        assert _by_name(entries_from_package_json("package.json", content)) == {
            "lodash": "^4.17.0",
            "react": "18.2.0",
        }

    def test_collects_dev_and_optional_dependencies(self):
        content = json.dumps(
            {
                "dependencies": {"lodash": "4.17.15"},
                "devDependencies": {"jest": "29.7.0"},
                "optionalDependencies": {"fsevents": "2.3.3"},
            }
        )
        entries = {entry.name: entry.dev for entry in entries_from_package_json("package.json", content)}
        assert entries == {"lodash": False, "jest": True, "fsevents": False}

    def test_skips_peer_dependencies(self):
        # The declaring package does not install its peers.
        content = json.dumps({"peerDependencies": {"react": "^18.0.0"}, "dependencies": {"lodash": "4.17.15"}})
        assert _by_name(entries_from_package_json("package.json", content)) == {"lodash": "4.17.15"}

    def test_resolves_aliased_dependency_to_real_package(self):
        content = json.dumps({"dependencies": {"aliased": "npm:real-pkg@1.2.3"}})
        assert _by_name(entries_from_package_json("package.json", content)) == {"real-pkg": "1.2.3"}

    def test_alias_keeps_a_range_spec_unresolved(self):
        content = json.dumps({"dependencies": {"aliased": "npm:real-pkg@^1.0.0"}})
        assert _by_name(entries_from_package_json("package.json", content)) == {"real-pkg": "^1.0.0"}

    def test_optional_dependency_overrides_duplicate_name(self):
        # npm: "Entries in optionalDependencies will override entries of the
        # same name in dependencies".
        content = json.dumps({"dependencies": {"foo": "1.0.0"}, "optionalDependencies": {"foo": "2.0.0"}})
        entries = entries_from_package_json("package.json", content)
        assert [(e.name, e.spec) for e in entries] == [("foo", "2.0.0")]

    def test_collects_scoped_names(self):
        content = json.dumps({"dependencies": {"@babel/traverse": "7.23.1"}})
        assert _by_name(entries_from_package_json("package.json", content)) == {"@babel/traverse": "7.23.1"}

    def test_ignores_non_mapping_sections_and_bundle_dependencies(self):
        content = json.dumps(
            {
                "dependencies": ["lodash"],
                "bundleDependencies": ["lodash"],
                "devDependencies": {"jest": "29.7.0"},
            }
        )
        assert _by_name(entries_from_package_json("package.json", content)) == {"jest": "29.7.0"}

    def test_ignores_non_string_specs(self):
        content = json.dumps({"dependencies": {"weird": 123, "lodash": "4.17.15"}})
        assert _by_name(entries_from_package_json("package.json", content)) == {"lodash": "4.17.15"}

    def test_reports_source_path_and_line_number(self):
        content = '{\n  "dependencies": {\n    "first": "1.0.0",\n    "lodash": "^4.17.0"\n  }\n}\n'
        entries = {
            entry.name: (entry.source, entry.line_number)
            for entry in entries_from_package_json("app/package.json", content)
        }
        assert entries == {"first": ("app/package.json", 3), "lodash": ("app/package.json", 4)}

    def test_malformed_json_yields_no_entries(self):
        assert entries_from_package_json("package.json", "{not json") == []

    def test_manifest_without_dependencies_yields_no_entries(self):
        assert entries_from_package_json("package.json", json.dumps({"name": "x", "version": "1.0.0"})) == []


class TestIsNpmManifest:
    """Only a manifest the package itself declares counts."""

    @pytest.mark.parametrize("path", ["package.json", "web/package.json", "a/b/package.json", "PACKAGE.JSON"])
    def test_accepts_own_manifests(self, path):
        assert is_npm_manifest(path) is True

    @pytest.mark.parametrize(
        "path",
        [
            "node_modules/dep/package.json",
            "web/node_modules/dep/package.json",
            "node_modules/a/node_modules/b/package.json",
        ],
    )
    def test_rejects_installed_dependency_manifests(self, path):
        # Ranges inside an installed package are not the author's to pin.
        assert is_npm_manifest(path) is False

    @pytest.mark.parametrize("path", ["package-lock.json", "other.json", "package.json.bak", "SKILL.md"])
    def test_rejects_other_files(self, path):
        assert is_npm_manifest(path) is False
