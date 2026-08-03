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

"""Validate the MDX pages published by cisco-ai-defense.github.io."""

from __future__ import annotations

import ast
import re
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = REPO_ROOT / "docs-site"
FRONTMATTER_RE = re.compile(r"\A---\r?\n(?P<body>.*?)\r?\n---\r?\n", re.DOTALL)
FIELD_RE = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9_-]*):\s*(?P<value>.*)$")
INTERNAL_LINK_RE = re.compile(r"\]\(/docs/skill-scanner(?:/(?P<slug>[^)#\s]+))?(?:#[^)]*)?\)")


def parse_scalar(raw: str) -> object:
    value = raw.strip()
    if not value:
        return ""
    if value[0:1] in {'"', "'"}:
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return value
    if re.fullmatch(r"-?\d+", value):
        return int(value)
    return value


def route_for(page: Path) -> str:
    relative = page.relative_to(DOCS_ROOT).with_suffix("")
    parts = list(relative.parts)
    if parts[-1] == "index":
        parts.pop()
    return "/".join(parts)


def validate() -> list[str]:
    errors: list[str] = []
    if not DOCS_ROOT.is_dir():
        return [f"Missing documentation directory: {DOCS_ROOT}"]

    pages = sorted(DOCS_ROOT.rglob("*.mdx"))
    if not pages:
        return [f"No MDX pages found under {DOCS_ROOT}"]

    routes = {route_for(page) for page in pages}
    if "" not in routes:
        errors.append("docs-site/index.mdx is required")

    orders_by_directory: dict[Path, dict[int, Path]] = defaultdict(dict)

    for page in pages:
        relative = page.relative_to(REPO_ROOT)
        content = page.read_text(encoding="utf-8")
        match = FRONTMATTER_RE.match(content)
        if not match:
            errors.append(f"{relative}: missing or malformed frontmatter")
            continue

        fields: dict[str, object] = {}
        for line in match.group("body").splitlines():
            field_match = FIELD_RE.match(line)
            if field_match:
                fields[field_match.group("key")] = parse_scalar(field_match.group("value"))

        if not isinstance(fields.get("title"), str) or not fields["title"].strip():
            errors.append(f'{relative}: "title" must be a non-empty string')
        if not isinstance(fields.get("description"), str) or not fields["description"].strip():
            errors.append(f'{relative}: "description" must be a non-empty string')

        order = fields.get("order")
        if not isinstance(order, int):
            errors.append(f'{relative}: "order" must be an integer')
        elif order in orders_by_directory[page.parent]:
            other = orders_by_directory[page.parent][order].relative_to(REPO_ROOT)
            errors.append(f"{relative}: duplicate order {order} (also used by {other})")
        else:
            orders_by_directory[page.parent][order] = page

        if not content[match.end() :].strip():
            errors.append(f"{relative}: page body is empty")

        if "/docs/defenseclaw" in content:
            errors.append(f"{relative}: stale DefenseClaw path; use https://cisco-ai-defense.github.io/defenseclaw/")

        for link_match in INTERNAL_LINK_RE.finditer(content):
            slug = (link_match.group("slug") or "").rstrip("/")
            if slug not in routes:
                errors.append(f"{relative}: internal link points to missing route {slug!r}")

    return errors


def main() -> int:
    errors = validate()
    if errors:
        print(f"Documentation validation failed with {len(errors)} error(s):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    page_count = len(list(DOCS_ROOT.rglob("*.mdx")))
    print(f"Validated {page_count} Skill Scanner website MDX pages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
