# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Undeclared network-destination detection ("intent vs implementation").

Rule: UNDECLARED_NETWORK_DESTINATION.

Extracts literal ``https?://`` destinations that scripts contact or configure
and compares exact normalized hosts against the hosts disclosed in SKILL.md,
other Markdown, and the manifest description. A documented parent domain (for
example ``acme-corp.dev``) covers subdomains on a DNS dot boundary, but unrelated
public/private-suffix tenants (``approved.org.uk`` vs ``collector.org.uk`` or
``approved.github.io`` vs ``unrelated.github.io``) do not silence each other.
Deduplication is per distinct normalized host. Markdown code blocks count as
visible disclosure; invisible HTML comments do not. Python docstrings are not
special-cased for this destination-oriented rule, while 6a requires registry
configuration context and therefore does not treat docstrings as configuration.
IP literals, including bracketed IPv6 URLs, are extracted and are undeclared
unless the same literal is disclosed or the literal is loopback/unspecified.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id
from .url_normalization import (
    is_same_or_subdomain,
    is_trusted_host,
    iter_bare_dns_hosts,
    iter_http_url_hosts,
    normalize_host,
    normalize_trusted_domains,
)

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill

RULE_ID = "UNDECLARED_NETWORK_DESTINATION"

_SCRIPT_FILE_TYPES = frozenset({"python", "bash", "javascript", "typescript"})
_LOOPBACK_OR_UNSPECIFIED = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})
_RESERVED_TLDS = frozenset({"example", "invalid", "test", "localhost"})

# Exact host/domain allowlist. Subdomains are allowed only on a dot boundary.
WELL_KNOWN_HOSTS = frozenset(
    {
        # Default package registries / language toolchains
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "pypi.org",
        "pypi.python.org",
        "files.pythonhosted.org",
        "proxy.golang.org",
        "sum.golang.org",
        "pkg.go.dev",
        "crates.io",
        "static.crates.io",
        "index.crates.io",
        "rubygems.org",
        "api.nuget.org",
        "registry-1.docker.io",
        "docker.io",
        "ghcr.io",
        "npm.pkg.github.com",
        # Common code/model hosting and schema/namespace hosts deliberately accepted for 6b.
        "github.com",
        "githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        "huggingface.co",
        "w3.org",
        "www.w3.org",
        "json-schema.org",
        "schema.org",
        "schemas.android.com",
        "schemas.xmlsoap.org",
        "apache.org",
        # Reserved documentation domains.
        "example.com",
        "example.org",
        "example.net",
    }
)
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


@dataclass(frozen=True)
class UndeclaredDestination:
    """A script network destination absent from the skill documentation."""

    host: str
    file_path: str
    line_number: int


def strip_js_ts_comments_preserve_lines(content: str) -> list[str]:
    """Strip JS/TS comments while preserving strings and original line numbers."""
    result_lines: list[str] = []
    current: list[str] = []
    quote: str | None = None
    block_comment = False
    escaped = False
    index = 0
    while index < len(content):
        char = content[index]
        nxt = content[index + 1] if index + 1 < len(content) else ""
        if char == "\n":
            result_lines.append("".join(current))
            current = []
            escaped = False if quote != "`" else escaped
            index += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            current.append(char)
            index += 1
            continue
        if char == "/" and nxt == "/":
            while index < len(content) and content[index] != "\n":
                index += 1
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        current.append(char)
        index += 1
    result_lines.append("".join(current))
    return result_lines


def _strip_markdown_html_comments(document: str) -> str:
    return _HTML_COMMENT_RE.sub(lambda match: "\n" * match.group(0).count("\n"), document)


def _is_declared(host: str, declared_hosts: set[str]) -> bool:
    return any(is_same_or_subdomain(host, declared) for declared in declared_hosts)


def _is_allowlisted(host: str) -> bool:
    if host in _LOOPBACK_OR_UNSPECIFIED:
        return True
    normalized = normalize_host(host)
    if normalized is None:
        return False
    if normalized.is_ip_literal:
        return False
    labels = host.split(".")
    if labels[-1] in _RESERVED_TLDS:
        return True
    return any(is_same_or_subdomain(host, allowed) for allowed in WELL_KNOWN_HOSTS)


def _iter_script_hosts(line: str) -> list[str]:
    return [host for host, _start, _end in iter_http_url_hosts(line)]


def _declared_hosts(skill: Skill) -> set[str]:
    """Collect normalized hosts visibly mentioned in documentation."""
    documents: list[tuple[str, bool]] = []
    if skill.description:
        documents.append((skill.description, False))
    if skill.instruction_body:
        documents.append((skill.instruction_body, True))
    for skill_file in skill.files:
        if skill_file.file_type == "markdown":
            documents.append((skill_file.read_content(), True))

    declared: set[str] = set()
    for document, strip_html_comments in documents:
        visible = _strip_markdown_html_comments(document) if strip_html_comments else document
        for host, _start, _end in iter_http_url_hosts(visible):
            declared.add(host)
        declared.update(iter_bare_dns_hosts(visible))
    return declared


def _is_bash_echo_or_search_only(line: str) -> bool:
    stripped = line.lstrip()
    if not stripped.startswith(("echo ", "printf ", "rg ", "grep ")):
        return False
    return ">" not in stripped and "| tee" not in stripped


def _script_lines(content: str, file_type: str) -> list[str]:
    from skill_scanner.core.static_analysis.comment_stripping import comment_stripped_lines

    if file_type in {"python", "bash"}:
        return comment_stripped_lines(content, file_type)
    if file_type in {"javascript", "typescript"}:
        return strip_js_ts_comments_preserve_lines(content)
    return content.split("\n")


def find_undeclared_destinations(skill: Skill) -> list[UndeclaredDestination]:
    """Return script destinations whose host is never visibly named in the docs."""
    declared = _declared_hosts(skill)
    destinations: list[UndeclaredDestination] = []
    seen: set[str] = set()
    for skill_file in skill.files:
        if skill_file.file_type not in _SCRIPT_FILE_TYPES:
            continue
        content = skill_file.read_content()
        if not content:
            continue
        for index, line in enumerate(_script_lines(content, skill_file.file_type), start=1):
            if skill_file.file_type == "bash" and _is_bash_echo_or_search_only(line):
                continue
            for host in _iter_script_hosts(line):
                if host in seen or _is_allowlisted(host) or _is_declared(host, declared):
                    continue
                seen.add(host)
                destinations.append(UndeclaredDestination(host, skill_file.relative_path, index))
    return destinations


def check_undeclared_network_destination(skill: Skill, trusted_domains: Iterable[str] = ()) -> list[Finding]:
    """Flag script network destinations absent from the skill documentation.

    Destinations under *trusted_domains* (the policy's
    ``llm_analysis.trusted_reference_domains``) are demoted to LOW rather than
    suppressed, matching how the LLM analyzer treats trusted internal domains.
    """
    trusted = normalize_trusted_domains(trusted_domains)
    findings: list[Finding] = []
    for destination in find_undeclared_destinations(skill):
        is_trusted = is_trusted_host(destination.host, trusted)
        description = (
            f"Script contacts or configures '{destination.host}' but the skill documentation "
            f"never visibly mentions it. Undocumented network destinations can indicate "
            f"behaviour the manifest and description do not disclose."
        )
        if is_trusted:
            description += " The host is a trusted reference domain in the scan policy, so severity is LOW."
        findings.append(
            Finding(
                id=generate_finding_id(RULE_ID, f"{destination.file_path}:{destination.host}"),
                rule_id=RULE_ID,
                category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
                severity=Severity.LOW if is_trusted else Severity.MEDIUM,
                title="Script contacts a destination the documentation never mentions",
                description=description,
                file_path=destination.file_path,
                line_number=destination.line_number,
                remediation=(
                    "Document the destination in SKILL.md (or the manifest description) if it is "
                    "intended, or remove the undisclosed network access. Organizations can list "
                    "internal hosts in llm_analysis.trusted_reference_domains."
                ),
                analyzer="static",
            )
        )
    return findings
