# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Shared URL and hostname normalization for core Python detection rules."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

_HTTP_URL_RE = re.compile(r"https?://[^\s\"'<>)},|\\]+", re.IGNORECASE)
_HOST_TOKEN_RE = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,}\b")


@dataclass(frozen=True)
class NormalizedHost:
    """A normalized destination host extracted from a URL-like value."""

    host: str
    is_ip_literal: bool


def normalize_host(host: str | None) -> NormalizedHost | None:
    """Normalize a parsed hostname using IDNA, DNS trailing-dot, and IP-literal rules."""
    if host is None:
        return None
    host = host.strip().strip("[]").rstrip(".").lower()
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
        return NormalizedHost(ip.compressed.lower(), True)
    except ValueError:
        pass
    try:
        ascii_host = host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        return None
    if not ascii_host or any(part == "" for part in ascii_host.split(".")):
        return None
    if not re.fullmatch(r"[a-z0-9.-]+", ascii_host):
        return None
    return NormalizedHost(ascii_host, False)


def normalize_host_from_value(value: str) -> NormalizedHost | None:
    """Extract and normalize a host from a literal URL or host[:port] registry value.

    Query strings, fragments, ports, userinfo (including percent-encoded userinfo),
    percent-escaped paths, DNS trailing dots, IDNs, IPv4, and bracketed IPv6 are
    handled by ``urllib.parse``. Values containing unresolved variables are ignored.
    """
    value = value.strip().strip("\"'`").rstrip(",;")
    if not value or "$" in value or "%" in value and "://" not in value:
        return None
    candidate = value if "://" in value else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        return None
    return normalize_host(parsed.hostname)


def iter_http_url_hosts(text: str) -> list[tuple[str, int, int]]:
    """Return normalized hosts for literal HTTP(S) URLs in *text* with match spans."""
    hosts: list[tuple[str, int, int]] = []
    for match in _HTTP_URL_RE.finditer(text):
        normalized = normalize_host_from_value(match.group(0))
        if normalized is not None:
            hosts.append((normalized.host, match.start(), match.end()))
    return hosts


def iter_bare_dns_hosts(text: str) -> set[str]:
    """Return normalized bare DNS host mentions from prose-like text."""
    hosts: set[str] = set()
    for match in _HOST_TOKEN_RE.finditer(text):
        normalized = normalize_host(match.group(0))
        if normalized is not None and not normalized.is_ip_literal:
            hosts.add(normalized.host)
    return hosts


def split_registry_list(value: str) -> list[str]:
    """Split registry-list environment values such as GOPROXY comma/pipe lists."""
    return [part.strip() for part in re.split(r"[,|]", value) if part.strip()]


def is_same_or_subdomain(host: str, declared_host: str) -> bool:
    """Return true when *host* is exactly *declared_host* or below it on a dot boundary."""
    return host == declared_host or host.endswith(f".{declared_host}")


def normalize_trusted_domains(domains: Iterable[str]) -> frozenset[str]:
    """Normalize policy-declared trusted domains (bare hosts or URLs) for host matching."""
    normalized: set[str] = set()
    for domain in domains:
        host = normalize_host_from_value(domain)
        if host is not None:
            normalized.add(host.host)
    return frozenset(normalized)


def is_trusted_host(host: str, trusted_domains: frozenset[str]) -> bool:
    """Return true when *host* is a policy-trusted domain or one of its subdomains."""
    return any(is_same_or_subdomain(host, trusted) for trusted in trusted_domains)
