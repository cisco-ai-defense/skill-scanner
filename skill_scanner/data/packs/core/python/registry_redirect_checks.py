# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Package-registry redirection detection.

Rule: SUPPLY_CHAIN_REGISTRY_REDIRECT.

Detects package-manager registry/index configuration that targets a non-default
host.  Supported v1 contexts are explicit package-manager commands, well-known
environment-variable forms, standalone package-manager config files, and simple
recognized shell writes/heredocs/``tee`` calls targeting those config files.
Ordinary strings such as ``print(registry)``, ``echo registry=...`` without a
config-file write, or unrelated variables named ``registry`` are intentionally
ignored.

This is a conservative line scanner, not a full shell/TOML parser. Variable
resolution is statement-ordered: only preceding assignments in the same file are
used, unknown reassignments invalidate previous literal bindings, same-line
``;``/``&&`` boundaries are honored, literal defaults like
``${REG:-https://mirror.example}`` are inspected, and unresolved required forms
like ``${REG:?}`` remain silent. Cargo support covers non-default ``registry =``
URLs in ``.cargo/config.toml`` source/registries tables. Go ``GOPROXY`` comma
and pipe lists are split into individual registry alternatives.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id
from .url_normalization import (
    is_trusted_host,
    normalize_host_from_value,
    normalize_trusted_domains,
    split_registry_list,
)

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill, SkillFile

RULE_ID = "SUPPLY_CHAIN_REGISTRY_REDIRECT"

DEFAULT_REGISTRY_HOSTS = frozenset(
    {
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "pypi.org",
        "pypi.python.org",
        "files.pythonhosted.org",
        "proxy.golang.org",
        "sum.golang.org",
        "crates.io",
        "static.crates.io",
        "index.crates.io",
        "rubygems.org",
        "api.nuget.org",
        "registry-1.docker.io",
        "docker.io",
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
    }
)

REGISTRY_CONFIG_BASENAMES = frozenset(
    {".npmrc", "npmrc", ".yarnrc", ".yarnrc.yml", "pip.conf", "pip.ini", ".pypirc", "config.toml"}
)
_CONFIG_TARGET_RE = re.compile(
    r"(?:^|/)(?:\.npmrc|npmrc|\.yarnrc|\.yarnrc\.yml|pip\.conf|pip\.ini|\.pypirc|\.cargo/config\.toml)$",
    re.IGNORECASE,
)
_SCRIPT_FILE_TYPES = frozenset({"python", "bash", "javascript", "typescript"})

_ASSIGNMENT_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_]\w*)=(.*)$")
_ENV_ASSIGN_RE = re.compile(r"(?:^|\s)(?:export\s+)?([A-Za-z_]\w*)=(\S+)")
_VARIABLE_RE = re.compile(r"\$(?:\{([A-Za-z_]\w*)(?:(:-)([^}]+)|:[?][^}]*)?\}|([A-Za-z_]\w*))|%([A-Za-z_]\w*)%")
_HEREDOC_RE = re.compile(r"\bcat\b[^\n]*(?:>|>>)[^\n]*?(\S+)[^\n]*<<-?\s*['\"]?([A-Za-z_][\w-]*)['\"]?")
_TEE_RE = re.compile(r"\btee\b(?:\s+-a)?\s+(\S+)")
_REDIRECT_RE = re.compile(r"(?:>>|>)\s*(\S+)")
_REGISTRY_LINE_RE = re.compile(
    r"(?i)(?:^|[\s'\"`])(?:registry|(?:extra-)?index-url|repository|npmRegistryServer)\s*[:= ]\s*['\"]?([^'\"\s]+)"
)
_CARGO_TABLE_RE = re.compile(r"^\s*\[(source\.[^\]]+|registries\.[^\]]+)\]")
_CARGO_REGISTRY_RE = re.compile(r"^\s*registry\s*=\s*['\"]([^'\"]+)['\"]")

_COMMAND_PATTERNS: tuple[tuple[re.Pattern[str], str, bool], ...] = (
    (re.compile(r"\bnpm\s+config\s+set\s+registry\s+(\S+)"), "npm", False),
    (re.compile(r"\bnpm\s+(?:install|i|add|ci)\b[^\n]*?--registry(?:=|\s+)(\S+)"), "npm", False),
    (re.compile(r"\byarn\s+config\s+set\s+(?:npmRegistryServer|registry)\s+(\S+)"), "yarn", False),
    (re.compile(r"\byarn\s+(?:add|install)\b[^\n]*?--registry(?:=|\s+)(\S+)"), "yarn", False),
    (re.compile(r"\bpnpm\s+config\s+set\s+registry\s+(\S+)"), "pnpm", False),
    (re.compile(r"\bpnpm\s+(?:install|i|add)\b[^\n]*?--registry(?:=|\s+)(\S+)"), "pnpm", False),
    (re.compile(r"\bpip(?:3)?\s+config\s+set\s+(?:global|install)\.(?:extra-)?index-url\s+(\S+)"), "pip", False),
    (
        re.compile(
            r"\b(?:pip|pip3|uv|uvx)\s+(?:install|pip\s+install)\b[^\n]*?(?:--index-url|--extra-index-url|--default-index)(?:=|\s+)(\S+)"
        ),
        "pip",
        False,
    ),
    (re.compile(r"\b(?:pip|pip3|uv|uvx)\s+(?:install|pip\s+install)\b[^\n]*?\s-i\s+(\S+)"), "pip", False),
    (re.compile(r"\bgo\s+env\s+-w\s+GOPROXY=(\S+)"), "go", True),
    (re.compile(r"\bgem\s+sources\s+--add\s+(\S+)"), "gem", False),
    (re.compile(r"\bnuget\s+(?:add\s+source|sources\s+add)\b[^\n]*?(https?://\S+)"), "nuget", False),
    (re.compile(r"--registry-mirror(?:=|\s+)(\S+)"), "docker", False),
)
_ENV_REGISTRY_NAMES = re.compile(
    r"^(?:NPM_CONFIG_REGISTRY|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|UV_INDEX_URL|UV_EXTRA_INDEX_URL|UV_DEFAULT_INDEX|"
    r"GOPROXY|YARN_REGISTRY|CARGO_REGISTRIES_[A-Za-z0-9_]+_INDEX)$",
    re.IGNORECASE,
)
_LIST_ENV_NAMES = {"GOPROXY"}


@dataclass(frozen=True)
class RegistryRedirect:
    """One detected package-registry redirection to a non-default host."""

    host: str
    package_manager: str
    file_path: str
    line_number: int


def _strip_quotes(value: str) -> str:
    value = value.strip().strip(";,")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'`":
        return value[1:-1]
    return value


def _host_values(value: str, variables: dict[str, str | None], *, list_value: bool = False) -> list[str]:
    """Resolve a directive value to zero or more literal non-default hosts."""
    resolved = _resolve_value(_strip_quotes(value), variables)
    if resolved is None:
        return []
    parts = split_registry_list(resolved) if list_value else [resolved]
    hosts: list[str] = []
    for part in parts:
        if part.lower() in {"direct", "off"}:
            continue
        normalized = normalize_host_from_value(part)
        if normalized is None or normalized.host in DEFAULT_REGISTRY_HOSTS:
            continue
        hosts.append(normalized.host)
    return hosts


def _resolve_value(value: str, variables: dict[str, str | None]) -> str | None:
    if "$" not in value and "%" not in value:
        return value

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(4) or match.group(5)
        default = match.group(3)
        if default is not None:
            return default
        bound = variables.get(name)
        if bound is None:
            raise KeyError(name)
        return bound

    try:
        return _VARIABLE_RE.sub(replace, value)
    except KeyError:
        return None


def _config_basename(relative_path: str) -> bool:
    path = relative_path.replace("\\", "/").lower()
    basename = Path(path).name
    return basename in REGISTRY_CONFIG_BASENAMES and (basename != "config.toml" or "/.cargo/" in f"/{path}")


def _is_config_target(token: str) -> bool:
    token = _strip_quotes(token).replace("\\", "/").rstrip(";)")
    return bool(_CONFIG_TARGET_RE.search(token))


def _scan_config_line(line: str, variables: dict[str, str | None]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for match in _REGISTRY_LINE_RE.finditer(line):
        manager = "pip" if "index" in match.group(0).lower() else "npm"
        found.extend((host, manager) for host in _host_values(match.group(1), variables))
    return found


def _split_statements(line: str, file_type: str = "bash") -> list[str]:
    statements: list[str] = []
    start = 0
    index = 0
    quote: str | None = None
    escaped = False
    while index < len(line):
        char = line[index]
        if escaped:
            escaped = False
        elif char == "\\" and (file_type != "bash" or quote != "'"):  # Bash: literal inside single quotes
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in "\"'`":
            quote = char
        elif char == ";" or (line.startswith("&&", index) or line.startswith("||", index)):
            statements.append(line[start:index].strip())
            index += 1 if char == ";" else 2
            start = index
            continue
        index += 1
    tail = line[start:].strip()
    if tail:
        statements.append(tail)
    return statements


def _scan_script_statement(statement: str, variables: dict[str, str | None]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for name, value in _ENV_ASSIGN_RE.findall(statement):
        if _ENV_REGISTRY_NAMES.match(name):
            manager = "go" if name.upper() == "GOPROXY" else "cargo" if name.upper().startswith("CARGO_") else "npm"
            found.extend(
                (host, manager) for host in _host_values(value, variables, list_value=name.upper() in _LIST_ENV_NAMES)
            )
    for pattern, manager, list_value in _COMMAND_PATTERNS:
        for match in pattern.finditer(statement):
            found.extend((host, manager) for host in _host_values(match.group(1), variables, list_value=list_value))
    if _is_config_write(statement):
        found.extend(_scan_config_line(statement, variables))
    return found


def _is_config_write(statement: str) -> bool:
    redirect = _REDIRECT_RE.search(statement)
    if redirect and _is_config_target(redirect.group(1)):
        return True
    tee = _TEE_RE.search(statement)
    return bool(tee and _is_config_target(tee.group(1)))


def _update_assignment(statement: str, variables: dict[str, str | None]) -> None:
    match = _ASSIGNMENT_RE.match(statement)
    if match is None:
        return
    name = match.group(1)
    if _ENV_REGISTRY_NAMES.match(name):
        return
    value = _strip_quotes(match.group(2))
    normalized = normalize_host_from_value(value)
    variables[name] = normalized.host if normalized is not None else None


def _scan_cargo_config(lines: list[str], variables: dict[str, str | None]) -> list[tuple[int, str, str]]:
    in_source_table = False
    redirects: list[tuple[int, str, str]] = []
    for index, line in enumerate(lines, start=1):
        table = _CARGO_TABLE_RE.match(line)
        if table is not None:
            in_source_table = True
            continue
        if line.lstrip().startswith("["):
            in_source_table = False
        if not in_source_table:
            continue
        match = _CARGO_REGISTRY_RE.match(line)
        if match:
            redirects.extend((index, host, "cargo") for host in _host_values(match.group(1), variables))
    return redirects


def _scan_lines(content: str, file_type: str) -> list[str]:
    from skill_scanner.core.static_analysis.comment_stripping import comment_stripped_lines

    from .undeclared_destination_checks import strip_js_ts_comments_preserve_lines

    if file_type in {"python", "bash"}:
        return comment_stripped_lines(content, file_type)
    if file_type in {"javascript", "typescript"}:
        return strip_js_ts_comments_preserve_lines(content)
    return ["" if line.lstrip().startswith(("#", ";")) else line for line in content.split("\n")]


def _registry_scan_targets(skill: Skill) -> list[SkillFile]:
    return [
        skill_file
        for skill_file in skill.files
        if skill_file.file_type in _SCRIPT_FILE_TYPES or _config_basename(skill_file.relative_path)
    ]


def find_registry_redirects(skill: Skill) -> list[RegistryRedirect]:
    """Return non-default package-registry redirects across scripts and config files."""
    redirects: list[RegistryRedirect] = []
    for skill_file in _registry_scan_targets(skill):
        content = skill_file.read_content()
        if not content:
            continue
        lines = _scan_lines(content, skill_file.file_type)
        variables: dict[str, str | None] = {}
        seen: set[tuple[str, str]] = set()
        heredoc_delimiter: str | None = None
        heredoc_target_config = False
        is_config = _config_basename(skill_file.relative_path)
        if is_config and skill_file.relative_path.endswith(".cargo/config.toml"):
            # Table-aware scan of the whole file, run once (not per line) so a large
            # config without a match stays linear.
            cargo_matches = _scan_cargo_config(lines, variables)
            if cargo_matches:
                for cargo_index, host, manager in cargo_matches:
                    key = (skill_file.relative_path, host)
                    if key not in seen:
                        seen.add(key)
                        redirects.append(RegistryRedirect(host, manager, skill_file.relative_path, cargo_index))
                continue
        for index, line in enumerate(lines, start=1):
            if heredoc_delimiter is not None:
                if line.strip() == heredoc_delimiter:
                    heredoc_delimiter = None
                    heredoc_target_config = False
                    continue
                matches = _scan_config_line(line, variables) if heredoc_target_config else []
            elif is_config:
                matches = _scan_config_line(line, variables)
            else:
                heredoc = _HEREDOC_RE.search(line)
                if heredoc is not None:
                    heredoc_target_config = _is_config_target(heredoc.group(1))
                    heredoc_delimiter = heredoc.group(2)
                matches = []
                for statement in _split_statements(line, skill_file.file_type):
                    matches.extend(_scan_script_statement(statement, variables))
                    _update_assignment(statement, variables)
            for host, manager in matches:
                key = (skill_file.relative_path, host)
                if key in seen:
                    continue
                seen.add(key)
                redirects.append(RegistryRedirect(host, manager, skill_file.relative_path, index))
    return redirects


def describe_registry_redirect(redirect: RegistryRedirect) -> str:
    """Return the human-readable description for one registry redirect."""
    return (
        f"Script or configuration redirects the {redirect.package_manager} package registry to the "
        f"non-default host '{redirect.host}'. Repointing the registry silently reroutes future "
        f"dependency installs through a non-default mirror."
    )


def check_registry_redirect(skill: Skill, trusted_domains: Iterable[str] = ()) -> list[Finding]:
    """Flag package-manager registry/index redirection to a non-default host.

    Redirects to a host under *trusted_domains* (the policy's
    ``llm_analysis.trusted_reference_domains``) are demoted to LOW rather than
    suppressed, matching how the LLM analyzer treats trusted internal domains.
    """
    trusted = normalize_trusted_domains(trusted_domains)
    findings: list[Finding] = []
    for redirect in find_registry_redirects(skill):
        is_trusted = is_trusted_host(redirect.host, trusted)
        description = describe_registry_redirect(redirect)
        if is_trusted:
            description += " The host is a trusted reference domain in the scan policy, so severity is LOW."
        findings.append(
            Finding(
                id=generate_finding_id(RULE_ID, f"{redirect.file_path}:{redirect.line_number}:{redirect.host}"),
                rule_id=RULE_ID,
                category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                severity=Severity.LOW if is_trusted else Severity.HIGH,
                title="Package registry redirected to a non-default host",
                description=description,
                file_path=redirect.file_path,
                line_number=redirect.line_number,
                remediation=(
                    "Confirm the registry mirror is trusted and intentionally configured, or remove the "
                    "registry/index override so installs use the default public registry. Organizations "
                    "with an internal mirror can list it in llm_analysis.trusted_reference_domains."
                ),
                analyzer="static",
            )
        )
    return findings
