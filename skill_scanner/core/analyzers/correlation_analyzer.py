# Copyright 2026 Cisco Systems, Inc.
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

"""Deterministic correlation candidates for multi-stage skill behavior.

This analyzer deliberately does not replace the existing syntax, YARA, or
data-flow analyzers.  It extracts a small set of typed signals and correlates
them when the package contains an explicit import/reference relationship.  The
resulting ``semantic_facts`` metadata is safe for the bounded CEL projector: it
contains classifications and normalized paths, never source snippets, secret
values, or arbitrary parsed objects.
"""

from __future__ import annotations

import ast
import configparser
import hashlib
import json
import os
import re
import shlex
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from ..models import Finding, Severity, Skill, SkillFile, ThreatCategory
from ..scan_policy import ScanPolicy
from ..static_analysis.bash_taint_tracker import BashTaintType, analyze_bash_script
from ..static_analysis.javascript_dataflow import analyze_javascript_dataflow
from ..static_analysis.url_classifier import classify_url, extract_urls
from .base import BaseAnalyzer

_SCRIPT_TYPES = frozenset({"python", "bash", "javascript", "typescript"})
_CONFIG_SUFFIXES = frozenset({".json", ".toml", ".yaml", ".yml", ".ini", ".cfg", ".conf"})
_MAX_CONFIG_URL_FACTS = 512

_SECRET_NAME_PARTS = (
    "api_key",
    "apikey",
    "auth",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
)
_SENSITIVE_PATH_PARTS = (
    "/etc/passwd",
    "/etc/shadow",
    ".aws/credentials",
    ".config/gcloud",
    ".docker/config.json",
    ".gnupg",
    ".kube/config",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".ssh/",
    "id_ed25519",
    "id_rsa",
)

_NETWORK_CALLS = frozenset(
    {
        "aiohttp.ClientSession.delete",
        "aiohttp.ClientSession.get",
        "aiohttp.ClientSession.head",
        "aiohttp.ClientSession.options",
        "aiohttp.ClientSession.patch",
        "aiohttp.ClientSession.post",
        "aiohttp.ClientSession.put",
        "http.client.HTTPConnection.request",
        "http.client.HTTPSConnection.request",
        "httpx.delete",
        "httpx.get",
        "httpx.head",
        "httpx.options",
        "httpx.patch",
        "httpx.post",
        "httpx.put",
        "requests.delete",
        "requests.get",
        "requests.head",
        "requests.options",
        "requests.patch",
        "requests.post",
        "requests.put",
        "socket.create_connection",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "urllib3.PoolManager.request",
    }
)
_NETWORK_CLIENT_TYPES = frozenset(
    {
        "aiohttp.ClientSession",
        "httpx.AsyncClient",
        "httpx.Client",
        "requests.Session",
        "socket.socket",
        "urllib3.PoolManager",
    }
)
_OUTBOUND_METHODS = frozenset({"delete", "patch", "post", "put", "send", "sendall", "sendto", "upload"})
_EXECUTION_CALLS = frozenset(
    {
        "eval",
        "exec",
        "os.popen",
        "os.system",
        "runpy.run_module",
        "runpy.run_path",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
    }
)
_OBFUSCATION_CALLS = {
    "base64.b64decode": "base64_decode",
    "base64.urlsafe_b64decode": "base64_decode",
    "binascii.a2b_base64": "base64_decode",
    "codecs.decode": "codec_decode",
    "gzip.decompress": "decompression",
    "lzma.decompress": "decompression",
    "marshal.loads": "marshal_decode",
    "zlib.decompress": "decompression",
}
_ARCHIVE_CALL_PARTS = frozenset({"extract", "extractall", "unpack_archive"})

_SHELL_NETWORK = frozenset({"curl", "nc", "ncat", "netcat", "socat", "wget"})
_SHELL_EXECUTION = frozenset(
    {"bash", "eval", "exec", "node", "perl", "python", "python3", "ruby", "sh", "source", "zsh"}
)
_SHELL_OBFUSCATION = frozenset({"base64", "openssl", "xxd"})
_SHELL_ARCHIVES = frozenset({"7z", "tar", "unzip"})
_SHELL_READERS = frozenset({"cat", "head", "source", "tail"})
_SHELL_SEPARATORS = frozenset({"&", "&&", "(", ")", ";", ";;", "|", "||"})
_SHELL_WRAPPERS = frozenset({"command", "env", "nohup", "sudo", "time"})
_SHELL_WRAPPER_VALUE_OPTIONS: dict[str, frozenset[str]] = {
    "env": frozenset({"-C", "--chdir", "-S", "--split-string", "-u", "--unset"}),
    "sudo": frozenset(
        {
            "-C",
            "--close-from",
            "-D",
            "--chdir",
            "-g",
            "--group",
            "-h",
            "--host",
            "-p",
            "--prompt",
            "-R",
            "--chroot",
            "-T",
            "--command-timeout",
            "-u",
            "--user",
        }
    ),
    "time": frozenset({"-f", "--format", "-o", "--output"}),
}
_SHELL_KEYWORDS = frozenset({"do", "elif", "else", "fi", "if", "then", "until", "while"})
_SHELL_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.DOTALL)
_SHELL_VAR_ASSIGNMENT = re.compile(
    r"^(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$",
    re.DOTALL,
)
_SHELL_VAR_REFERENCE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
_AUTH_HEADER_RE = re.compile(
    r"^\s*(?:authorization|proxy-authorization|x-api-key|api-key|private-token|x-auth-token)\s*:",
    re.IGNORECASE,
)
_AUTH_HEADER_NAMES = frozenset(
    {
        "api-key",
        "authorization",
        "private-token",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
    }
)
_GENERIC_CREDENTIAL_NAME_TOKENS = frozenset(
    {
        "access",
        "api",
        "auth",
        "bearer",
        "client",
        "credential",
        "credentials",
        "key",
        "oauth",
        "password",
        "private",
        "secret",
        "service",
        "token",
        "user",
    }
)
_COMMON_SECOND_LEVEL_SUFFIXES = frozenset({"ac", "co", "com", "edu", "gov", "net", "org"})
_PROVIDER_TOKEN_RE = re.compile(r"[a-z0-9]+")
_CONFIGURED_ENDPOINT_NAME_RE = re.compile(
    r"(?:^|_)(?:API_(?:BASE|ENDPOINT|URL)|BASE_URL|SERVICE_(?:ENDPOINT|URL))$",
    re.IGNORECASE,
)
_DOMAIN_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
_CURL_HEADER_OPTIONS = frozenset({"-H", "--header"})
_CURL_AUTH_OPTIONS = frozenset({"-u", "--user"})
_CURL_PAYLOAD_OPTIONS = frozenset(
    {
        "-d",
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "--form",
        "--form-string",
        "--json",
        "--post-data",
        "--post-file",
        "--upload-file",
        "-F",
        "-T",
    }
)

_EXECUTABLE_MAGIC_PREFIXES = (
    b"\x7fELF",
    b"MZ",
    b"\xca\xfe\xba\xbe",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
)

_NETWORK_TOOL_MARKERS = ("curl", "fetch", "http", "network", "requests", "web", "wget")
_NETWORK_UMBRELLA_TOOL_MARKERS = ("bash", "shell", "terminal")
_EXECUTION_TOOL_MARKERS = ("bash", "execute", "node", "python", "shell", "subprocess", "terminal")
_FILE_TOOL_MARKERS = ("file", "glob", "grep", "read", "write")

# Fenced code in SKILL.md is executable guidance, but it is not represented as
# a standalone ``SkillFile``.  Keep the projection deliberately small and
# language-labelled so the existing AST/shell extractors can inspect it without
# guessing whether arbitrary prose is code.
_FENCED_CODE_MARKDOWN_LIMIT = 1_048_576
_FENCED_CODE_BLOCK_LIMIT = 128
_FENCED_CODE_BLOCK_CHAR_LIMIT = 131_072
_FENCED_CODE_TOTAL_CHAR_LIMIT = 524_288
_FENCE_RE = re.compile(r"^(?P<indent> {0,3})(?P<marker>`{3,}|~{3,})(?P<info>[^\r\n]*)$")
_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
_NEGATIVE_EXAMPLE_HEADING_RE = re.compile(
    r"\b(?:bad|dangerous|insecure|negative|unsafe|vulnerable)\s+(?:code\s+)?examples?\b"
    r"|\b(?:anti[- ]?pattern|incorrect example|what not to do)\b",
    re.IGNORECASE,
)
_EXAMPLE_HEADING_RE = re.compile(r"\b(?:example|examples|demo|demonstration|sample)\b", re.IGNORECASE)
_PROHIBITION_HEADING_RE = re.compile(
    r"\b(?:do not run|forbidden|never run|prohibited|prohibition|must not run)\b",
    re.IGNORECASE,
)
_DOCUMENTED_INSTALLER_HEADING_RE = re.compile(
    r"\b(?:bootstrap|install|installation)\b",
    re.IGNORECASE,
)
_PROHIBITION_LEAD_RE = re.compile(
    r"^\s*(?:[-*+]\s+)?(?:do\s+not|don't|never|must\s+not|should\s+not)\s+"
    r"(?:copy|execute|invoke|run|use)\s+(?:the\s+)?(?:"
    r"(?:following|below)\s+(?:code|commands?|example|snippet)"
    r"|(?:code|commands?|example|snippet)(?:\s+(?:below|shown|that follows))?"
    r")\s*[:.!]?\s*$",
    re.IGNORECASE,
)
_EXAMPLE_LEAD_RE = re.compile(
    r"^\s*(?:[-*+]\s+)?(?:for\s+)?(?:example|demo|demonstration|sample)(?:\s+only)?\s*[:.!]?\s*$",
    re.IGNORECASE,
)
_PYTHON_FENCE_LANGUAGES = frozenset({"py", "python", "python3"})
_SHELL_FENCE_LANGUAGES = frozenset({"bash", "sh", "shell", "zsh"})
_PYTHON_FENCE_FLOW_MARKERS = (
    "aiohttp",
    "base64",
    "binascii",
    "codecs",
    "gzip",
    "http.client",
    "httpx",
    "keyring",
    "lzma",
    "marshal",
    "os.environ",
    "os.getenv",
    "requests",
    "socket",
    "urllib",
    "urllib3",
    "zlib",
)
_SHELL_FENCE_FLOW_MARKERS = tuple(sorted(_SHELL_NETWORK | _SHELL_OBFUSCATION))

# The network-to-file-write extractor below is deliberately narrower than the
# general Python taint tracker.  Its only purpose is to prove one short,
# path-feasible ``requests.get(...).content`` flow into a dynamically selected
# binary file.  On every limit it abandons the candidate rather than widening
# the analysis or joining unrelated paths.
_NETWORK_WRITE_MAX_HOPS = 3
_NETWORK_WRITE_MAX_BRANCH_STATES = 8
_NETWORK_WRITE_MAX_SCOPE_BINDINGS = 256
_NETWORK_WRITE_MAX_TAINTS_PER_NAME = 8
_NETWORK_WRITE_MAX_SCOPES = 128
_NETWORK_WRITE_PREFILTER_MARKERS = ("content", "open", "requests", "write")
_NETWORK_WRITE_BINARY_MODES = frozenset(
    {
        "ab",
        "ab+",
        "a+b",
        "rb+",
        "r+b",
        "wb",
        "wb+",
        "w+b",
        "xb",
        "xb+",
        "x+b",
    }
)


@dataclass(frozen=True)
class _NetworkEvent:
    """A normalized network operation, without request content."""

    line: int
    executable: str
    method: str
    direction: str
    downloads: bool
    urls: tuple[dict[str, Any], ...] = ()
    source_paths: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()
    credential_use: str = ""
    destination_class: str = ""


@dataclass(frozen=True)
class _ExecutionEvent:
    """A normalized process/interpreter operation."""

    line: int
    executable: str
    dynamic: bool
    source_paths: tuple[str, ...] = ()
    source_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class _CallEvent:
    """A call to a package-local symbol with argument provenance."""

    target_path: str
    target_symbol: str
    line: int
    positional_refs: tuple[tuple[str, ...], ...]
    keyword_refs: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True)
class _NetworkWriteTaint:
    """Bounded provenance for one network response value."""

    source_api: str
    selector: str
    hops: int


@dataclass(frozen=True)
class _OpenHandle:
    """A named handle created by a precision-qualified ``open`` call."""

    dynamic_path: bool
    writable: bool
    binary: bool


@dataclass
class _NetworkWriteState:
    """One feasible lexical-path state for the bounded write tracker."""

    aliases: dict[str, str] = field(default_factory=dict)
    taints: dict[str, frozenset[_NetworkWriteTaint]] = field(default_factory=dict)
    handles: dict[str, _OpenHandle] = field(default_factory=dict)
    literal_strings: dict[str, str] = field(default_factory=dict)

    def clone(self) -> _NetworkWriteState:
        return _NetworkWriteState(
            aliases=dict(self.aliases),
            taints=dict(self.taints),
            handles=dict(self.handles),
            literal_strings=dict(self.literal_strings),
        )


@dataclass(frozen=True)
class _Flow:
    """A source-to-sink candidate suitable for ``FlowFact``."""

    source_class: str
    sink_class: str
    transforms: tuple[str, ...]
    source_path: str
    sink_path: str
    line: int
    cross_file: bool = False
    via_paths: tuple[str, ...] = ()

    def fact(self) -> dict[str, Any]:
        return {
            "source_class": self.source_class,
            "sink_class": self.sink_class,
            "transforms": list(self.transforms),
            "cross_file": self.cross_file,
            "source_path": self.source_path,
            "sink_path": self.sink_path,
        }


@dataclass(frozen=True)
class _ShellCommand:
    """One command at a shell command position, not an arbitrary argument."""

    executable: str
    raw_executable: str
    arguments: tuple[str, ...]
    preceding_operator: str | None = None


@dataclass(frozen=True)
class _FencedCodeBlock:
    """One bounded, explicitly language-labelled SKILL.md code fence."""

    file_type: str
    content: str = field(repr=False)
    line_offset: int
    context_kind: str
    role_kind: str = ""


@dataclass
class _FileSignals:
    """Bounded, structured observations for one package file."""

    path: str
    file_type: str
    hidden: bool = False
    executable: bool = False
    archive_depth: int = 0
    referenced_by_skill: bool = False
    line_offset: int = 0
    context_kind: str = "code"
    evidence_kind: str = "correlated_behavior"
    role_kind: str = ""
    references: set[str] = field(default_factory=set)
    source_lines: dict[str, int] = field(default_factory=dict)
    source_symbols: dict[str, set[str]] = field(default_factory=dict)
    symbol_taints: dict[str, set[str]] = field(default_factory=dict)
    networks: list[_NetworkEvent] = field(default_factory=list)
    download_symbols: set[str] = field(default_factory=set)
    executions: list[_ExecutionEvent] = field(default_factory=list)
    obfuscations: dict[str, int] = field(default_factory=dict)
    obfuscation_symbols: set[str] = field(default_factory=set)
    archive_operations: dict[str, int] = field(default_factory=dict)
    function_parameters: dict[str, tuple[str, ...]] = field(default_factory=dict)
    sink_parameters: dict[str, dict[str, dict[str, int]]] = field(default_factory=dict)
    calls: list[_CallEvent] = field(default_factory=list)
    urls: list[dict[str, Any]] = field(default_factory=list)
    config_urls: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    config_parsed: bool = False
    flows: list[_Flow] = field(default_factory=list)

    @property
    def has_dangerous_behavior(self) -> bool:
        return bool(self.source_lines or self.networks or self.executions or self.obfuscations)


def _normalise_path(value: str | os.PathLike[str]) -> str:
    path = PurePosixPath(str(value).replace("\\", "/"))
    parts: list[str] = []
    for part in path.parts:
        if part in {"", ".", "/"}:
            continue
        if part == ".." and parts and parts[-1] != "..":
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def _shell_executable(token: str) -> str:
    """Normalize a token already known to occupy a command position."""
    if token == ".":
        return "source"
    return Path(token.strip("{}")).name.lower()


def _shell_commands(line: str) -> list[_ShellCommand]:
    """Parse top-level command positions from a shell line.

    This is intentionally a small shell lexer, not a shell interpreter.  Its
    security property is that words after a command remain arguments unless a
    real control or pipeline operator starts a new command.  Consequently
    prose-like commands such as ``echo curl`` and ``printf bash`` cannot create
    network or execution signals.
    """
    try:
        lexer = shlex.shlex(line, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        tokens = list(lexer)
    except ValueError:
        return []

    segments: list[tuple[str | None, list[str]]] = []
    preceding: str | None = None
    current: list[str] = []
    for token in tokens:
        if token in _SHELL_SEPARATORS:
            if current:
                segments.append((preceding, current))
                current = []
            preceding = token
        else:
            current.append(token)
    if current:
        segments.append((preceding, current))

    commands: list[_ShellCommand] = []
    for operator, segment in segments:
        index = 0
        while index < len(segment) and (
            _SHELL_ASSIGNMENT.fullmatch(segment[index]) or segment[index].lower() in _SHELL_KEYWORDS
        ):
            index += 1
        if index >= len(segment):
            continue

        # Resolve common command wrappers without treating their option values
        # or environment assignments as executable names.
        while index < len(segment) and _shell_executable(segment[index]) in _SHELL_WRAPPERS:
            wrapper_index = index
            wrapper = _shell_executable(segment[index])
            index += 1
            while index < len(segment):
                token = segment[index]
                if _SHELL_ASSIGNMENT.fullmatch(token):
                    index += 1
                    continue
                if not token.startswith("-"):
                    break
                option = token.partition("=")[0]
                index += 1
                if (
                    "=" not in token
                    and option in _SHELL_WRAPPER_VALUE_OPTIONS.get(wrapper, frozenset())
                    and index < len(segment)
                ):
                    index += 1
            if index >= len(segment) and wrapper == "env":
                # ``env`` without a following command prints the environment;
                # keep it as the command so it remains a sensitive source.
                index = wrapper_index
                break
        if index >= len(segment):
            continue

        raw = segment[index]
        commands.append(
            _ShellCommand(
                executable=_shell_executable(raw),
                raw_executable=raw,
                arguments=tuple(segment[index + 1 :]),
                preceding_operator=operator,
            )
        )
    return commands


def _shell_variable_names(command: _ShellCommand) -> set[str]:
    return {
        match.group(1)
        for token in (command.raw_executable, *command.arguments)
        for match in _SHELL_VAR_REFERENCE.finditer(token)
    }


def _literal_shell_assignment(value: str) -> str | None:
    """Resolve one inert scalar assignment without evaluating shell syntax."""

    if not value or len(value) > 2_048 or any(marker in value for marker in ("$", "`", "\x00")):
        return None
    try:
        parts = shlex.split(value, comments=False, posix=True)
    except ValueError:
        return None
    return parts[0] if len(parts) == 1 else None


def _shell_credential_use(command: _ShellCommand, sensitive_names: set[str]) -> str:
    """Classify credential variables as authentication or transmitted data."""

    if not sensitive_names:
        return ""
    roles: list[str] = []
    arguments = list(command.arguments)
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if argument in _CURL_HEADER_OPTIONS and index + 1 < len(arguments):
            value = arguments[index + 1]
            names = set(_SHELL_VAR_REFERENCE.findall(value)) & sensitive_names
            if names:
                roles.append("authentication" if _AUTH_HEADER_RE.match(value) else "payload")
            index += 2
            continue
        if argument in _CURL_AUTH_OPTIONS and index + 1 < len(arguments):
            value = arguments[index + 1]
            if set(_SHELL_VAR_REFERENCE.findall(value)) & sensitive_names:
                roles.append("authentication")
            index += 2
            continue
        if argument.startswith("--header="):
            value = argument.partition("=")[2]
            if set(_SHELL_VAR_REFERENCE.findall(value)) & sensitive_names:
                roles.append("authentication" if _AUTH_HEADER_RE.match(value) else "payload")
        elif any(argument.startswith(f"{option}=") for option in _CURL_PAYLOAD_OPTIONS):
            if set(_SHELL_VAR_REFERENCE.findall(argument)) & sensitive_names:
                roles.append("payload")
        elif set(_SHELL_VAR_REFERENCE.findall(argument)) & sensitive_names:
            roles.append("payload")
        index += 1
    if roles and all(role == "authentication" for role in roles):
        return "authentication"
    return "payload" if roles else ""


def _shell_network_urls(
    command: _ShellCommand,
    literal_variables: dict[str, str],
) -> tuple[list[str], bool]:
    """Resolve bounded literal/configured endpoints without shell expansion."""

    urls: list[str] = []
    configured_endpoint = False
    for token in command.arguments:
        urls.extend(extract_urls(token))
        for name in _SHELL_VAR_REFERENCE.findall(token):
            value = literal_variables.get(name)
            if value is None:
                continue
            resolved = extract_urls(value)
            if resolved and _CONFIGURED_ENDPOINT_NAME_RE.search(name):
                configured_endpoint = True
            urls.extend(resolved)
    return list(dict.fromkeys(urls)), configured_endpoint


def _declared_service_domains(skill: Skill) -> set[str]:
    """Extract bounded domain tokens from authoritative manifest prose."""

    material = " ".join(
        value
        for value in (skill.manifest.name, skill.manifest.description, skill.manifest.compatibility)
        if isinstance(value, str)
    )[:16_384]
    return {match.group(0).lower().rstrip(".") for match in islice(_DOMAIN_TOKEN_RE.finditer(material), 64)}


def _service_provider_label(host: str) -> str:
    """Return one conservative provider label from a normalized DNS host.

    This is deliberately not a domain allowlist.  It only supports exact
    provider-name correlation (for example ``GITHUB_TOKEN`` to
    ``api.github.com``).  A small structural rule handles common country-code
    second-level suffixes without attempting to implement a public-suffix
    resolver inside the scanner.
    """

    labels = [label for label in host.lower().rstrip(".").split(".") if label]
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9-]{1,63}", label) for label in labels):
        return ""
    if len(labels[-1]) == 2 and len(labels) >= 3 and labels[-2] in _COMMON_SECOND_LEVEL_SUFFIXES:
        return labels[-3]
    return labels[-2]


def _declared_provider_labels(skill: Skill) -> set[str]:
    """Extract bounded provider labels from authoritative skill prose.

    Only normalized DNS labels leave this helper.  Raw instructions and URL
    paths never enter findings or CEL facts.
    """

    manifest_material = " ".join(
        value
        for value in (skill.manifest.name, skill.manifest.description, skill.manifest.compatibility)
        if isinstance(value, str)
    )[:16_384]
    labels: set[str] = set()
    for match in islice(_DOMAIN_TOKEN_RE.finditer(manifest_material), 64):
        label = _service_provider_label(match.group(0))
        if label:
            labels.add(label)
    for raw_url in extract_urls(skill.instruction_body[:65_536])[:128]:
        try:
            host = urlsplit(raw_url).hostname or ""
        except ValueError:
            continue
        label = _service_provider_label(host)
        if label:
            labels.add(label)
    return labels


def _credential_provider_tokens(value: str) -> set[str]:
    """Return bounded provider tokens from a credential identifier.

    Generic credential words are discarded, and short aliases are not used
    for suppression.  The returned values are internal classifications; the
    original environment-variable name is never projected.
    """

    return {
        token
        for token in _PROVIDER_TOKEN_RE.findall(value.lower().replace("-", "_"))[:16]
        if len(token) >= 3 and token not in _GENERIC_CREDENTIAL_NAME_TOKENS
    }


def _authentication_urls_match_providers(
    providers: set[str],
    urls: tuple[dict[str, Any], ...],
) -> bool:
    """Require a resolved HTTPS host bound to the credential provider.

    Package-authored prose, headings, and function names are not an integrity
    boundary.  An authentication flow is considered ordinary only when every
    resolved destination is HTTPS, non-suspicious, and its normalized provider
    label matches one derived from the credential identifier.  Dynamic or
    unresolved destinations fail open.
    """

    if len(providers) != 1 or not urls:
        return False
    return all(
        url.get("scheme") == "https"
        and url.get("domain_class") != "suspicious"
        and _service_provider_label(str(url.get("host", ""))) in providers
        for url in urls
    )


def _network_destination_class(
    urls: tuple[dict[str, Any], ...],
    *,
    configured: bool,
    declared_domains: set[str] | None = None,
) -> str:
    classes = {str(url.get("domain_class", "")) for url in urls}
    if "suspicious" in classes:
        return "suspicious"
    if configured:
        return "configured_service"
    declared = declared_domains or set()
    if any(
        (host := str(url.get("host", ""))) and any(host == domain or host.endswith(f".{domain}") for domain in declared)
        for url in urls
    ):
        return "declared_service"
    if "legitimate" in classes:
        return "legitimate"
    if urls:
        return "external"
    return "dynamic"


def _is_shell_decode(command: _ShellCommand) -> bool:
    arguments = set(command.arguments)
    if command.executable == "base64":
        return bool(arguments & {"-d", "-D", "--decode"})
    if command.executable == "xxd":
        return bool(arguments & {"-r", "--revert"})
    if command.executable == "openssl":
        return bool(arguments & {"-d", "--decrypt"}) and bool(
            arguments & {"base64", "enc"} or any(arg.startswith("-") and "base64" in arg for arg in arguments)
        )
    return False


def _download_output_path(command: _ShellCommand) -> str | None:
    options = {"-o", "--output"} if command.executable == "curl" else {"-O", "--output-document"}
    for index, argument in enumerate(command.arguments[:-1]):
        if argument in options:
            return command.arguments[index + 1]
    for argument in command.arguments:
        for option in options:
            if argument.startswith(f"{option}="):
                return argument.partition("=")[2]
    return None


def _shell_execution_inputs(command: _ShellCommand) -> tuple[str, ...]:
    if command.executable in {"eval", "exec", "source"}:
        return command.arguments
    if command.executable in {"bash", "node", "perl", "python", "python3", "ruby", "sh", "zsh"}:
        arguments = list(command.arguments)
        for index, argument in enumerate(arguments[:-1]):
            if argument in {"-c", "-e", "--eval"}:
                return (arguments[index + 1],)
        for argument in arguments:
            if not argument.startswith("-"):
                return (argument,)
        return ()
    return (command.raw_executable,)


def _dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _dotted_name(node.func)
    return ""


def _target_names(node: ast.AST) -> Iterable[str]:
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, (ast.Tuple, ast.List)):
        for item in node.elts:
            yield from _target_names(item)


def _literal_fragments(node: ast.AST) -> list[str]:
    """Return string constants only; never render an arbitrary AST node."""
    return [item.value for item in ast.walk(node) if isinstance(item, ast.Constant) and isinstance(item.value, str)]


def _is_literal_expr(node: ast.AST) -> bool:
    """Return whether an expression is composed entirely of literals."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return all(_is_literal_expr(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(key is None or _is_literal_expr(key) for key in node.keys) and all(
            _is_literal_expr(value) for value in node.values
        )
    return False


def _is_sensitive_name(value: str) -> bool:
    lowered = value.lower().replace("-", "_")
    return any(part in lowered for part in _SECRET_NAME_PARTS)


def _is_sensitive_path(value: str) -> bool:
    lowered = value.lower().replace("\\", "/")
    return any(part in lowered for part in _SENSITIVE_PATH_PARTS)


def _url_fact(url: str, file_path: str, *, direction: str = "inbound", method: str = "get") -> dict[str, Any]:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        scheme = parsed.scheme.lower()
    except ValueError:
        host = ""
        scheme = ""
    domain_class = classify_url(url)
    if domain_class == "unknown":
        domain_class = "external"
    return {
        "scheme": scheme,
        "host": host,
        "domain_class": domain_class,
        "trusted_installer": False,
        "method": method,
        "direction": direction,
        "file_path": file_path,
    }


def _append_reference_selector(taints: set[str], selector: str) -> set[str]:
    """Append a literal config selector to reference provenance markers."""
    selected: set[str] = set()
    for taint in taints:
        if not taint.startswith("reference:"):
            selected.add(taint)
            continue
        reference = taint.removeprefix("reference:")
        path, separator, symbol = reference.partition("#")
        if PurePosixPath(path).suffix.lower() not in _CONFIG_SUFFIXES:
            selected.add(taint)
            continue
        if separator and not symbol.startswith("key:"):
            selected.add(taint)
            continue
        key = symbol.removeprefix("key:") if separator else ""
        key = ".".join(part for part in (key, selector) if part)
        selected.add(f"reference:{path}#key:{key}")
    return selected


def _parse_config_urls(content: str, file_path: str) -> tuple[bool, dict[str, list[dict[str, Any]]]]:
    """Parse bounded configuration data and classify URL-bearing scalar keys.

    Only key paths and normalized URL facts leave this function.  Parsed
    scalar values are never retained in findings or semantic facts.
    """
    suffix = PurePosixPath(file_path).suffix.lower()
    try:
        if suffix == ".json":
            root: Any = json.loads(content)
        elif suffix == ".toml":
            root = tomllib.loads(content)
        elif suffix in {".yaml", ".yml"}:
            root = yaml.safe_load(content)
        elif suffix in {".ini", ".cfg", ".conf"}:
            parser = configparser.ConfigParser(interpolation=None, strict=False)
            parser.read_string(content)
            root = {section: dict(parser.items(section)) for section in parser.sections()}
        else:
            return False, {}
    except (
        configparser.Error,
        json.JSONDecodeError,
        MemoryError,
        RecursionError,
        tomllib.TOMLDecodeError,
        TypeError,
        ValueError,
        yaml.YAMLError,
    ):
        return False, {}

    result: dict[str, list[dict[str, Any]]] = {}
    stack: list[tuple[str, Any, int]] = [("", root, 0)]
    visited: set[int] = set()
    visited_nodes = 0
    url_count = 0
    while stack and visited_nodes < 1_024 and url_count < _MAX_CONFIG_URL_FACTS:
        key_path, value, depth = stack.pop()
        visited_nodes += 1
        if depth > 12:
            continue
        if isinstance(value, dict):
            identity = id(value)
            if identity in visited:
                continue
            visited.add(identity)
            for key, child in islice(value.items(), 256):
                part = str(key)[:128]
                child_path = ".".join(part for part in (key_path, part) if part)
                stack.append((child_path, child, depth + 1))
        elif isinstance(value, (list, tuple)):
            identity = id(value)
            if identity in visited:
                continue
            visited.add(identity)
            for index, child in enumerate(value[:256]):
                child_path = ".".join(part for part in (key_path, str(index)) if part)
                stack.append((child_path, child, depth + 1))
        elif isinstance(value, str):
            facts = [_url_fact(url, file_path) for url in extract_urls(value[:16_384])]
            if facts:
                remaining = _MAX_CONFIG_URL_FACTS - url_count
                result.setdefault(key_path, []).extend(facts[:remaining])
                url_count += min(len(facts), remaining)
    return True, result


class _BoundedNetworkFileWriteTracker:
    """Prove one short, branch-local network-to-dynamic-file write.

    This is intentionally independent from ``_PythonSignalExtractor``.  The
    general extractor is designed to retain useful provenance through ordinary
    helpers; this tracker instead needs a much stronger invariant before a HIGH
    finding is justified.  It accepts only ``requests.get`` response bytes,
    only the ``content`` selector, and only a named handle returned by an
    explicit binary writable ``open`` call with a non-literal destination.
    """

    def __init__(self, signals: _FileSignals) -> None:
        self.signals = signals
        self.flows: list[_Flow] = []
        self._scope_count = 0

    def extract(self, tree: ast.AST) -> list[_Flow]:
        if not isinstance(tree, ast.Module):
            return []
        self._analyze_scope(tree.body, {})
        return self.flows

    def _analyze_scope(self, statements: list[ast.stmt], aliases: dict[str, str]) -> None:
        if self._scope_count >= _NETWORK_WRITE_MAX_SCOPES:
            return
        self._scope_count += 1
        self._walk_statements(statements, [_NetworkWriteState(aliases=dict(aliases))])

    def _walk_statements(
        self,
        statements: list[ast.stmt],
        states: list[_NetworkWriteState],
    ) -> list[_NetworkWriteState]:
        current = self._bounded_states(states)
        for statement in statements:
            if not current:
                break
            next_states: list[_NetworkWriteState] = []
            for state in current:
                next_states.extend(self._step_statement(statement, state))
            current = self._bounded_states(next_states)
        return current

    def _step_statement(self, statement: ast.stmt, state: _NetworkWriteState) -> list[_NetworkWriteState]:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Function bodies have fresh value/handle state.  Import aliases are
            # lexical metadata and may safely be inherited read-only.
            self._analyze_scope(statement.body, state.aliases)
            return [state]
        if isinstance(statement, ast.ClassDef):
            self._analyze_scope(statement.body, state.aliases)
            return [state]

        self._inspect_direct_expressions(statement, state)

        if isinstance(statement, ast.Import):
            updated = state.clone()
            for alias in statement.names:
                bound_name = alias.asname or alias.name.partition(".")[0]
                updated.aliases[bound_name] = alias.name
            return self._valid_or_empty(updated)

        if isinstance(statement, ast.ImportFrom):
            updated = state.clone()
            if statement.module:
                for alias in statement.names:
                    if alias.name == "*":
                        continue
                    updated.aliases[alias.asname or alias.name] = f"{statement.module}.{alias.name}"
            return self._valid_or_empty(updated)

        if isinstance(statement, ast.Assign):
            updated = state.clone()
            taints = self._advance(self._expression_taints(statement.value, state))
            handle = self._open_handle(statement.value, state)
            literal = self._literal_string(statement.value, state)
            for target in statement.targets:
                self._assign_target(updated, target, taints, handle, literal)
            return self._valid_or_empty(updated)

        if isinstance(statement, ast.AnnAssign):
            updated = state.clone()
            value = statement.value
            taints = self._advance(self._expression_taints(value, state)) if value is not None else frozenset()
            handle = self._open_handle(value, state) if value is not None else None
            literal = self._literal_string(value, state) if value is not None else None
            self._assign_target(updated, statement.target, taints, handle, literal)
            return self._valid_or_empty(updated)

        if isinstance(statement, ast.AugAssign):
            updated = state.clone()
            combined = self._expression_taints(statement.target, state) | self._expression_taints(
                statement.value, state
            )
            self._assign_target(updated, statement.target, self._advance(combined), None, None)
            return self._valid_or_empty(updated)

        if isinstance(statement, ast.Delete):
            updated = state.clone()
            for target in statement.targets:
                for name in _target_names(target):
                    self._clear_name(updated, name)
            return [updated]

        if isinstance(statement, ast.If):
            body_states = self._walk_statements(statement.body, [state.clone()])
            else_states = (
                self._walk_statements(statement.orelse, [state.clone()]) if statement.orelse else [state.clone()]
            )
            return body_states + else_states

        if isinstance(statement, (ast.For, ast.AsyncFor)):
            body_start = state.clone()
            self._assign_target(body_start, statement.target, frozenset(), None, None)
            body_states = self._walk_statements(statement.body, [body_start])
            zero_iteration = [state.clone()]
            continuations = body_states + zero_iteration
            if statement.orelse:
                continuations = self._walk_statements(statement.orelse, continuations)
            return continuations

        if isinstance(statement, ast.While):
            body_states = self._walk_statements(statement.body, [state.clone()])
            continuations = body_states + [state.clone()]
            if statement.orelse:
                continuations = self._walk_statements(statement.orelse, continuations)
            return continuations

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            scoped = state.clone()
            shadowed: dict[str, tuple[frozenset[_NetworkWriteTaint] | None, _OpenHandle | None, str | None]] = {}
            for item in statement.items:
                if not isinstance(item.optional_vars, ast.Name):
                    continue
                name = item.optional_vars.id
                shadowed[name] = (
                    scoped.taints.get(name),
                    scoped.handles.get(name),
                    scoped.literal_strings.get(name),
                )
                self._assign_target(
                    scoped,
                    item.optional_vars,
                    frozenset(),
                    self._open_handle(item.context_expr, state),
                    None,
                )
            body_states = self._walk_statements(statement.body, [scoped])
            for body_state in body_states:
                for name, previous in shadowed.items():
                    self._restore_name(body_state, name, previous)
            return body_states

        if isinstance(statement, ast.Try):
            success = self._walk_statements(statement.body, [state.clone()])
            if statement.orelse:
                success = self._walk_statements(statement.orelse, success)
            alternatives = list(success)
            for handler in statement.handlers:
                alternatives.extend(self._walk_statements(handler.body, [state.clone()]))
            if not alternatives:
                alternatives = [state.clone()]
            if statement.finalbody:
                alternatives = self._walk_statements(statement.finalbody, alternatives)
            return alternatives

        if isinstance(statement, ast.Match):
            match_states: list[_NetworkWriteState] = []
            for case in statement.cases:
                match_states.extend(self._walk_statements(case.body, [state.clone()]))
            return match_states or [state]

        return [state]

    def _inspect_direct_expressions(self, statement: ast.stmt, state: _NetworkWriteState) -> None:
        """Inspect expressions owned by this statement, never nested bodies."""

        for _field, value in ast.iter_fields(statement):
            if isinstance(value, ast.expr):
                self._inspect_expression(value, state)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.expr):
                        self._inspect_expression(item, state)

    def _inspect_expression(self, expression: ast.expr, state: _NetworkWriteState) -> None:
        for node in ast.walk(expression):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if (
                node.func.attr != "write"
                or not isinstance(node.func.value, ast.Name)
                or len(node.args) != 1
                or node.keywords
            ):
                continue
            handle = state.handles.get(node.func.value.id)
            if handle is None or not (handle.dynamic_path and handle.writable and handle.binary):
                continue
            taints = self._expression_taints(node.args[0], state)
            if not any(
                taint.source_api == "requests.get"
                and taint.selector == "content"
                and taint.hops <= _NETWORK_WRITE_MAX_HOPS
                for taint in taints
            ):
                continue
            self.flows.append(
                _Flow(
                    source_class="network",
                    sink_class="filesystem_write",
                    transforms=(),
                    source_path=self.signals.path,
                    sink_path=self.signals.path,
                    line=node.lineno,
                )
            )

    def _expression_taints(
        self,
        node: ast.AST | None,
        state: _NetworkWriteState,
    ) -> frozenset[_NetworkWriteTaint]:
        if node is None:
            return frozenset()
        if isinstance(node, ast.Name):
            return state.taints.get(node.id, frozenset())
        if isinstance(node, ast.Attribute):
            return self._advance(self._expression_taints(node.value, state), selector=node.attr)
        if isinstance(node, ast.Call):
            if self._canonical_name(_dotted_name(node.func), state) == "requests.get":
                return frozenset({_NetworkWriteTaint("requests.get", "", 1)})
            combined: set[_NetworkWriteTaint] = set()
            if isinstance(node.func, ast.Attribute):
                combined.update(self._expression_taints(node.func.value, state))
            combined.update(taint for argument in node.args for taint in self._expression_taints(argument, state))
            combined.update(
                taint for keyword in node.keywords for taint in self._expression_taints(keyword.value, state)
            )
            return self._advance(frozenset(combined))
        if isinstance(node, ast.Constant):
            return frozenset()

        combined = {taint for child in ast.iter_child_nodes(node) for taint in self._expression_taints(child, state)}
        return self._advance(frozenset(combined))

    @staticmethod
    def _canonical_name(value: str, state: _NetworkWriteState) -> str:
        head, separator, remainder = value.partition(".")
        replacement = state.aliases.get(head)
        if replacement is None:
            return value
        return f"{replacement}.{remainder}" if separator else replacement

    def _open_handle(self, node: ast.AST | None, state: _NetworkWriteState) -> _OpenHandle | None:
        if not isinstance(node, ast.Call):
            return None
        callee = self._canonical_name(_dotted_name(node.func), state)
        if callee not in {"open", "builtins.open"}:
            return None
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg is not None}
        destination = node.args[0] if node.args else keywords.get("file")
        mode_node = node.args[1] if len(node.args) > 1 else keywords.get("mode")
        if destination is None or not isinstance(mode_node, ast.Constant) or not isinstance(mode_node.value, str):
            return None
        mode = mode_node.value
        return _OpenHandle(
            dynamic_path=self._literal_string(destination, state) is None,
            writable=mode in _NETWORK_WRITE_BINARY_MODES,
            binary=mode in _NETWORK_WRITE_BINARY_MODES,
        )

    @staticmethod
    def _literal_string(node: ast.AST | None, state: _NetworkWriteState) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.Name):
            return state.literal_strings.get(node.id)
        return None

    def _assign_target(
        self,
        state: _NetworkWriteState,
        target: ast.AST,
        taints: frozenset[_NetworkWriteTaint],
        handle: _OpenHandle | None,
        literal: str | None,
    ) -> None:
        names = list(_target_names(target))
        for name in names:
            if len(taints) > _NETWORK_WRITE_MAX_TAINTS_PER_NAME:
                self._clear_name(state, name)
                continue
            if taints:
                state.taints[name] = taints
            else:
                state.taints.pop(name, None)
            if isinstance(target, ast.Name) and handle is not None:
                state.handles[name] = handle
            else:
                state.handles.pop(name, None)
            if isinstance(target, ast.Name) and literal is not None:
                state.literal_strings[name] = literal
            else:
                state.literal_strings.pop(name, None)

    @staticmethod
    def _clear_name(state: _NetworkWriteState, name: str) -> None:
        state.taints.pop(name, None)
        state.handles.pop(name, None)
        state.literal_strings.pop(name, None)

    @staticmethod
    def _restore_name(
        state: _NetworkWriteState,
        name: str,
        previous: tuple[frozenset[_NetworkWriteTaint] | None, _OpenHandle | None, str | None],
    ) -> None:
        taints, handle, literal = previous
        if taints is None:
            state.taints.pop(name, None)
        else:
            state.taints[name] = taints
        if handle is None:
            state.handles.pop(name, None)
        else:
            state.handles[name] = handle
        if literal is None:
            state.literal_strings.pop(name, None)
        else:
            state.literal_strings[name] = literal

    @staticmethod
    def _advance(
        taints: frozenset[_NetworkWriteTaint],
        *,
        selector: str | None = None,
    ) -> frozenset[_NetworkWriteTaint]:
        return frozenset(
            _NetworkWriteTaint(
                taint.source_api,
                selector if selector is not None else taint.selector,
                taint.hops + 1,
            )
            for taint in taints
            if taint.hops < _NETWORK_WRITE_MAX_HOPS
        )

    @staticmethod
    def _state_key(state: _NetworkWriteState) -> tuple[Any, ...]:
        return (
            tuple(sorted(state.aliases.items())),
            tuple(
                (name, tuple(sorted((taint.source_api, taint.selector, taint.hops) for taint in taints)))
                for name, taints in sorted(state.taints.items())
            ),
            tuple(
                (name, handle.dynamic_path, handle.writable, handle.binary)
                for name, handle in sorted(state.handles.items())
            ),
            tuple(sorted(state.literal_strings.items())),
        )

    @staticmethod
    def _binding_count(state: _NetworkWriteState) -> int:
        return len(state.aliases) + len(state.taints) + len(state.handles) + len(state.literal_strings)

    def _valid_or_empty(self, state: _NetworkWriteState) -> list[_NetworkWriteState]:
        return [state] if self._binding_count(state) <= _NETWORK_WRITE_MAX_SCOPE_BINDINGS else []

    def _bounded_states(self, states: list[_NetworkWriteState]) -> list[_NetworkWriteState]:
        unique: list[_NetworkWriteState] = []
        seen: set[tuple[Any, ...]] = set()
        for state in states:
            if self._binding_count(state) > _NETWORK_WRITE_MAX_SCOPE_BINDINGS:
                continue
            key = self._state_key(state)
            if key in seen:
                continue
            seen.add(key)
            unique.append(state)
            if len(unique) > _NETWORK_WRITE_MAX_BRANCH_STATES:
                return []
        return unique


class _PythonSignalExtractor(ast.NodeVisitor):
    """Small, flow-sensitive AST extractor for explicit assignments/calls."""

    def __init__(
        self,
        signals: _FileSignals,
        known_paths: set[str],
        declared_provider_labels: set[str] | None = None,
    ) -> None:
        self.signals = signals
        self.known_paths = known_paths
        self.declared_provider_labels = frozenset(declared_provider_labels or ())
        self._environments: list[dict[str, set[str]]] = [{}]
        self._object_types: list[dict[str, str]] = [{}]
        self._file_handles: list[dict[str, str]] = [{}]
        self._string_values: list[dict[str, str]] = [{}]
        self._artifact_taints: dict[str, set[str]] = {}
        self._module_references: dict[str, tuple[str, str | None]] = {}
        self._name_aliases: dict[str, str] = {}
        self._function_taints: dict[str, set[str]] = {}
        self._local_classes: set[str] = set()
        self._classes: list[str] = []
        self._scopes: list[str] = [""]

    @property
    def env(self) -> dict[str, set[str]]:
        return self._environments[-1]

    @property
    def object_types(self) -> dict[str, str]:
        return self._object_types[-1]

    def _lookup_taints(self, name: str) -> set[str]:
        for environment in reversed(self._environments):
            if name in environment:
                return set(environment[name])
        return set()

    def _lookup_object_type(self, name: str) -> str | None:
        for object_types in reversed(self._object_types):
            if name in object_types:
                return object_types[name]
        return None

    def _lookup_file_handle(self, name: str) -> str | None:
        for file_handles in reversed(self._file_handles):
            if name in file_handles:
                return file_handles[name]
        return None

    def _lookup_string(self, name: str) -> str | None:
        canonical = self._canonical_name(name)
        for string_values in reversed(self._string_values):
            if canonical in string_values:
                return string_values[canonical]
            if name in string_values:
                return string_values[name]
        return None

    def extract(self, tree: ast.AST) -> None:
        self._collect_references(tree)
        self.visit(tree)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._local_classes.add(".".join((*self._classes, node.name)))
        self._classes.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self._classes.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        scope = ".".join((*self._classes, node.name))
        parameter_names = self._function_parameter_names(node.args)
        self.signals.function_parameters[scope] = parameter_names
        self._environments.append({name: {f"parameter:{scope}#{name}"} for name in parameter_names})
        self._object_types.append({})
        self._file_handles.append({})
        self._string_values.append({})
        self._scopes.append(scope)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self._expr_taints(default)
        for statement in node.body:
            self.visit(statement)
        self._scopes.pop()
        self._file_handles.pop()
        self._string_values.pop()
        self._object_types.pop()
        self._environments.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        scope = ".".join((*self._classes, node.name))
        parameter_names = self._function_parameter_names(node.args)
        self.signals.function_parameters[scope] = parameter_names
        self._environments.append({name: {f"parameter:{scope}#{name}"} for name in parameter_names})
        self._object_types.append({})
        self._file_handles.append({})
        self._string_values.append({})
        self._scopes.append(scope)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self._expr_taints(default)
        for statement in node.body:
            self.visit(statement)
        self._scopes.pop()
        self._file_handles.pop()
        self._string_values.pop()
        self._object_types.pop()
        self._environments.pop()

    @staticmethod
    def _function_parameter_names(arguments: ast.arguments) -> tuple[str, ...]:
        names = [
            argument.arg
            for argument in (*arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs)
            if argument.arg not in {"cls", "self"}
        ]
        if arguments.vararg is not None:
            names.append(arguments.vararg.arg)
        if arguments.kwarg is not None:
            names.append(arguments.kwarg.arg)
        return tuple(names)

    def visit_Assign(self, node: ast.Assign) -> None:
        taints = self._expr_taints(node.value)
        object_type = self._constructed_object_type(node.value)
        file_path = self._opened_file_path(node.value)
        string_value = self._resolved_string(node.value)
        for target in node.targets:
            self._assign_target_taints(target, taints)
            for name in _target_names(target):
                if object_type is not None:
                    self.object_types[name] = object_type
                if file_path is not None:
                    self._file_handles[-1][name] = file_path
                if string_value is not None:
                    self._string_values[-1][self._qualified_assignment_name(name)] = string_value
                if self._scopes[-1] == "":
                    self._record_symbol_taints(name, taints)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        taints = self._expr_taints(node.value) if node.value is not None else set()
        object_type = self._constructed_object_type(node.value)
        file_path = self._opened_file_path(node.value)
        string_value = self._resolved_string(node.value)
        self._assign_target_taints(node.target, taints)
        for name in _target_names(node.target):
            if object_type is not None:
                self.object_types[name] = object_type
            if file_path is not None:
                self._file_handles[-1][name] = file_path
            if string_value is not None:
                self._string_values[-1][self._qualified_assignment_name(name)] = string_value
            if self._scopes[-1] == "":
                self._record_symbol_taints(name, taints)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        taints = self._expr_taints(node.value) | self._expr_taints(node.target)
        self._assign_target_taints(node.target, taints)

    def _assign_target_taints(self, target: ast.AST, taints: set[str]) -> None:
        assigned_taints = set(taints)
        if self._is_auth_header_target(target):
            assigned_taints = self._as_authentication_taints(assigned_taints)
        names = list(_target_names(target))
        if isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            names.append(target.value.id)
        for name in names:
            if isinstance(target, ast.Subscript):
                self.env.setdefault(name, set()).update(assigned_taints)
            else:
                self.env[name] = set(assigned_taints)

    @staticmethod
    def _is_auth_header_target(target: ast.AST) -> bool:
        if not isinstance(target, ast.Subscript):
            return False
        key = target.slice
        return (
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value.strip().lower() in _AUTH_HEADER_NAMES
        )

    def _qualified_assignment_name(self, name: str) -> str:
        if self._classes and not self._scopes[-1]:
            return ".".join((*self._classes, name))
        return name

    def visit_Expr(self, node: ast.Expr) -> None:
        self._expr_taints(node.value)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            taints = self._expr_taints(node.value)
            scope = self._scopes[-1]
            if scope:
                self._function_taints.setdefault(scope, set()).update(taints)
                self._record_symbol_taints(scope, taints)

    def visit_If(self, node: ast.If) -> None:
        self._expr_taints(node.test)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_While(self, node: ast.While) -> None:
        self._expr_taints(node.test)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        taints = self._expr_taints(node.iter)
        for name in _target_names(node.target):
            self.env[name] = set(taints)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        taints = self._expr_taints(node.iter)
        for name in _target_names(node.target):
            self.env[name] = set(taints)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            taints = self._expr_taints(item.context_expr)
            object_type = self._constructed_object_type(item.context_expr)
            file_path = self._opened_file_path(item.context_expr)
            if item.optional_vars is not None:
                for name in _target_names(item.optional_vars):
                    self.env[name] = set(taints)
                    if object_type is not None:
                        self.object_types[name] = object_type
                    if file_path is not None:
                        self._file_handles[-1][name] = file_path
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        for item in node.items:
            taints = self._expr_taints(item.context_expr)
            object_type = self._constructed_object_type(item.context_expr)
            file_path = self._opened_file_path(item.context_expr)
            if item.optional_vars is not None:
                for name in _target_names(item.optional_vars):
                    self.env[name] = set(taints)
                    if object_type is not None:
                        self.object_types[name] = object_type
                    if file_path is not None:
                        self._file_handles[-1][name] = file_path
        for statement in node.body:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        self._expr_taints(node)

    def _expr_taints(self, node: ast.AST | None) -> set[str]:
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            return self._lookup_taints(node.id) | self._value_reference_taints(node.id)
        if isinstance(node, ast.Subscript):
            taints = self._expr_taints(node.value) | self._expr_taints(node.slice)
            dotted_value = self._canonical_name(_dotted_name(node.value))
            if dotted_value == "os.environ":
                names = _literal_fragments(node.slice)
                if not names or any(_is_sensitive_name(name) for name in names):
                    self._record_source("sensitive_environment", node.lineno)
                    taints.add("sensitive_environment")
            elif isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, (str, int)):
                taints = _append_reference_selector(taints, str(node.slice.value))
            return taints
        if isinstance(node, ast.Attribute):
            dotted = _dotted_name(node)
            direct = self._value_reference_taints(dotted)
            if direct:
                return direct
            return _append_reference_selector(self._expr_taints(node.value), node.attr)
        if isinstance(node, ast.Call):
            return self._call_taints(node)
        if isinstance(node, ast.Dict):
            dictionary_taints: set[str] = set()
            for key, value in zip(node.keys, node.values, strict=True):
                value_taints = self._expr_taints(value)
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and key.value.strip().lower() in _AUTH_HEADER_NAMES
                ):
                    value_taints = self._as_authentication_taints(value_taints)
                elif key is not None:
                    value_taints.update(self._expr_taints(key))
                dictionary_taints.update(value_taints)
            return dictionary_taints
        if isinstance(node, ast.NamedExpr):
            taints = self._expr_taints(node.value)
            for name in _target_names(node.target):
                self.env[name] = set(taints)
                if self._scopes[-1] == "":
                    self._record_symbol_taints(name, taints)
            return taints

        node_taints: set[str] = set()
        for child in ast.iter_child_nodes(node):
            node_taints.update(self._expr_taints(child))
        return node_taints

    def _call_taints(self, node: ast.Call) -> set[str]:
        raw_callee = _dotted_name(node.func)
        callee = self._canonical_name(raw_callee)
        call_references = self._call_reference_taints(raw_callee, node)
        if callee in _EXECUTION_CALLS and callee not in {"eval", "exec"}:
            call_references.update(self._literal_path_reference_taints(node))
        receiver_taints = self._expr_taints(node.func.value) if isinstance(node.func, ast.Attribute) else set()
        if isinstance(node.func, ast.Attribute):
            call_references.update(self._method_reference_taints(receiver_taints, node.func.attr))
        if raw_callee.endswith(".get") and node.args and isinstance(node.args[0], ast.Constant):
            selector = node.args[0].value
            if isinstance(selector, (str, int)):
                receiver_taints = _append_reference_selector(receiver_taints, str(selector))
        positional_taints = [self._expr_taints(argument) for argument in node.args]
        keyword_taints: dict[str, set[str]] = {}
        for keyword in node.keywords:
            if keyword.arg is None:
                continue
            taints = self._expr_taints(keyword.value)
            if keyword.arg.lower() in {"auth", "authentication"}:
                taints = self._as_authentication_taints(taints)
            keyword_taints[keyword.arg] = taints
        argument_taints: set[str] = set(receiver_taints) | call_references
        for taints in positional_taints:
            argument_taints.update(taints)
        for taints in keyword_taints.values():
            argument_taints.update(taints)
        self._record_call_events(node, call_references, positional_taints, keyword_taints)
        self._record_local_sink_flows(callee, positional_taints, keyword_taints)

        write_path = self._write_target_path(node)
        if write_path is not None and argument_taints:
            self._artifact_taints.setdefault(write_path, set()).update(argument_taints)

        if self._is_sensitive_call(callee, node):
            source_class = "sensitive_environment" if "environ" in callee or "getenv" in callee else "credential_file"
            self._record_source(source_class, node.lineno)
            argument_taints.add(source_class)
            if source_class == "sensitive_environment":
                for name in _literal_fragments(node)[:16]:
                    argument_taints.update(
                        f"credential_provider:{provider}" for provider in _credential_provider_tokens(name)
                    )

        if callee in _OBFUSCATION_CALLS:
            transform = _OBFUSCATION_CALLS[callee]
            self.signals.obfuscations.setdefault(transform, node.lineno)
            argument_taints.add("obfuscation")

        if self._is_network_call(callee):
            method = self._network_method(callee, node)
            direct_sensitive = self._sensitive_taints(argument_taints)
            authenticated_sensitive = self._authenticated_source_classes(argument_taints)
            sensitive = direct_sensitive | authenticated_sensitive
            credential_use = ""
            if authenticated_sensitive and not direct_sensitive:
                credential_use = "authentication"
            elif sensitive:
                credential_use = "payload"
            provisional_urls = tuple(
                _url_fact(url, self.signals.path, method=method)
                for fragment in self._resolved_literal_fragments(node)
                for url in extract_urls(fragment)
            )
            destination_class = _network_destination_class(provisional_urls, configured=False)
            providers = self._credential_providers(argument_taints)
            normal_authentication = credential_use == "authentication" and self._authentication_destination_matches(
                providers,
                provisional_urls,
            )
            if normal_authentication:
                destination_class = "provider_bound_service"
            reportable_sensitive = set() if normal_authentication else sensitive
            direction = "outbound" if method in _OUTBOUND_METHODS or reportable_sensitive else "inbound"
            urls = tuple({**url, "direction": direction} for url in provisional_urls)
            event = _NetworkEvent(
                line=node.lineno,
                executable=callee.split(".")[0],
                method=method,
                direction=direction,
                downloads=method in {"get", "recv", "recvfrom", "urlopen", "urlretrieve"},
                urls=urls,
                source_paths=self._reference_paths(argument_taints),
                source_refs=self._reference_inputs(argument_taints),
                credential_use=credential_use,
                destination_class=destination_class,
            )
            self.signals.networks.append(event)
            self._record_sink_parameters("network", argument_taints, node.lineno)
            self.signals.urls.extend(urls)
            if direction == "outbound" and reportable_sensitive:
                self.signals.flows.append(
                    _Flow(
                        source_class=sorted(reportable_sensitive)[0],
                        sink_class="network",
                        transforms=(),
                        source_path=self.signals.path,
                        sink_path=self.signals.path,
                        line=node.lineno,
                    )
                )
            return {"network"} | call_references

        if callee in _EXECUTION_CALLS:
            for value in _literal_fragments(node):
                argument_taints.update(self._artifact_taints.get(_normalise_path(value), set()))
            dynamic = bool(argument_taints) or any(not _is_literal_expr(arg) for arg in node.args)
            executable = callee.rsplit(".", 1)[-1]
            self.signals.executions.append(
                _ExecutionEvent(
                    node.lineno,
                    executable,
                    dynamic,
                    self._reference_paths(argument_taints),
                    self._reference_inputs(argument_taints),
                )
            )
            self._record_sink_parameters("code_execution", argument_taints, node.lineno)
            if "network" in argument_taints:
                self.signals.flows.append(
                    _Flow(
                        source_class="network",
                        sink_class="code_execution",
                        transforms=(),
                        source_path=self.signals.path,
                        sink_path=self.signals.path,
                        line=node.lineno,
                    )
                )
            if "obfuscation" in argument_taints:
                self.signals.flows.append(
                    _Flow(
                        source_class="obfuscation",
                        sink_class="code_execution",
                        # CEL receives a stable classification, never the
                        # extractor-specific API name (for example
                        # ``base64_decode`` or ``marshal_loads``).
                        transforms=("decode",),
                        source_path=self.signals.path,
                        sink_path=self.signals.path,
                        line=node.lineno,
                    )
                )
            return {"execution"} | call_references

        if callee.rsplit(".", 1)[-1] in _ARCHIVE_CALL_PARTS:
            self.signals.archive_operations.setdefault("archive_extract", node.lineno)

        local_taints = self._function_taints.get(callee) or self._function_taints.get(raw_callee)
        if local_taints is not None:
            return set(local_taints) | argument_taints

        # Propagate taint through ordinary helpers and accessors. Cross-file
        # findings additionally require symbol-level reference provenance at
        # the classified sink.
        return argument_taints

    def _collect_references(self, tree: ast.AST) -> None:
        current = PurePosixPath(self.signals.path)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self._name_aliases[alias.asname] = alias.name
                    path = self._add_module_reference(alias.name, current.parent)
                    if path is not None:
                        self._module_references[alias.asname or alias.name] = (path, None)
            elif isinstance(node, ast.ImportFrom):
                base = current.parent
                for _ in range(max(0, node.level - 1)):
                    base = base.parent
                if node.module:
                    for alias in node.names:
                        if alias.name != "*":
                            self._name_aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
                    path = self._add_module_reference(node.module, base)
                    if path is not None:
                        for alias in node.names:
                            self._module_references[alias.asname or alias.name] = (path, alias.name)
                else:
                    for alias in node.names:
                        path = self._add_module_reference(alias.name, base)
                        if path is not None:
                            self._module_references[alias.asname or alias.name] = (path, None)

    def _canonical_name(self, value: str) -> str:
        if not value:
            return value
        head, separator, remainder = value.partition(".")
        if head in {"cls", "self"} and self._classes:
            class_name = ".".join(self._classes)
            return f"{class_name}.{remainder}" if separator else class_name
        replacement = self._lookup_object_type(head) or self._name_aliases.get(head)
        if replacement is None:
            return value
        return f"{replacement}.{remainder}" if separator else replacement

    def _constructed_object_type(self, node: ast.AST | None) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        callee = self._canonical_name(_dotted_name(node.func))
        if callee in {"socket.create_connection", "socket.socket"}:
            return "socket.socket"
        if callee in {"httpx.AsyncClient", "httpx.Client"} and self._is_in_process_httpx_client(node):
            return None
        return callee if callee in _NETWORK_CLIENT_TYPES or callee in self._local_classes else None

    def _is_in_process_httpx_client(self, node: ast.Call) -> bool:
        """Recognize ASGI/WSGI/mock clients that never leave the process."""
        for keyword in node.keywords:
            if keyword.arg == "app":
                return True
            if keyword.arg != "transport" or not isinstance(keyword.value, ast.Call):
                continue
            transport = self._canonical_name(_dotted_name(keyword.value.func))
            if transport in {"httpx.ASGITransport", "httpx.MockTransport", "httpx.WSGITransport"}:
                return True
        return False

    def _resolved_string(self, node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, (ast.Name, ast.Attribute)):
            return self._lookup_string(_dotted_name(node))
        return None

    def _resolved_literal_fragments(self, node: ast.AST) -> list[str]:
        values: list[str] = []
        seen: set[str] = set()
        for item in ast.walk(node):
            value = self._resolved_string(item)
            if value is not None and value not in seen:
                seen.add(value)
                values.append(value)
        return values

    def _opened_file_path(self, node: ast.AST | None) -> str | None:
        if not isinstance(node, ast.Call):
            return None
        callee = self._canonical_name(_dotted_name(node.func))
        if callee not in {"open", "pathlib.Path.open"} or not node.args:
            return None
        first = node.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            return None
        return _normalise_path(first.value)

    def _write_target_path(self, node: ast.Call) -> str | None:
        if not isinstance(node.func, ast.Attribute):
            return None
        if node.func.attr not in {"write", "write_bytes", "write_text"}:
            return None
        receiver = node.func.value
        if isinstance(receiver, ast.Name):
            return self._lookup_file_handle(receiver.id)
        if not isinstance(receiver, ast.Call) or not receiver.args:
            return None
        receiver_callee = self._canonical_name(_dotted_name(receiver.func))
        if receiver_callee not in {"open", "pathlib.Path"}:
            return None
        first = receiver.args[0]
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            return None
        return _normalise_path(first.value)

    def _value_reference_taints(self, value: str) -> set[str]:
        taints: set[str] = set()
        for name, (path, imported_symbol) in self._module_references.items():
            if value != name and not value.startswith(f"{name}."):
                continue
            remainder = value.removeprefix(name).removeprefix(".")
            symbol_parts = [part for part in (imported_symbol, remainder) if part]
            symbol = ".".join(symbol_parts)
            taints.add(f"reference:{path}#{symbol}" if symbol else f"reference:{path}")
        return taints

    @staticmethod
    def _method_reference_taints(taints: set[str], method: str) -> set[str]:
        references: set[str] = set()
        for taint in taints:
            if not taint.startswith("reference:"):
                continue
            reference = taint.removeprefix("reference:")
            path, _, symbol = reference.partition("#")
            if PurePosixPath(path).suffix.lower() != ".py" or symbol.startswith("key:"):
                continue
            target_symbol = ".".join(part for part in (symbol, method) if part)
            references.add(f"reference:{path}#{target_symbol}")
        return references

    def _record_call_events(
        self,
        node: ast.Call,
        references: set[str],
        positional_taints: list[set[str]],
        keyword_taints: dict[str, set[str]],
    ) -> None:
        positional_refs = tuple(self._reference_inputs(taints) for taints in positional_taints)
        keyword_refs = tuple((name, self._reference_inputs(taints)) for name, taints in sorted(keyword_taints.items()))
        for reference in sorted(references):
            if not reference.startswith("reference:"):
                continue
            path, separator, symbol = reference.removeprefix("reference:").partition("#")
            if not separator or not symbol:
                continue
            self.signals.calls.append(_CallEvent(path, symbol, node.lineno, positional_refs, keyword_refs))

    def _record_sink_parameters(self, sink_class: str, taints: set[str], line: int) -> None:
        scope = self._scopes[-1]
        if not scope:
            return
        prefix = f"parameter:{scope}#"
        for taint in taints:
            if not taint.startswith(prefix):
                continue
            parameter = taint.removeprefix(prefix)
            self.signals.sink_parameters.setdefault(scope, {}).setdefault(sink_class, {}).setdefault(parameter, line)

    def _record_local_sink_flows(
        self,
        callee: str,
        positional_taints: list[set[str]],
        keyword_taints: dict[str, set[str]],
    ) -> None:
        """Bind same-file call arguments to parameters consumed by known sinks."""
        parameters = self.signals.function_parameters.get(callee)
        sink_parameters = self.signals.sink_parameters.get(callee)
        if parameters is None or sink_parameters is None:
            return

        def argument_taints(parameter: str) -> set[str]:
            if parameter in keyword_taints:
                return keyword_taints[parameter]
            try:
                index = parameters.index(parameter)
            except ValueError:
                return set()
            return positional_taints[index] if index < len(positional_taints) else set()

        for parameter, sink_line in sink_parameters.get("network", {}).items():
            sensitive = self._sensitive_taints(argument_taints(parameter))
            if sensitive:
                self.signals.flows.append(
                    _Flow(
                        source_class=sorted(sensitive)[0],
                        sink_class="network",
                        transforms=(),
                        source_path=self.signals.path,
                        sink_path=self.signals.path,
                        line=sink_line,
                    )
                )

        for parameter, sink_line in sink_parameters.get("code_execution", {}).items():
            taints = argument_taints(parameter)
            if "network" in taints:
                self.signals.flows.append(
                    _Flow(
                        source_class="network",
                        sink_class="code_execution",
                        transforms=(),
                        source_path=self.signals.path,
                        sink_path=self.signals.path,
                        line=sink_line,
                    )
                )
            if "obfuscation" in taints:
                self.signals.flows.append(
                    _Flow(
                        source_class="obfuscation",
                        sink_class="code_execution",
                        transforms=tuple(sorted(self.signals.obfuscations)) or ("decode",),
                        source_path=self.signals.path,
                        sink_path=self.signals.path,
                        line=sink_line,
                    )
                )

    def _record_symbol_taints(self, symbol: str, taints: set[str]) -> None:
        if not taints:
            return
        self.signals.symbol_taints.setdefault(symbol, set()).update(taints)
        sensitive = self._sensitive_taints(taints)
        if sensitive:
            self.signals.source_symbols.setdefault(symbol, set()).update(sensitive)
        if "network" in taints:
            self.signals.download_symbols.add(symbol)
        if "obfuscation" in taints:
            self.signals.obfuscation_symbols.add(symbol)

    def _add_module_reference(self, module: str, base: PurePosixPath) -> str | None:
        relative = PurePosixPath(*module.split("."))
        candidates = (
            base / relative.with_suffix(".py"),
            base / relative / "__init__.py",
            relative.with_suffix(".py"),
            relative / "__init__.py",
        )
        for candidate in candidates:
            path = _normalise_path(candidate)
            if path in self.known_paths:
                self.signals.references.add(path)
                return path
        return None

    def _add_path_reference(self, value: str, base: PurePosixPath) -> str | None:
        if not value or "\x00" in value or len(value) > 1_024:
            return None
        candidate = PurePosixPath(value.replace("\\", "/"))
        if candidate.is_absolute():
            return None
        for possible in (candidate, base / candidate):
            path = _normalise_path(possible)
            if path in self.known_paths:
                self.signals.references.add(path)
                return path
        return None

    def _call_reference_taints(self, callee: str, node: ast.Call) -> set[str]:
        """Return provenance markers from imported modules or file readers."""
        taints: set[str] = set()
        for name, (path, imported_symbol) in self._module_references.items():
            if callee != name and not callee.startswith(f"{name}."):
                continue
            remainder = callee.removeprefix(name).removeprefix(".")
            symbol_parts = [part for part in (imported_symbol, remainder) if part]
            symbol = ".".join(symbol_parts)
            taints.add(f"reference:{path}#{symbol}" if symbol else f"reference:{path}")

        reads_path = callee == "open" or callee.endswith((".read_bytes", ".read_text"))
        if reads_path:
            current = PurePosixPath(self.signals.path)
            for value in _literal_fragments(node):
                referenced_path = self._add_path_reference(value, current.parent)
                if referenced_path is not None:
                    taints.add(f"reference:{referenced_path}")
        return taints

    def _literal_path_reference_taints(self, node: ast.Call) -> set[str]:
        current = PurePosixPath(self.signals.path)
        taints: set[str] = set()
        for value in _literal_fragments(node):
            referenced_path = self._add_path_reference(value, current.parent)
            if referenced_path is not None:
                taints.add(f"reference:{referenced_path}")
        return taints

    @staticmethod
    def _reference_paths(taints: set[str]) -> tuple[str, ...]:
        return tuple(
            sorted(
                value.removeprefix("reference:").partition("#")[0] for value in taints if value.startswith("reference:")
            )
        )

    @staticmethod
    def _reference_inputs(taints: set[str]) -> tuple[str, ...]:
        return tuple(sorted(value.removeprefix("reference:") for value in taints if value.startswith("reference:")))

    def _record_source(self, source_class: str, line: int) -> None:
        self.signals.source_lines.setdefault(source_class, line)

    @staticmethod
    def _sensitive_taints(taints: set[str]) -> set[str]:
        return {value for value in taints if value.startswith("sensitive_") or value == "credential_file"}

    @classmethod
    def _as_authentication_taints(cls, taints: set[str]) -> set[str]:
        """Mark sensitive values as authentication without retaining values."""

        sensitive = cls._sensitive_taints(taints)
        if not sensitive:
            return set(taints)
        classified = set(taints) - sensitive
        classified.add("credential_authentication")
        classified.update(f"authenticated_source:{source}" for source in sensitive)
        return classified

    @staticmethod
    def _authenticated_source_classes(taints: set[str]) -> set[str]:
        return {
            value.removeprefix("authenticated_source:")
            for value in taints
            if value.startswith("authenticated_source:")
            and value.removeprefix("authenticated_source:")
            in {"credential_file", "sensitive_environment", "sensitive_file"}
        }

    @staticmethod
    def _credential_providers(taints: set[str]) -> set[str]:
        return {
            value.removeprefix("credential_provider:")
            for value in taints
            if value.startswith("credential_provider:")
            and re.fullmatch(r"[a-z0-9]{3,32}", value.removeprefix("credential_provider:"))
        }

    def _authentication_destination_matches(
        self,
        providers: set[str],
        urls: tuple[dict[str, Any], ...],
    ) -> bool:
        """Require a resolved provider-bound HTTPS destination.

        Dynamic helpers remain sensitive even if their lexical name and the
        package prose mention the credential provider: both are controlled by
        the package and cannot bind a runtime URL.
        """

        return _authentication_urls_match_providers(providers, urls)

    @staticmethod
    def _is_network_call(callee: str) -> bool:
        if callee in _NETWORK_CALLS:
            return True
        prefix, _, method = callee.rpartition(".")
        if prefix in _NETWORK_CLIENT_TYPES and method in {
            "delete",
            "get",
            "head",
            "options",
            "patch",
            "post",
            "put",
            "request",
            "recv",
            "recvfrom",
            "send",
            "sendall",
            "sendto",
        }:
            return True
        return callee.endswith(".request") and callee.startswith(("requests.", "httpx.", "urllib3."))

    @staticmethod
    def _network_method(callee: str, node: ast.Call) -> str:
        method = callee.rsplit(".", 1)[-1].lower()
        if method == "request":
            method_nodes = [node.args[0]] if node.args else []
            method_nodes.extend(keyword.value for keyword in node.keywords if keyword.arg == "method")
            for method_node in method_nodes:
                if isinstance(method_node, ast.Constant) and isinstance(method_node.value, str):
                    return method_node.value.lower()
        return method

    @staticmethod
    def _is_sensitive_call(callee: str, node: ast.Call) -> bool:
        if callee in {"os.environ.copy", "os.environ.items", "os.environ.values"}:
            return True
        if callee in {"os.getenv", "os.environ.get"}:
            names = _literal_fragments(node)
            return not names or any(_is_sensitive_name(name) for name in names)
        if callee in {"keyring.get_credential", "keyring.get_password"}:
            return True
        if callee == "open" or callee.endswith((".read_bytes", ".read_text")):
            return any(_is_sensitive_path(value) for value in _literal_fragments(node))
        return False


class CorrelationAnalyzer(BaseAnalyzer):
    """Emit deterministic candidates for connected, multi-stage behavior."""

    def __init__(self, policy: ScanPolicy | None = None) -> None:
        super().__init__(name="correlation", policy=policy)

    def analyze(self, skill: Skill) -> list[Finding]:
        signals = self._extract_signals(skill)
        graph = self._reference_graph(signals)
        findings: list[Finding] = []

        findings.extend(self._flow_findings(signals, graph))
        findings.extend(self._fenced_code_findings(skill))
        findings.extend(self._hidden_executable_findings(signals, graph))
        findings.extend(self._config_execution_findings(signals, graph))
        findings.extend(self._nested_archive_findings(signals))

        mismatch = self._manifest_mismatch_finding(skill, signals)
        if mismatch is not None:
            findings.append(mismatch)
        return self._dedupe_findings(findings)

    def _extract_signals(self, skill: Skill) -> dict[str, _FileSignals]:
        known_paths = {_normalise_path(file.relative_path) for file in skill.files}
        referenced = {_normalise_path(path) for path in skill.referenced_files}
        declared_domains = _declared_service_domains(skill)
        declared_provider_labels = _declared_provider_labels(skill)
        signals: dict[str, _FileSignals] = {}

        for skill_file in skill.files:
            path = _normalise_path(skill_file.relative_path)
            file_signals = _FileSignals(
                path=path,
                file_type=skill_file.file_type,
                hidden=skill_file.is_hidden,
                executable=self._is_executable(skill_file),
                archive_depth=max(0, skill_file.archive_depth),
                referenced_by_skill=path in referenced,
            )
            content = skill_file.read_content()
            if content:
                if skill_file.file_type == "python":
                    self._extract_python(content, file_signals, known_paths, declared_provider_labels)
                elif skill_file.file_type == "bash":
                    self._extract_shell(content, file_signals, known_paths, declared_domains)
                elif skill_file.file_type in {"javascript", "typescript"}:
                    self._extract_javascript(content, file_signals, declared_domains)
                elif PurePosixPath(path).suffix.lower() in _CONFIG_SUFFIXES:
                    file_signals.config_parsed, file_signals.config_urls = _parse_config_urls(content, path)
                    if file_signals.config_urls:
                        file_signals.urls.extend(fact for facts in file_signals.config_urls.values() for fact in facts)
                    else:
                        file_signals.urls.extend(
                            _url_fact(url, path) for url in extract_urls(content[:1_000_000])[:_MAX_CONFIG_URL_FACTS]
                        )
            signals[path] = file_signals
        return signals

    def _fenced_code_findings(self, skill: Skill) -> list[Finding]:
        """Run existing structured extractors on bounded SKILL.md fences.

        Each fence is analyzed in isolation.  That is important for precision:
        a download in one example must never be correlated with execution in a
        different example merely because both appear in the same Markdown
        document.  The physical path and line offset are retained on findings,
        while raw fence content never enters semantic facts.
        """

        findings: list[Finding] = []
        known_paths = {_normalise_path(file.relative_path) for file in skill.files}
        declared_domains = _declared_service_domains(skill)
        declared_provider_labels = _declared_provider_labels(skill)
        for block in self._extract_fenced_code(skill):
            file_signals = _FileSignals(
                path="SKILL.md",
                file_type=block.file_type,
                line_offset=block.line_offset,
                context_kind=block.context_kind,
                evidence_kind="fenced_code_flow",
                role_kind=block.role_kind,
            )
            if block.file_type == "python":
                if not any(marker in block.content for marker in _PYTHON_FENCE_FLOW_MARKERS):
                    continue
                self._extract_python(block.content, file_signals, known_paths, declared_provider_labels)
            else:
                if not self._shell_fence_may_flow(block.content):
                    continue
                self._extract_shell(block.content, file_signals, known_paths, declared_domains)
            signals = {file_signals.path: file_signals}
            findings.extend(self._flow_findings(signals, {file_signals.path: set()}))
        return findings

    @staticmethod
    def _shell_fence_may_flow(content: str) -> bool:
        """Cheap structured prefilter before the full shell provenance pass.

        This only uses the same command-position lexer and command classes as
        the extractor.  Co-occurrence can admit a near miss here, but it can
        never create a finding; exact provenance remains mandatory below.
        """

        if not any(marker in content for marker in _SHELL_FENCE_FLOW_MARKERS):
            return False

        network = False
        execution = False
        direct_path_execution = False
        obfuscation = False
        sensitive = False
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for command in _shell_commands(stripped):
                executable = command.executable
                arguments = command.arguments
                variables = _shell_variable_names(command)
                if executable in _SHELL_NETWORK:
                    network = True
                    if any(_is_sensitive_name(name) for name in variables) or any(
                        _is_sensitive_path(argument.lstrip("@")) for argument in arguments
                    ):
                        sensitive = True
                if executable in _SHELL_EXECUTION:
                    execution = True
                elif "/" in command.raw_executable and executable not in _SHELL_READERS | _SHELL_NETWORK:
                    direct_path_execution = True
                if executable in _SHELL_OBFUSCATION and _is_shell_decode(command):
                    obfuscation = True
                if executable in {"env", "printenv"}:
                    sensitive = True
                if executable in {"cat", "head", "tail"} and any(
                    _is_sensitive_path(argument) for argument in arguments
                ):
                    sensitive = True
        return (network and (execution or direct_path_execution or sensitive)) or (obfuscation and execution)

    @classmethod
    def _extract_fenced_code(cls, skill: Skill) -> list[_FencedCodeBlock]:
        """Return complete, supported fences within fixed count/size bounds."""

        content = skill.instruction_body[:_FENCED_CODE_MARKDOWN_LIMIT]
        lines = content.splitlines()
        blocks: list[_FencedCodeBlock] = []
        total_chars = 0
        fence_candidates = 0
        marker_char = ""
        marker_length = 0
        opener_indent = 0
        opener_line = 0
        file_type: str | None = None
        block_context = "code"
        block_lines: list[str] = []
        section_context = "code"
        section_role = ""
        previous_nonempty = ""

        for line_index, line in enumerate(lines):
            match = _FENCE_RE.match(line)
            if marker_char:
                if match is not None:
                    marker = match.group("marker")
                    info = match.group("info")
                    if marker[0] == marker_char and len(marker) >= marker_length and not info.strip():
                        if file_type is not None and len(blocks) < _FENCED_CODE_BLOCK_LIMIT:
                            block = "\n".join(block_lines)
                            block_chars = len(block)
                            if (
                                block_chars <= _FENCED_CODE_BLOCK_CHAR_LIMIT
                                and total_chars + block_chars <= _FENCED_CODE_TOTAL_CHAR_LIMIT
                            ):
                                blocks.append(
                                    _FencedCodeBlock(
                                        file_type=file_type,
                                        content=block,
                                        line_offset=skill.instruction_body_line_offset + opener_line + 1,
                                        context_kind=block_context,
                                        role_kind=cls._fence_block_role(skill, section_role, block),
                                    )
                                )
                                total_chars += block_chars
                        marker_char = ""
                        marker_length = 0
                        opener_indent = 0
                        file_type = None
                        block_lines = []
                        previous_nonempty = ""
                        continue
                if file_type is not None:
                    # CommonMark strips up to the opener indentation from code
                    # lines.  Preserve all other whitespace for Python ASTs.
                    removable = min(opener_indent, len(line) - len(line.lstrip(" ")))
                    block_lines.append(line[removable:])
                continue

            heading = _HEADING_RE.match(line)
            if heading is not None:
                heading_title = heading.group("title")
                section_context = cls._fence_section_context(heading_title)
                section_role = cls._fence_section_role(heading_title)

            if match is not None:
                marker = match.group("marker")
                info = match.group("info").strip()
                # Backticks in a backtick info string are malformed CommonMark
                # and must not expand the code region.
                if marker[0] == "`" and "`" in info:
                    previous_nonempty = line.strip() or previous_nonempty
                    continue
                fence_candidates += 1
                if fence_candidates > _FENCED_CODE_BLOCK_LIMIT * 2:
                    break
                language = info.split(None, 1)[0].lower() if info else ""
                if language in _PYTHON_FENCE_LANGUAGES:
                    file_type = "python"
                elif language in _SHELL_FENCE_LANGUAGES:
                    file_type = "bash"
                else:
                    file_type = None
                marker_char = marker[0]
                marker_length = len(marker)
                opener_indent = len(match.group("indent"))
                opener_line = line_index
                block_context = cls._fence_context(section_context, previous_nonempty)
                block_lines = []
                continue

            if line.strip():
                previous_nonempty = line.strip()[:512]

        # An unclosed fence is intentionally discarded; parsing a truncated
        # fragment would invent control/data relationships that are not present.
        return blocks

    @staticmethod
    def _fence_section_context(title: str) -> str:
        if _NEGATIVE_EXAMPLE_HEADING_RE.search(title):
            return "negative_example"
        if _PROHIBITION_HEADING_RE.search(title):
            return "prohibition"
        if _EXAMPLE_HEADING_RE.search(title):
            return "example"
        return "code"

    @staticmethod
    def _fence_section_role(title: str) -> str:
        """Return a bounded file-role classification for executable guidance.

        A heading alone never changes a candidate. The provisional role is
        bound to a manifest-declared provider by ``_fence_block_role`` before
        it can affect severity.
        """

        return "documented_installer" if _DOCUMENTED_INSTALLER_HEADING_RE.search(title) else ""

    @staticmethod
    def _fence_block_role(skill: Skill, section_role: str, block: str) -> str:
        """Bind an installer heading to a manifest-declared HTTPS provider.

        The comparison uses normalized provider labels, not vendor names or a
        trust list.  Domains mentioned only inside the executable snippet are
        insufficient: the skill manifest must independently declare the same
        provider.  Suspicious or mixed-provider blocks remain ordinary code.
        """

        if section_role != "documented_installer":
            return ""
        declared = {label for domain in _declared_service_domains(skill) if (label := _service_provider_label(domain))}
        urls = [_url_fact(raw_url, "SKILL.md") for raw_url in extract_urls(block)[:64]]
        if not declared or not urls:
            return ""
        providers = {_service_provider_label(str(url.get("host", ""))) for url in urls}
        if "" in providers or not providers <= declared:
            return ""
        if any(url.get("scheme") != "https" or url.get("domain_class") == "suspicious" for url in urls):
            return ""
        return section_role

    @staticmethod
    def _fence_context(section_context: str, previous_nonempty: str) -> str:
        if _NEGATIVE_EXAMPLE_HEADING_RE.search(previous_nonempty):
            return "negative_example"
        if _PROHIBITION_LEAD_RE.fullmatch(previous_nonempty):
            return "prohibition"
        if _EXAMPLE_LEAD_RE.fullmatch(previous_nonempty):
            return "example"
        return section_context

    @staticmethod
    def _extract_python(
        content: str,
        signals: _FileSignals,
        known_paths: set[str],
        declared_provider_labels: set[str] | None = None,
    ) -> None:
        try:
            tree = ast.parse(content)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError):
            return
        _PythonSignalExtractor(signals, known_paths, declared_provider_labels).extract(tree)
        if signals.context_kind == "code" and all(marker in content for marker in _NETWORK_WRITE_PREFILTER_MARKERS):
            signals.flows.extend(_BoundedNetworkFileWriteTracker(signals).extract(tree))

    @staticmethod
    def _extract_javascript(
        content: str,
        signals: _FileSignals,
        declared_domains: set[str] | None = None,
    ) -> None:
        """Adapt complete bounded JS/TS facts to the correlation model.

        Lexical, structural, and resource-limit failures deliberately add no
        partial signal. Broad static and YARA candidates remain untouched as
        fail-open coverage.
        """

        result = analyze_javascript_dataflow(content)
        if not result.complete:
            return

        for source in result.sources:
            if source.source_class in {"credential_file", "sensitive_environment"}:
                signals.source_lines.setdefault(source.source_class, source.line)

        for network in result.networks:
            normalized_urls: list[dict[str, Any]] = []
            for endpoint in network.endpoints:
                url = _url_fact(
                    f"{endpoint.scheme}://{endpoint.host}",
                    signals.path,
                    direction=network.direction,
                    method=network.method,
                )
                # The shared classifier intentionally calls ordinary public
                # domains "unknown". Flow facts use the closed semantic
                # vocabulary, where a syntactically valid unclassified remote
                # endpoint is the structural class "external".
                if url["domain_class"] == "unknown":
                    url["domain_class"] = "external"
                normalized_urls.append(url)
            urls = tuple(normalized_urls)
            destination_class = _network_destination_class(
                urls,
                configured=False,
                declared_domains=declared_domains,
            )
            if network.provider_bound_authentication:
                destination_class = "provider_bound_service"
            signals.networks.append(
                _NetworkEvent(
                    line=network.line,
                    executable=network.api_class.split(".", 1)[0],
                    method=network.method,
                    direction=network.direction,
                    downloads=network.downloads,
                    urls=urls,
                    credential_use=network.credential_use,
                    destination_class=destination_class,
                )
            )
            signals.urls.extend(urls)

        for execution in result.executions:
            signals.executions.append(
                _ExecutionEvent(
                    line=execution.line,
                    executable=execution.api_class,
                    dynamic=execution.dynamic,
                )
            )
        for transform in result.transforms:
            signals.obfuscations.setdefault(transform.transform, transform.line)
        signals.flows.extend(
            _Flow(
                source_class=flow.source_class,
                sink_class=flow.sink_class,
                transforms=flow.transforms,
                source_path=signals.path,
                sink_path=signals.path,
                line=flow.line,
            )
            for flow in result.flows
        )

    @staticmethod
    def _extract_shell(
        content: str,
        signals: _FileSignals,
        known_paths: set[str],
        declared_domains: set[str] | None = None,
    ) -> None:
        current = PurePosixPath(signals.path)
        commands_by_line: dict[int, set[str]] = {}
        parsed_commands_by_line: dict[int, list[_ShellCommand]] = {}
        variable_taints: dict[str, set[str]] = {}
        variable_provider_origins: dict[str, set[str]] = {}
        literal_variables: dict[str, str] = {}
        downloaded_artifacts: set[str] = set()
        for line_number, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            assignment = _SHELL_VAR_ASSIGNMENT.match(stripped)
            if assignment is not None:
                name = assignment.group("name")
                referenced_names = _SHELL_VAR_REFERENCE.findall(assignment.group("value"))
                provider_origins: set[str] = set()
                for referenced_name in referenced_names:
                    if referenced_name in variable_provider_origins:
                        provider_origins.update(variable_provider_origins[referenced_name])
                    elif _is_sensitive_name(referenced_name):
                        provider_origins.update(_credential_provider_tokens(referenced_name))
                # Presence in this mapping records that the sink variable was
                # reassigned.  An empty set is deliberately inconclusive and
                # must not fall back to trusting the alias name itself.
                variable_provider_origins[name] = provider_origins
                literal = _literal_shell_assignment(assignment.group("value"))
                if literal is None:
                    literal_variables.pop(name, None)
                else:
                    literal_variables[name] = literal
            commands = _shell_commands(stripped)
            if not commands:
                if assignment is not None:
                    propagated = {
                        taint
                        for name in _SHELL_VAR_REFERENCE.findall(assignment.group("value"))
                        for taint in variable_taints.get(name, set())
                    }
                    if propagated:
                        variable_taints[assignment.group("name")] = propagated
                continue
            commands_by_line[line_number] = {command.executable for command in commands}
            parsed_commands_by_line[line_number] = commands

            for command in commands:
                executable = command.executable
                raw_args = list(command.arguments)
                referenced_paths: set[str] = set()
                command_variables = _shell_variable_names(command)
                command_taints = {taint for name in command_variables for taint in variable_taints.get(name, set())}
                if any(_is_sensitive_name(name) for name in command_variables):
                    command_taints.add("sensitive_environment")
                    signals.source_lines.setdefault("sensitive_environment", line_number)

                def add_reference(value: str) -> None:
                    if not value or "\x00" in value or len(value) > 1_024:
                        return
                    candidate = PurePosixPath(value.replace("\\", "/"))
                    if candidate.is_absolute():
                        return
                    for possible in (candidate, current.parent / candidate):
                        path = _normalise_path(possible)
                        if path in known_paths:
                            signals.references.add(path)
                            referenced_paths.add(path)
                            return

                add_reference(command.raw_executable)
                if executable in _SHELL_READERS | _SHELL_EXECUTION:
                    for argument in raw_args:
                        if not argument.startswith("-"):
                            add_reference(argument)

                if executable in _SHELL_NETWORK:
                    sensitive_path = any(_is_sensitive_path(argument.lstrip("@")) for argument in raw_args)
                    if sensitive_path:
                        command_taints.add("credential_file")
                        signals.source_lines.setdefault("credential_file", line_number)
                    sensitive_source = sorted(
                        taint
                        for taint in command_taints
                        if taint in {"credential_file", "sensitive_environment", "sensitive_file"}
                    )
                    sensitive_names = {name for name in command_variables if _is_sensitive_name(name)}
                    credential_use = "payload" if sensitive_path else _shell_credential_use(command, sensitive_names)
                    payload_options = any(
                        argument in _CURL_PAYLOAD_OPTIONS
                        or any(argument.startswith(f"{option}=") for option in _CURL_PAYLOAD_OPTIONS)
                        for argument in raw_args
                    )
                    method = "post" if payload_options else "get"
                    for method_index, argument in enumerate(raw_args[:-1]):
                        if argument in {"-X", "--request", "--method"}:
                            method = raw_args[method_index + 1].lower()
                            break
                    resolved_urls, configured_endpoint = _shell_network_urls(command, literal_variables)
                    provisional_urls = tuple(_url_fact(url, signals.path, method=method) for url in resolved_urls)
                    destination_class = _network_destination_class(
                        provisional_urls,
                        configured=configured_endpoint,
                        declared_domains=declared_domains,
                    )
                    credential_providers = {
                        provider
                        for name in sensitive_names
                        for provider in (
                            variable_provider_origins[name]
                            if name in variable_provider_origins
                            else _credential_provider_tokens(name)
                        )
                    }
                    normal_authentication = credential_use == "authentication" and _authentication_urls_match_providers(
                        credential_providers,
                        provisional_urls,
                    )
                    if normal_authentication:
                        destination_class = "provider_bound_service"
                    reportable_sensitive = [] if normal_authentication else sensitive_source
                    outbound = (
                        bool(reportable_sensitive)
                        or executable in {"nc", "ncat", "netcat", "socat"}
                        or payload_options
                        or method in _OUTBOUND_METHODS
                    )
                    direction = "outbound" if outbound else "inbound"
                    urls = tuple(
                        _url_fact(url, signals.path, direction=direction, method=method) for url in resolved_urls
                    )
                    signals.networks.append(
                        _NetworkEvent(
                            line=line_number,
                            executable=executable,
                            method=method,
                            direction=direction,
                            downloads=executable in {"curl", "wget"} and method == "get",
                            urls=urls,
                            source_paths=tuple(sorted(referenced_paths)),
                            credential_use=credential_use,
                            destination_class=destination_class,
                        )
                    )
                    signals.urls.extend(urls)
                    if reportable_sensitive:
                        signals.flows.append(
                            _Flow(
                                reportable_sensitive[0],
                                "network",
                                (),
                                signals.path,
                                signals.path,
                                line_number,
                            )
                        )
                    output_path = _download_output_path(command)
                    if output_path and "$" not in output_path and "`" not in output_path:
                        downloaded_artifacts.add(_normalise_path(output_path))
                if executable in _SHELL_EXECUTION:
                    execution_inputs = _shell_execution_inputs(command)
                    dynamic = any("$" in token or "`" in token for token in execution_inputs)
                    signals.executions.append(
                        _ExecutionEvent(
                            line_number,
                            executable,
                            dynamic,
                            tuple(sorted(referenced_paths)),
                        )
                    )
                    execution_taints = {
                        taint
                        for token in execution_inputs
                        for name in _SHELL_VAR_REFERENCE.findall(token)
                        for taint in variable_taints.get(name, set())
                    }
                    if "network" in execution_taints:
                        signals.flows.append(
                            _Flow("network", "code_execution", (), signals.path, signals.path, line_number)
                        )
                    if "obfuscation" in execution_taints:
                        signals.flows.append(
                            _Flow(
                                "obfuscation",
                                "code_execution",
                                ("decode",),
                                signals.path,
                                signals.path,
                                line_number,
                            )
                        )
                    if any(
                        _normalise_path(token) in downloaded_artifacts
                        for token in execution_inputs
                        if token and "$" not in token and "`" not in token
                    ):
                        signals.flows.append(
                            _Flow("network", "code_execution", (), signals.path, signals.path, line_number)
                        )
                elif referenced_paths and executable not in _SHELL_READERS:
                    # A package-relative executable invoked directly (for
                    # example ``./scripts/helper``) is an execution event.
                    signals.executions.append(
                        _ExecutionEvent(
                            line_number,
                            executable,
                            any("$" in token or "`" in token for token in raw_args),
                            tuple(sorted(referenced_paths)),
                        )
                    )
                elif _normalise_path(command.raw_executable) in downloaded_artifacts:
                    signals.executions.append(_ExecutionEvent(line_number, executable, True))
                    signals.flows.append(
                        _Flow("network", "code_execution", (), signals.path, signals.path, line_number)
                    )
                if executable in _SHELL_OBFUSCATION and _is_shell_decode(command):
                    signals.obfuscations.setdefault(f"{executable}_decode", line_number)
                if executable in _SHELL_ARCHIVES:
                    signals.archive_operations.setdefault("archive_extract", line_number)

            if assignment is not None:
                assignment_taints = {
                    taint
                    for name in _SHELL_VAR_REFERENCE.findall(assignment.group("value"))
                    for taint in variable_taints.get(name, set())
                }
                if any(command.executable in _SHELL_NETWORK for command in commands):
                    assignment_taints.add("network")
                if any(_is_shell_decode(command) for command in commands):
                    assignment_taints.add("obfuscation")
                if assignment_taints:
                    variable_taints[assignment.group("name")] = assignment_taints

            command_names = commands_by_line[line_number]
            if command_names & {"env", "printenv"}:
                signals.source_lines.setdefault("sensitive_environment", line_number)
            if command_names & {"cat", "head", "tail"} and any(
                command.executable in {"cat", "head", "tail"}
                and any(_is_sensitive_path(argument) for argument in command.arguments)
                for command in commands
            ):
                signals.source_lines.setdefault("credential_file", line_number)

            # Mere co-occurrence on a line is not a flow.  Only a continuous
            # pipeline into an execution command supplies explicit shell data
            # provenance (variable flows are handled by the taint tracker).
            for sink_index, sink in enumerate(commands):
                if sink.executable not in _SHELL_EXECUTION:
                    continue
                upstream: list[_ShellCommand] = []
                cursor = sink_index
                while cursor > 0 and commands[cursor].preceding_operator == "|":
                    upstream.append(commands[cursor - 1])
                    cursor -= 1
                if any(command.executable in _SHELL_NETWORK for command in upstream):
                    signals.flows.append(
                        _Flow("network", "code_execution", (), signals.path, signals.path, line_number)
                    )
                if any(_is_shell_decode(command) for command in upstream):
                    signals.flows.append(
                        _Flow(
                            "obfuscation",
                            "code_execution",
                            ("decode",),
                            signals.path,
                            signals.path,
                            line_number,
                        )
                    )

        # Reuse the existing variable-aware shell tracker for explicit flows,
        # discarding its raw source/sink snippets at this boundary.
        for flow in analyze_bash_script(content, signals.path):
            if flow.sink_command not in commands_by_line.get(flow.sink_line, set()):
                continue
            if not any(
                command.executable == flow.sink_command and flow.source_var in _shell_variable_names(command)
                for command in parsed_commands_by_line.get(flow.sink_line, [])
            ):
                continue
            taints = flow.taints
            if flow.sink_command in _SHELL_NETWORK and taints & {
                BashTaintType.CREDENTIAL,
                BashTaintType.ENV_VAR,
                BashTaintType.SENSITIVE_FILE,
            }:
                if BashTaintType.CREDENTIAL in taints:
                    source = "credential_file"
                elif BashTaintType.ENV_VAR in taints:
                    source = "sensitive_environment"
                else:
                    source = "sensitive_file"
                signals.flows.append(_Flow(source, "network", (), signals.path, signals.path, flow.sink_line))
            if flow.sink_command in _SHELL_EXECUTION and BashTaintType.NETWORK_INPUT in taints:
                signals.flows.append(_Flow("network", "code_execution", (), signals.path, signals.path, flow.sink_line))

    def _flow_findings(self, signals: dict[str, _FileSignals], graph: dict[str, set[str]]) -> list[Finding]:
        findings: list[Finding] = []

        for item in signals.values():
            for flow in item.flows:
                spec = self._flow_spec(flow)
                if spec is not None:
                    severity = self._same_file_flow_severity(item, flow)
                    findings.append(self._make_flow_finding(flow, severity, spec, signals, graph))

        sources = [item for item in signals.values() if item.source_lines]
        outbound = [item for item in signals.values() if any(event.direction == "outbound" for event in item.networks)]
        downloads = [item for item in signals.values() if any(event.downloads for event in item.networks)]
        dynamic_exec = [item for item in signals.values() if any(event.dynamic for event in item.executions)]
        obfuscated = [item for item in signals.values() if item.obfuscations]

        for source in sources:
            for sink in outbound:
                consuming_network_events: list[_NetworkEvent] = []
                consumed_source_classes: set[str] = set()
                for event in sink.networks:
                    if event.direction != "outbound":
                        continue
                    if event.credential_use == "authentication" and event.destination_class == "provider_bound_service":
                        continue
                    classes = self._consumed_source_classes(source, event.source_refs, signals)
                    if classes:
                        consuming_network_events.append(event)
                        consumed_source_classes.update(classes)
                if source.path == sink.path or not consuming_network_events:
                    continue
                source_class = sorted(consumed_source_classes)[0]
                flow = _Flow(
                    source_class,
                    "network",
                    (),
                    source.path,
                    sink.path,
                    min(event.line for event in consuming_network_events),
                    True,
                )
                severity = Severity.HIGH if self._has_suspicious_url(sink) else Severity.MEDIUM
                findings.append(self._make_flow_finding(flow, severity, self._flow_spec(flow), signals, graph))

        for source in downloads:
            for sink in dynamic_exec:
                consuming_execution_events: list[_ExecutionEvent] = [
                    event
                    for event in sink.executions
                    if event.dynamic
                    and self._consumes_symbol_behavior(
                        source.path,
                        source.download_symbols,
                        event.source_refs,
                        signals,
                    )
                ]
                if source.path == sink.path or not consuming_execution_events:
                    continue
                flow = _Flow(
                    "network",
                    "code_execution",
                    (),
                    source.path,
                    sink.path,
                    min(event.line for event in consuming_execution_events),
                    True,
                )
                severity = Severity.HIGH if self._has_untrusted_or_dynamic_url(source) else Severity.MEDIUM
                findings.append(self._make_flow_finding(flow, severity, self._flow_spec(flow), signals, graph))

        for source in obfuscated:
            for sink in dynamic_exec:
                consuming_execution_events = [
                    event
                    for event in sink.executions
                    if event.dynamic
                    and self._consumes_symbol_behavior(
                        source.path,
                        source.obfuscation_symbols,
                        event.source_refs,
                        signals,
                    )
                ]
                if source.path == sink.path or not consuming_execution_events:
                    continue
                flow = _Flow(
                    "obfuscation",
                    "code_execution",
                    ("decode",),
                    source.path,
                    sink.path,
                    min(event.line for event in consuming_execution_events),
                    True,
                )
                findings.append(self._make_flow_finding(flow, Severity.HIGH, self._flow_spec(flow), signals, graph))
        findings.extend(self._interprocedural_sink_findings(signals, graph, sources, downloads, obfuscated))
        return findings

    def _interprocedural_sink_findings(
        self,
        signals: dict[str, _FileSignals],
        graph: dict[str, set[str]],
        sources: list[_FileSignals],
        downloads: list[_FileSignals],
        obfuscated: list[_FileSignals],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for caller in signals.values():
            for call in caller.calls:
                target = signals.get(call.target_path)
                if target is None:
                    continue
                parameters = target.function_parameters.get(call.target_symbol, ())
                network_parameters = target.sink_parameters.get(call.target_symbol, {}).get("network", {})
                for parameter, sink_line in network_parameters.items():
                    references = self._call_argument_references(call, parameters, parameter)
                    if not references:
                        continue
                    for source in sources:
                        if source.path == target.path:
                            continue
                        classes = self._consumed_source_classes(source, references, signals)
                        if not classes:
                            continue
                        flow = _Flow(
                            sorted(classes)[0],
                            "network",
                            (),
                            source.path,
                            target.path,
                            sink_line,
                            True,
                            (caller.path,),
                        )
                        severity = Severity.HIGH if self._has_suspicious_url(target) else Severity.MEDIUM
                        findings.append(self._make_flow_finding(flow, severity, self._flow_spec(flow), signals, graph))
                execution_parameters = target.sink_parameters.get(call.target_symbol, {}).get("code_execution", {})
                for parameter, sink_line in execution_parameters.items():
                    references = self._call_argument_references(call, parameters, parameter)
                    if not references:
                        continue
                    for source in downloads:
                        if source.path == target.path or not self._consumes_symbol_behavior(
                            source.path, source.download_symbols, references, signals
                        ):
                            continue
                        flow = _Flow(
                            "network",
                            "code_execution",
                            (),
                            source.path,
                            target.path,
                            sink_line,
                            True,
                            (caller.path,),
                        )
                        severity = Severity.HIGH if self._has_untrusted_or_dynamic_url(source) else Severity.MEDIUM
                        findings.append(self._make_flow_finding(flow, severity, self._flow_spec(flow), signals, graph))
                    for source in obfuscated:
                        if source.path == target.path or not self._consumes_symbol_behavior(
                            source.path, source.obfuscation_symbols, references, signals
                        ):
                            continue
                        flow = _Flow(
                            "obfuscation",
                            "code_execution",
                            ("decode",),
                            source.path,
                            target.path,
                            sink_line,
                            True,
                            (caller.path,),
                        )
                        findings.append(
                            self._make_flow_finding(flow, Severity.HIGH, self._flow_spec(flow), signals, graph)
                        )
        return findings

    @staticmethod
    def _call_argument_references(call: _CallEvent, parameters: tuple[str, ...], parameter: str) -> tuple[str, ...]:
        keyword_refs = dict(call.keyword_refs)
        if parameter in keyword_refs:
            return keyword_refs[parameter]
        try:
            index = parameters.index(parameter)
        except ValueError:
            return ()
        if index >= len(call.positional_refs):
            return ()
        return call.positional_refs[index]

    @staticmethod
    def _flow_spec(flow: _Flow) -> tuple[str, ThreatCategory, str, str] | None:
        if flow.sink_class == "network" and flow.source_class in {
            "credential_file",
            "sensitive_environment",
            "sensitive_file",
        }:
            return (
                "CORRELATED_SENSITIVE_NETWORK_FLOW",
                ThreatCategory.DATA_EXFILTRATION,
                "Sensitive source reaches a network sink",
                "Remove the transmission or constrain it to explicitly declared, trusted destinations.",
            )
        if flow.source_class == "network" and flow.sink_class == "code_execution":
            return (
                "CORRELATED_NETWORK_EXECUTION_FLOW",
                ThreatCategory.COMMAND_INJECTION,
                "Network-derived content reaches code execution",
                "Verify downloaded content cryptographically and never pass network data to a dynamic interpreter.",
            )
        if flow.source_class == "network" and flow.sink_class == "filesystem_write":
            return (
                "CORRELATED_NETWORK_FILE_WRITE_FLOW",
                ThreatCategory.MALWARE,
                "Network-derived bytes written to a dynamic file destination",
                "Use a fixed, reviewable destination and verify a trusted digest before persisting network content.",
            )
        if flow.source_class == "obfuscation" and flow.sink_class == "code_execution":
            return (
                "CORRELATED_OBFUSCATION_EXECUTION_FLOW",
                ThreatCategory.OBFUSCATION,
                "Decoded or unpacked content reaches code execution",
                "Remove dynamic decoding/execution and ship reviewable source code instead.",
            )
        return None

    def _make_flow_finding(
        self,
        flow: _Flow,
        severity: Severity,
        spec: tuple[str, ThreatCategory, str, str] | None,
        signals: dict[str, _FileSignals],
        graph: dict[str, set[str]],
    ) -> Finding:
        if spec is None:  # Defensive: callers only pass supported flows.
            raise ValueError(f"unsupported correlated flow: {flow.source_class}->{flow.sink_class}")
        rule_id, category, title, remediation = spec
        reference_path = self._directed_reference_path(graph, flow.sink_path, flow.source_path)
        files = sorted(
            {
                *(reference_path or (flow.source_path, flow.sink_path)),
                *flow.via_paths,
            }
        )
        sink_signals = signals.get(flow.sink_path)
        physical_line = self._physical_line(sink_signals, flow.line)
        identity_values = list(files)
        if sink_signals is not None and sink_signals.line_offset:
            identity_values.append(f"line:{physical_line}")
        description = f"Correlated {flow.source_class} → {flow.sink_class} behavior across {', '.join(files)}."
        semantic = self._semantic_facts(files, signals, graph, flow=flow)
        return Finding(
            id=self._finding_id(rule_id, identity_values),
            rule_id=rule_id,
            category=category,
            severity=severity,
            title=title,
            description=description,
            file_path=flow.sink_path,
            line_number=physical_line,
            remediation=remediation,
            analyzer=self.get_name(),
            metadata={"files_involved": files, "semantic_facts": semantic},
        )

    def _hidden_executable_findings(
        self, signals: dict[str, _FileSignals], graph: dict[str, set[str]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        for item in signals.values():
            if not item.hidden or item.referenced_by_skill:
                continue
            invoking_files = [
                other.path
                for other in signals.values()
                if any(item.path in event.source_paths for event in other.executions)
            ]
            if not item.executable and not invoking_files:
                continue
            if not item.has_dangerous_behavior and not invoking_files:
                continue
            files = sorted({item.path, *invoking_files})
            severity = Severity.HIGH if item.has_dangerous_behavior else Severity.MEDIUM
            findings.append(
                Finding(
                    id=self._finding_id("CORRELATED_HIDDEN_EXECUTABLE", files),
                    rule_id="CORRELATED_HIDDEN_EXECUTABLE",
                    category=ThreatCategory.MALWARE,
                    severity=severity,
                    title="Hidden, undeclared executable has correlated behavior",
                    description=f"Executable {item.path} is hidden, absent from SKILL.md references, and behaviorally connected.",
                    file_path=item.path,
                    line_number=self._first_line(item),
                    remediation="Document and reference executable helpers, or remove the hidden executable.",
                    analyzer=self.get_name(),
                    metadata={
                        "files_involved": files,
                        "semantic_facts": self._semantic_facts(files, signals, graph, signal_kind="hidden_executable"),
                    },
                )
            )
        return findings

    def _config_execution_findings(self, signals: dict[str, _FileSignals], graph: dict[str, set[str]]) -> list[Finding]:
        findings: list[Finding] = []
        configs = [
            item
            for item in signals.values()
            if PurePosixPath(item.path).suffix.lower() in _CONFIG_SUFFIXES
            and any(url["domain_class"] != "legitimate" for url in item.urls)
        ]
        for config in configs:
            for downloader in signals.values():
                config_downloads = [
                    event
                    for event in downloader.networks
                    if event.downloads and config.path in event.source_paths and self._event_config_urls(config, event)
                ]
                if not config_downloads:
                    continue
                untrusted = [
                    url
                    for event in config_downloads
                    for url in self._event_config_urls(config, event)
                    if url["domain_class"] != "legitimate"
                ]
                if not untrusted:
                    continue
                severity = (
                    Severity.HIGH if any(url["domain_class"] == "suspicious" for url in untrusted) else Severity.MEDIUM
                )
                execution_sinks: list[tuple[_FileSignals, int]] = []
                local_lines = [
                    flow.line
                    for flow in downloader.flows
                    if flow.source_class == "network" and flow.sink_class == "code_execution"
                ]
                if local_lines:
                    execution_sinks.append((downloader, min(local_lines)))
                for executor in signals.values():
                    if executor.path == downloader.path:
                        continue
                    lines = [
                        event.line
                        for event in executor.executions
                        if event.dynamic
                        and self._consumes_symbol_behavior(
                            downloader.path,
                            downloader.download_symbols,
                            event.source_refs,
                            signals,
                        )
                    ]
                    if lines:
                        execution_sinks.append((executor, min(lines)))

                for executor, execution_line in execution_sinks:
                    flow = _Flow(
                        "config_url",
                        "code_execution",
                        ("network_download",),
                        config.path,
                        executor.path,
                        execution_line,
                        True,
                    )
                    reference_path = self._directed_reference_path(graph, executor.path, config.path)
                    files = sorted(set(reference_path or (config.path, downloader.path, executor.path)))
                    semantic = self._semantic_facts(files, signals, graph, flow=flow)
                    findings.append(
                        Finding(
                            id=self._finding_id("CORRELATED_CONFIG_URL_EXECUTION", files),
                            rule_id="CORRELATED_CONFIG_URL_EXECUTION",
                            category=ThreatCategory.SUPPLY_CHAIN_ATTACK,
                            severity=severity,
                            title="Configuration-controlled URL reaches execution",
                            description=(
                                f"{executor.path} executes content downloaded through configuration {config.path}."
                            ),
                            file_path=executor.path,
                            line_number=flow.line,
                            remediation="Pin a trusted origin and integrity hash, and remove dynamic execution of downloaded content.",
                            analyzer=self.get_name(),
                            metadata={"files_involved": files, "semantic_facts": semantic},
                        )
                    )
        return findings

    @staticmethod
    def _event_config_urls(config: _FileSignals, event: _NetworkEvent) -> list[dict[str, Any]]:
        matched: list[dict[str, Any]] = []
        saw_key = False
        for reference in event.source_refs:
            path, separator, symbol = reference.partition("#")
            if path != config.path:
                continue
            if separator and symbol.startswith("key:"):
                saw_key = True
                matched.extend(config.config_urls.get(symbol.removeprefix("key:"), []))
        if saw_key and config.config_parsed:
            return matched
        return list(config.urls)

    def _nested_archive_findings(self, signals: dict[str, _FileSignals]) -> list[Finding]:
        findings: list[Finding] = []
        for item in signals.values():
            if item.archive_depth < 2 or item.file_type not in _SCRIPT_TYPES:
                continue
            if item.referenced_by_skill and not item.has_dangerous_behavior:
                continue
            severity = Severity.HIGH if item.has_dangerous_behavior else Severity.MEDIUM
            files = [item.path]
            findings.append(
                Finding(
                    id=self._finding_id("CORRELATED_NESTED_ARCHIVE_SCRIPT", files),
                    rule_id="CORRELATED_NESTED_ARCHIVE_SCRIPT",
                    category=ThreatCategory.MALWARE,
                    severity=severity,
                    title="Nested archive contains an undeclared script",
                    description=f"Script {item.path} was recovered at archive depth {item.archive_depth} and is not declared by the skill.",
                    file_path=item.path,
                    line_number=self._first_line(item),
                    remediation="Flatten and document required scripts; remove unexpected nested executable content.",
                    analyzer=self.get_name(),
                    metadata={
                        "archive_depth": item.archive_depth,
                        "semantic_facts": self._semantic_facts(
                            files,
                            signals,
                            self._reference_graph(signals),
                            signal_kind="nested_archive_script",
                        ),
                    },
                )
            )
        return findings

    def _manifest_mismatch_finding(self, skill: Skill, signals: dict[str, _FileSignals]) -> Finding | None:
        if not bool(getattr(skill, "manifest_complete", True)):
            return None
        allowed = skill.manifest.allowed_tools
        if not isinstance(allowed, list) or not allowed:
            # The model cannot distinguish an omitted field from an explicit
            # empty list.  Avoid claiming a mismatch without an explicit bound.
            return None
        normalized = [str(tool) for tool in allowed]
        capabilities = {
            "network": any(item.networks for item in signals.values()),
            "execution": any(item.executions for item in signals.values()),
            "sensitive_file_read": any(item.source_lines for item in signals.values()),
        }
        declared = {
            # Agent-skill ``allowed-tools`` enumerates agent tools, not OS
            # capabilities. Bash/shell/terminal already authorize a script to
            # make outbound requests, so reporting those requests as exceeding
            # the manifest is categorically incorrect.
            "network": self._declares(normalized, _NETWORK_TOOL_MARKERS)
            or self._declares(normalized, _NETWORK_UMBRELLA_TOOL_MARKERS),
            "execution": self._declares(normalized, _EXECUTION_TOOL_MARKERS),
            "sensitive_file_read": self._declares(normalized, _FILE_TOOL_MARKERS),
        }
        missing = sorted(name for name, observed in capabilities.items() if observed and not declared[name])
        if not missing:
            return None

        involved = sorted(
            item.path
            for item in signals.values()
            if ("network" in missing and item.networks)
            or ("execution" in missing and item.executions)
            or ("sensitive_file_read" in missing and item.source_lines)
        )
        high_risk = len(missing) > 1 or any(item.flows for item in signals.values())
        severity = Severity.HIGH if high_risk else Severity.MEDIUM
        primary = involved[0]
        semantic = self._semantic_facts(
            involved,
            signals,
            self._reference_graph(signals),
            signal_kind="manifest_capability_mismatch",
        )
        semantic["signals"].extend(
            {
                "rule_id": "CORRELATED_MANIFEST_CAPABILITY_MISMATCH",
                "kind": "undeclared_capability",
                "file_path": primary,
                "value_class": capability,
            }
            for capability in missing
        )
        return Finding(
            id=self._finding_id("CORRELATED_MANIFEST_CAPABILITY_MISMATCH", [*involved, *missing]),
            rule_id="CORRELATED_MANIFEST_CAPABILITY_MISMATCH",
            category=ThreatCategory.UNAUTHORIZED_TOOL_USE,
            severity=severity,
            title="Implementation exceeds declared skill capabilities",
            description=f"Observed capabilities are absent from allowed-tools: {', '.join(missing)}.",
            file_path=primary,
            line_number=self._first_line(signals[primary]),
            remediation="Declare the required tools/capabilities or remove the undeclared behavior.",
            analyzer=self.get_name(),
            metadata={"missing_capabilities": missing, "semantic_facts": semantic},
        )

    def _semantic_facts(
        self,
        files: Iterable[str],
        signals: dict[str, _FileSignals],
        graph: dict[str, set[str]],
        *,
        flow: _Flow | None = None,
        signal_kind: str = "correlated_behavior",
    ) -> dict[str, Any]:
        selected = [signals[path] for path in sorted(set(files)) if path in signals]
        candidate_item = signals.get(flow.sink_path) if flow is not None else None
        if candidate_item is None and selected:
            candidate_item = selected[0]
        commands: list[dict[str, Any]] = []
        urls: list[dict[str, Any]] = []
        facts: list[dict[str, Any]] = []
        for item in selected:
            urls.extend(item.urls)
            for network_event in item.networks:
                commands.append(
                    {
                        "executable": network_event.executable,
                        "argument_classes": [
                            "request_method",
                            *([f"credential_{network_event.credential_use}"] if network_event.credential_use else []),
                            *(
                                [f"destination_{network_event.destination_class}"]
                                if network_event.destination_class
                                else []
                            ),
                        ],
                        "downloads": network_event.downloads,
                        "executes": False,
                        "destructive": False,
                        "privilege_change": False,
                        "source_class": "network" if network_event.downloads else "",
                        "sink_class": "network",
                        "file_path": item.path,
                    }
                )
            for execution_event in item.executions:
                commands.append(
                    {
                        "executable": execution_event.executable,
                        "argument_classes": ["dynamic" if execution_event.dynamic else "literal"],
                        "downloads": False,
                        "executes": True,
                        "destructive": False,
                        "privilege_change": False,
                        "source_class": "",
                        "sink_class": "code_execution",
                        "file_path": item.path,
                    }
                )
            facts.append(
                {
                    "rule_id": "CORRELATION_SIGNAL",
                    "kind": signal_kind,
                    "file_path": item.path,
                    "value_class": self._signal_value_class(item),
                }
            )
            if item.evidence_kind == "fenced_code_flow":
                facts.append(
                    {
                        "rule_id": "CORRELATION_SIGNAL",
                        "kind": "fenced_code_language",
                        "file_path": item.path,
                        "value_class": item.file_type,
                    }
                )
            if item.role_kind:
                facts.append(
                    {
                        "rule_id": "CORRELATION_SIGNAL",
                        "kind": "file_role",
                        "file_path": item.path,
                        "value_class": item.role_kind,
                    }
                )

        edges = [
            {"source_path": source, "target_path": target, "kind": "package_reference"}
            for source in sorted({item.path for item in selected})
            for target in sorted(graph.get(source, set()))
            if target in signals
        ]
        result: dict[str, Any] = {
            "evidence_kind": candidate_item.evidence_kind if candidate_item is not None else "correlated_behavior",
            "context_kind": candidate_item.context_kind if candidate_item is not None else "code",
            "commands": self._dedupe_dicts(commands),
            "urls": self._dedupe_dicts(urls),
            "flows": [flow.fact()] if flow else [],
            "reference_edges": self._dedupe_dicts(edges),
            "signals": facts,
        }
        if flow is not None:
            result["candidate_flow"] = flow.fact()
        return result

    @staticmethod
    def _reference_graph(signals: dict[str, _FileSignals]) -> dict[str, set[str]]:
        graph: dict[str, set[str]] = {path: set() for path in signals}
        for source, item in signals.items():
            for target in item.references:
                if target not in graph or target == source:
                    continue
                graph[source].add(target)
        return graph

    @staticmethod
    def _reference_symbol(reference: str, source_path: str) -> str | None:
        path, separator, symbol = reference.partition("#")
        if path != source_path:
            return None
        return symbol if separator else ""

    @classmethod
    def _consumed_source_classes(
        cls,
        source: _FileSignals,
        references: tuple[str, ...],
        signals: dict[str, _FileSignals],
    ) -> set[str]:
        classes: set[str] = set()
        for path, symbol in cls._walk_reference_symbols(references, signals):
            if path == source.path:
                classes.update(source.source_symbols.get(symbol, set()))
        return classes

    @classmethod
    def _consumes_symbol_behavior(
        cls,
        source_path: str,
        behavior_symbols: set[str],
        references: tuple[str, ...],
        signals: dict[str, _FileSignals],
    ) -> bool:
        return any(
            path == source_path and symbol in behavior_symbols
            for path, symbol in cls._walk_reference_symbols(references, signals)
        )

    @staticmethod
    def _walk_reference_symbols(references: tuple[str, ...], signals: dict[str, _FileSignals]) -> list[tuple[str, str]]:
        """Resolve bounded symbol provenance through ordinary wrapper modules."""
        pending = list(references)
        visited: set[str] = set()
        resolved: list[tuple[str, str]] = []
        while pending and len(visited) < 512:
            reference = pending.pop()
            if reference in visited:
                continue
            visited.add(reference)
            path, _, symbol = reference.partition("#")
            resolved.append((path, symbol))
            item = signals.get(path)
            if item is None:
                continue
            for taint in item.symbol_taints.get(symbol, set()):
                if taint.startswith("reference:"):
                    pending.append(taint.removeprefix("reference:"))
        return resolved

    @staticmethod
    def _directed_reference_path(graph: dict[str, set[str]], start: str, target: str) -> tuple[str, ...] | None:
        if start == target:
            return (start,)
        pending: list[tuple[str, tuple[str, ...]]] = [(start, (start,))]
        visited = {start}
        while pending and len(visited) <= len(graph):
            node, path = pending.pop(0)
            for neighbor in sorted(graph.get(node, set())):
                if neighbor in visited:
                    continue
                next_path = (*path, neighbor)
                if neighbor == target:
                    return next_path
                visited.add(neighbor)
                pending.append((neighbor, next_path))
        return None

    @staticmethod
    def _has_suspicious_url(signals: _FileSignals) -> bool:
        return any(url["domain_class"] == "suspicious" for url in signals.urls)

    @staticmethod
    def _has_untrusted_or_dynamic_url(signals: _FileSignals) -> bool:
        return not signals.urls or any(url["domain_class"] != "legitimate" for url in signals.urls)

    @classmethod
    def _same_file_flow_severity(cls, signals: _FileSignals, flow: _Flow) -> Severity:
        """Grade an exact same-file flow without erasing the candidate.

        Fetch-and-execute remains HIGH unless it is a fenced, documented
        installer whose download source is a fixed HTTPS URL and whose URL
        classifier did not mark it suspicious. That narrow, independently
        declared case remains visible as MEDIUM-risk supply-chain guidance.
        Dynamic, insecure, mismatched, or undeclared providers remain HIGH.
        """

        if (
            flow.source_class == "network"
            and flow.sink_class == "code_execution"
            and signals.evidence_kind == "fenced_code_flow"
            and signals.role_kind == "documented_installer"
            and cls._has_fixed_https_download(signals)
        ):
            return Severity.MEDIUM
        return Severity.HIGH

    @staticmethod
    def _has_fixed_https_download(signals: _FileSignals) -> bool:
        downloads = [event for event in signals.networks if event.downloads]
        if not downloads:
            return False
        for event in downloads:
            if event.credential_use or not event.urls:
                return False
            if event.destination_class not in {"declared_service", "external", "legitimate"}:
                return False
            if any(
                url.get("scheme") != "https" or not url.get("host") or url.get("domain_class") == "suspicious"
                for url in event.urls
            ):
                return False
        return True

    @staticmethod
    def _is_executable(skill_file: SkillFile) -> bool:
        try:
            if skill_file.path.stat().st_mode & 0o111:
                return True
            with skill_file.path.open("rb") as file_handle:
                header = file_handle.read(512)
            return header.startswith(b"#!") or any(header.startswith(prefix) for prefix in _EXECUTABLE_MAGIC_PREFIXES)
        except OSError:
            return False

    @staticmethod
    def _declares(tools: list[str], markers: tuple[str, ...]) -> bool:
        for tool in tools:
            expanded = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", tool)
            tokens = [token for token in re.split(r"[^a-z0-9]+", expanded.lower()) if token]
            for index, token in enumerate(tokens):
                if token not in markers:
                    continue
                previous = tokens[index - 1] if index else ""
                following = tokens[index + 1] if index + 1 < len(tokens) else ""
                if previous in {"deny", "disabled", "no", "without"} or following in {
                    "denied",
                    "disabled",
                    "none",
                }:
                    continue
                return True
        return False

    @classmethod
    def _first_line(cls, item: _FileSignals) -> int | None:
        lines = [
            *item.source_lines.values(),
            *(event.line for event in item.networks),
            *(event.line for event in item.executions),
            *item.obfuscations.values(),
            *item.archive_operations.values(),
        ]
        return cls._physical_line(item, min(lines)) if lines else None

    @staticmethod
    def _physical_line(item: _FileSignals | None, line: int | None) -> int | None:
        if line is None:
            return None
        return line + (item.line_offset if item is not None else 0)

    @staticmethod
    def _signal_value_class(item: _FileSignals) -> str:
        if item.source_lines:
            return "sensitive_source"
        if item.networks:
            return "network"
        if item.executions:
            return "code_execution"
        if item.obfuscations:
            return "obfuscation"
        if item.archive_depth >= 2:
            return "nested_archive"
        return "file"

    @staticmethod
    def _finding_id(rule_id: str, values: Iterable[str]) -> str:
        material = f"{rule_id}:{':'.join(sorted(values))}"
        return f"{rule_id}_{hashlib.sha256(material.encode()).hexdigest()[:12]}"

    @staticmethod
    def _dedupe_dicts(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for value in values:
            marker = repr(sorted(value.items()))
            if marker not in seen:
                seen.add(marker)
                result.append(value)
        return result

    @staticmethod
    def _dedupe_findings(findings: Iterable[Finding]) -> list[Finding]:
        by_id: dict[str, Finding] = {}
        severity_rank = {Severity.HIGH: 2, Severity.MEDIUM: 1}
        for finding in findings:
            previous = by_id.get(finding.id)
            if previous is None or severity_rank.get(finding.severity, 0) > severity_rank.get(previous.severity, 0):
                by_id[finding.id] = finding
        return list(by_id.values())
