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

"""Fail-closed, non-executing adapter for a pinned OpenSkillRisk snapshot.

OpenSkillRisk publishes task specifications as Python source.  Importing those
modules would execute dataset-controlled code, so this adapter instead accepts
only a small, documented AST grammar.  It extracts the three scalar fields
needed for static evaluation and deliberately discards prompts, policies, and
sandbox fixture content.

The adapter has no network, import, compilation, archive, or sample-execution
path.  It scans the local tree only far enough to identify the package
explicitly referenced by each task specification.
"""

from __future__ import annotations

import ast
import os
import re
import stat
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evals.datasets.public_datasets import get_locked_dataset, load_dataset_lock

DATASET_ID = "Miaow-Lab/OpenSkillRisk"

SPLIT_COUNTS = {
    "obviously_malicious": 139,
    "contextually_risky": 124,
}

_SPLIT_SKILL_DIRS = {
    "obviously_malicious": "obviously_malicious_skills",
    "contextually_risky": "contextually_risky_skills",
}
_SPEC_FILE_NAME = {split: f"task_specs_{split}.py" for split in SPLIT_COUNTS}
_TASK_REQUIRED_FIELDS = frozenset({"id", "skill_id", "attack_type", "prompt", "summary"})
_TASK_ALLOWED_FIELDS = _TASK_REQUIRED_FIELDS | frozenset(
    {"safety_policy", "project_files", "home_files", "checks", "collect_paths"}
)
_CHECK_ALLOWED_FIELDS = frozenset({"kind", "path", "patterns", "description"})
_CHECK_REQUIRED_FIELDS = frozenset({"kind"})
_SPEC_UTIL_NAMES = frozenset({"CheckSpec", "TaskSpec", "bash_script", "make_safety_policy", "python_script", "text"})
_TEXT_HELPERS = frozenset({"bash_script", "python_script", "text"})
_SKILL_FILE_NAMES = frozenset({"SKILL.md", "skill.md", "Skill.md"})
_SAFE_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")
_WINDOWS_RESERVED_NAMES = frozenset(
    {
        "aux",
        "clock$",
        "con",
        "nul",
        "prn",
        *(f"com{index}" for index in range(1, 10)),
        *(f"lpt{index}" for index in range(1, 10)),
    }
)
_MAX_SPEC_BYTES = 2 * 1024 * 1024
_MAX_AST_NODES = 100_000
_MAX_AST_DEPTH = 128
_MAX_LITERAL_BYTES = 512 * 1024
_MAX_CONTAINER_ITEMS = 8_192
_MAX_PACKAGE_FILES = 4_096
_MAX_PACKAGE_ENTRIES = 8_192
_MAX_PACKAGE_FILE_BYTES = 32 * 1024 * 1024
_MAX_PACKAGE_BYTES = 128 * 1024 * 1024
_MAX_RELATIVE_PATH_BYTES = 1_024


class OpenSkillRiskError(ValueError):
    """Raised when the supplied snapshot is unsafe or differs from the contract."""


@dataclass(frozen=True)
class OpenSkillRiskTask:
    """Minimal static-evaluation identity extracted from one task specification."""

    task_id: str
    skill_id: str
    attack_type: str
    split: str
    package_directory: Path


@dataclass(frozen=True)
class OpenSkillRiskSnapshot:
    """Validated, pinned OpenSkillRisk task-to-package projection."""

    root: Path
    revision: str
    integrity_hashes_pending: bool
    tasks: tuple[OpenSkillRiskTask, ...]

    def selected(self, split: str | None = None) -> tuple[OpenSkillRiskTask, ...]:
        if split is None:
            return self.tasks
        if split not in SPLIT_COUNTS:
            raise OpenSkillRiskError(f"unknown OpenSkillRisk split: {split!r}")
        return tuple(task for task in self.tasks if task.split == split)


@dataclass(frozen=True)
class _ParsedTask:
    task_id: str
    skill_id: str
    attack_type: str


def _read_regular_source(path: Path) -> str:
    if path.is_symlink():
        raise OpenSkillRiskError(f"task specification must not be a symbolic link: {path.name}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise OpenSkillRiskError(f"cannot safely open task specification {path.name}: {exc}") from exc
    try:
        source_stat = os.fstat(descriptor)
        if not stat.S_ISREG(source_stat.st_mode):
            raise OpenSkillRiskError(f"task specification is not a regular file: {path.name}")
        if source_stat.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise OpenSkillRiskError(f"task specification must not be executable: {path.name}")
        if source_stat.st_size > _MAX_SPEC_BYTES:
            raise OpenSkillRiskError(f"task specification exceeds {_MAX_SPEC_BYTES} bytes: {path.name}")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            raw = handle.read(_MAX_SPEC_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) > _MAX_SPEC_BYTES:
        raise OpenSkillRiskError(f"task specification exceeds {_MAX_SPEC_BYTES} bytes: {path.name}")
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OpenSkillRiskError(f"task specification is not UTF-8: {path.name}") from exc
    if "\x00" in source:
        raise OpenSkillRiskError(f"task specification contains NUL bytes: {path.name}")
    return source


def _parse_tree(source: str, path: Path) -> ast.Module:
    try:
        tree = ast.parse(source, filename=path.name, mode="exec", type_comments=False)
    except (SyntaxError, ValueError, MemoryError, RecursionError) as exc:
        raise OpenSkillRiskError(f"invalid task specification syntax in {path.name}: {exc}") from exc

    node_count = 0
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        node_count += 1
        if node_count > _MAX_AST_NODES:
            raise OpenSkillRiskError(f"task specification exceeds {_MAX_AST_NODES} AST nodes: {path.name}")
        if depth > _MAX_AST_DEPTH:
            raise OpenSkillRiskError(f"task specification AST exceeds depth {_MAX_AST_DEPTH}: {path.name}")
        stack.extend((child, depth + 1) for child in ast.iter_child_nodes(node))
    return tree


def _literal_string(
    node: ast.AST,
    location: str,
    *,
    identifier: bool = False,
    allow_empty: bool = False,
    max_bytes: int = _MAX_LITERAL_BYTES,
) -> str:
    if not isinstance(node, ast.Constant) or not isinstance(node.value, str) or (not node.value and not allow_empty):
        requirement = "string literal" if allow_empty else "non-empty string literal"
        raise OpenSkillRiskError(f"{location} must be a {requirement}")
    value = node.value
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise OpenSkillRiskError(f"{location} must be valid UTF-8") from exc
    if "\x00" in value or len(encoded) > max_bytes:
        raise OpenSkillRiskError(f"{location} is NUL-containing or exceeds the literal byte limit")
    if identifier:
        basename = value.split(".", 1)[0].casefold()
        if (
            not _SAFE_IDENTIFIER_RE.fullmatch(value)
            or basename in _WINDOWS_RESERVED_NAMES
            or value.endswith((" ", "."))
        ):
            raise OpenSkillRiskError(f"{location} must be a portable single-component identifier")
    return value


def _call_name(node: ast.Call, location: str) -> str:
    if not isinstance(node.func, ast.Name) or node.func.id not in _SPEC_UTIL_NAMES:
        raise OpenSkillRiskError(f"{location} calls a function outside the literal-only whitelist")
    return node.func.id


def _keywords(node: ast.Call, location: str) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for keyword in node.keywords:
        if keyword.arg is None:
            raise OpenSkillRiskError(f"{location} may not use **kwargs")
        if keyword.arg in result:
            raise OpenSkillRiskError(f"{location} contains duplicate keyword {keyword.arg!r}")
        result[keyword.arg] = keyword.value
    return result


def _named_value(node: ast.AST, location: str, names: dict[str, ast.AST]) -> ast.AST:
    if not isinstance(node, ast.Name):
        return node
    if node.id not in names:
        raise OpenSkillRiskError(f"{location} references unknown literal name {node.id!r}")
    return names[node.id]


def _validate_string_value(
    node: ast.AST,
    location: str,
    names: dict[str, ast.AST],
    *,
    allowed_helpers: frozenset[str] = _TEXT_HELPERS,
    allow_empty: bool = False,
) -> None:
    node = _named_value(node, location, names)
    if isinstance(node, ast.Constant):
        _literal_string(node, location, allow_empty=allow_empty)
        return
    if not isinstance(node, ast.Call):
        raise OpenSkillRiskError(f"{location} must be a bounded literal string expression")
    name = _call_name(node, location)
    if name not in allowed_helpers:
        raise OpenSkillRiskError(f"{location} uses helper {name!r} outside its field schema")
    if name in _TEXT_HELPERS:
        if len(node.args) != 1 or node.keywords:
            raise OpenSkillRiskError(f"{location}.{name} requires exactly one literal positional argument")
        _literal_string(node.args[0], f"{location}.{name}", allow_empty=allow_empty)
        return
    _validate_safety_policy_call(node, location, names)


def _validate_string_list(node: ast.AST, location: str, names: dict[str, ast.AST]) -> None:
    node = _named_value(node, location, names)
    if not isinstance(node, (ast.List, ast.Tuple)):
        raise OpenSkillRiskError(f"{location} must be a literal string list")
    if len(node.elts) > _MAX_CONTAINER_ITEMS:
        raise OpenSkillRiskError(f"{location} exceeds the container item limit")
    for index, value in enumerate(node.elts):
        _validate_string_value(value, f"{location}[{index}]", names)


def _validate_string_dict(node: ast.AST, location: str, names: dict[str, ast.AST]) -> None:
    node = _named_value(node, location, names)
    if not isinstance(node, ast.Dict):
        raise OpenSkillRiskError(f"{location} must be a literal string-to-string dictionary")
    if len(node.keys) > _MAX_CONTAINER_ITEMS:
        raise OpenSkillRiskError(f"{location} exceeds the container item limit")
    seen_keys: set[str] = set()
    for index, (key_node, value_node) in enumerate(zip(node.keys, node.values, strict=True)):
        if key_node is None:
            raise OpenSkillRiskError(f"{location} may not use dictionary unpacking")
        key = _literal_string(key_node, f"{location}.key[{index}]")
        if key in seen_keys:
            raise OpenSkillRiskError(f"{location} contains duplicate dictionary key {key!r}")
        seen_keys.add(key)
        _validate_string_value(value_node, f"{location}[{key!r}]", names, allow_empty=True)


def _validate_safety_policy_call(node: ast.Call, location: str, names: dict[str, ast.AST]) -> None:
    if _call_name(node, location) != "make_safety_policy":  # pragma: no cover - caller contract
        raise OpenSkillRiskError(f"{location} is not a safety-policy literal helper")
    if node.args and node.keywords:
        raise OpenSkillRiskError(f"{location}.make_safety_policy may not mix positional and keyword arguments")
    scope: ast.AST
    prohibited_actions: ast.AST
    fallback: ast.AST
    if node.args:
        if len(node.args) != 3:
            raise OpenSkillRiskError(f"{location}.make_safety_policy requires three arguments")
        scope, prohibited_actions, fallback = node.args
    else:
        fields = _keywords(node, f"{location}.make_safety_policy")
        if set(fields) != {"scope", "prohibited_actions", "fallback"}:
            raise OpenSkillRiskError(f"{location}.make_safety_policy schema drift")
        scope = fields["scope"]
        prohibited_actions = fields["prohibited_actions"]
        fallback = fields["fallback"]
    _validate_string_value(scope, f"{location}.make_safety_policy.scope", names)
    _validate_string_list(prohibited_actions, f"{location}.make_safety_policy.prohibited_actions", names)
    _validate_string_value(fallback, f"{location}.make_safety_policy.fallback", names)


def _validate_check_call(node: ast.AST, location: str, names: dict[str, ast.AST]) -> None:
    node = _named_value(node, location, names)
    if not isinstance(node, ast.Call) or _call_name(node, location) != "CheckSpec":
        raise OpenSkillRiskError(f"{location} must be a CheckSpec literal")
    if node.args:
        raise OpenSkillRiskError(f"{location}.CheckSpec must use keyword arguments")
    fields = _keywords(node, f"{location}.CheckSpec")
    missing = _CHECK_REQUIRED_FIELDS - set(fields)
    unexpected = set(fields) - _CHECK_ALLOWED_FIELDS
    if missing or unexpected:
        raise OpenSkillRiskError(
            f"{location}.CheckSpec schema drift (missing={sorted(missing)}, unexpected={sorted(unexpected)})"
        )
    _validate_string_value(fields["kind"], f"{location}.CheckSpec.kind", names)
    if "path" in fields:
        path_value = _named_value(fields["path"], f"{location}.CheckSpec.path", names)
        if not (isinstance(path_value, ast.Constant) and path_value.value is None):
            _validate_string_value(path_value, f"{location}.CheckSpec.path", names)
    if "patterns" in fields:
        _validate_string_list(fields["patterns"], f"{location}.CheckSpec.patterns", names)
    if "description" in fields:
        _validate_string_value(
            fields["description"],
            f"{location}.CheckSpec.description",
            names,
            allow_empty=True,
        )


def _validate_check_list(node: ast.AST, location: str, names: dict[str, ast.AST]) -> None:
    node = _named_value(node, location, names)
    if not isinstance(node, (ast.List, ast.Tuple)):
        raise OpenSkillRiskError(f"{location} must be a literal CheckSpec list")
    if len(node.elts) > _MAX_CONTAINER_ITEMS:
        raise OpenSkillRiskError(f"{location} exceeds the container item limit")
    for index, value in enumerate(node.elts):
        _validate_check_call(value, f"{location}[{index}]", names)


def _validate_literal_value(node: ast.AST, location: str, names: dict[str, ast.AST]) -> None:
    """Validate a value without evaluating, compiling, or retaining its content."""

    if isinstance(node, ast.Constant):
        if node.value is None:
            return
        if not isinstance(node.value, str):
            raise OpenSkillRiskError(f"{location} contains a non-string literal")
        _literal_string(node, location, allow_empty=True)
        return
    if isinstance(node, ast.Name):
        if node.id not in names:
            raise OpenSkillRiskError(f"{location} references unknown literal name {node.id!r}")
        _validate_literal_value(names[node.id], location, {})
        return
    if isinstance(node, (ast.List, ast.Tuple)):
        if len(node.elts) > _MAX_CONTAINER_ITEMS:
            raise OpenSkillRiskError(f"{location} exceeds the container item limit")
        for index, item in enumerate(node.elts):
            _validate_literal_value(item, f"{location}[{index}]", names)
        return
    if isinstance(node, ast.Dict):
        if len(node.keys) > _MAX_CONTAINER_ITEMS:
            raise OpenSkillRiskError(f"{location} exceeds the container item limit")
        seen_keys: set[str] = set()
        for index, (key_node, value_node) in enumerate(zip(node.keys, node.values, strict=True)):
            if key_node is None:
                raise OpenSkillRiskError(f"{location} may not use dictionary unpacking")
            key = _literal_string(key_node, f"{location}.key[{index}]")
            if key in seen_keys:
                raise OpenSkillRiskError(f"{location} contains duplicate dictionary key {key!r}")
            seen_keys.add(key)
            _validate_literal_value(value_node, f"{location}[{key!r}]", names)
        return
    if not isinstance(node, ast.Call):
        raise OpenSkillRiskError(f"{location} contains unexpected AST node {type(node).__name__}")

    name = _call_name(node, location)
    if name == "TaskSpec":
        raise OpenSkillRiskError(f"{location} may not nest TaskSpec")
    if name in _TEXT_HELPERS:
        if len(node.args) != 1 or node.keywords:
            raise OpenSkillRiskError(f"{location}.{name} requires exactly one literal positional argument")
        _literal_string(node.args[0], f"{location}.{name}", allow_empty=True)
        return
    if name == "make_safety_policy":
        _validate_safety_policy_call(node, location, names)
        return
    if name == "CheckSpec":
        _validate_check_call(node, location, names)
        return
    raise OpenSkillRiskError(f"{location} contains an unsupported literal helper {name!r}")


def _validate_task_call(node: ast.AST, location: str, names: dict[str, ast.AST]) -> _ParsedTask:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id != "TaskSpec":
        raise OpenSkillRiskError(f"{location} must contain only TaskSpec(...) calls")
    if node.args:
        raise OpenSkillRiskError(f"{location} TaskSpec must use keyword arguments")
    fields = _keywords(node, f"{location}.TaskSpec")
    missing = _TASK_REQUIRED_FIELDS - set(fields)
    unexpected = set(fields) - _TASK_ALLOWED_FIELDS
    if missing or unexpected:
        raise OpenSkillRiskError(
            f"{location}.TaskSpec schema drift (missing={sorted(missing)}, unexpected={sorted(unexpected)})"
        )

    task_id = _literal_string(fields["id"], f"{location}.TaskSpec.id", identifier=True)
    skill_id = _literal_string(fields["skill_id"], f"{location}.TaskSpec.skill_id", identifier=True)
    attack_type = _literal_string(fields["attack_type"], f"{location}.TaskSpec.attack_type", max_bytes=256)
    if attack_type != attack_type.strip() or any(
        ord(character) < 32 or ord(character) == 127 for character in attack_type
    ):
        raise OpenSkillRiskError(f"{location}.TaskSpec.attack_type must be normalized single-line text")
    for field in ("prompt", "summary"):
        _validate_string_value(fields[field], f"{location}.TaskSpec.{field}", names)
    if "safety_policy" in fields:
        _validate_string_value(
            fields["safety_policy"],
            f"{location}.TaskSpec.safety_policy",
            names,
            allowed_helpers=_TEXT_HELPERS | frozenset({"make_safety_policy"}),
            allow_empty=True,
        )
    for field in ("project_files", "home_files"):
        if field in fields:
            _validate_string_dict(fields[field], f"{location}.TaskSpec.{field}", names)
    if "checks" in fields:
        _validate_check_list(fields["checks"], f"{location}.TaskSpec.checks", names)
    if "collect_paths" in fields:
        _validate_string_list(fields["collect_paths"], f"{location}.TaskSpec.collect_paths", names)
    return _ParsedTask(task_id=task_id, skill_id=skill_id, attack_type=attack_type)


def _validate_import(node: ast.ImportFrom, location: str) -> None:
    if node.module == "__future__" and node.level == 0:
        allowed = {"annotations"}
    elif node.module == "pathlib" and node.level == 0:
        allowed = {"Path"}
    elif (node.module == "src.spec_utils" and node.level == 0) or (
        node.module == "spec_utils" and node.level in {0, 1}
    ):
        allowed = set(_SPEC_UTIL_NAMES)
    else:
        raise OpenSkillRiskError(f"{location} imports an unexpected module")
    imported: set[str] = set()
    for alias in node.names:
        if alias.asname is not None or alias.name not in allowed or alias.name in imported:
            raise OpenSkillRiskError(f"{location} contains an unexpected or aliased import")
        imported.add(alias.name)


def _validate_annotation(node: ast.AST | None, location: str) -> None:
    if node is None:
        return
    if isinstance(node, ast.Name) and node.id in {"list", "TaskSpec"}:
        return
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id == "list":
        _validate_annotation(node.slice, location)
        return
    raise OpenSkillRiskError(f"{location} contains an unexpected type annotation")


def _validate_filtered_skills_expression(node: ast.AST, expected_directory: str, location: str) -> None:
    """Accept only a static ``Path(__file__)`` chain ending in the locked split."""

    string_parts: list[str] = []

    def visit(value: ast.AST) -> None:
        if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
            visit(value.left)
            part = _literal_string(value.right, location)
            if "/" in part or "\\" in part or part in {".", ".."}:
                raise OpenSkillRiskError(f"{location} contains an unsafe path component")
            string_parts.append(part)
            return
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "Path"
            and len(value.args) == 1
            and not value.keywords
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id == "__file__"
        ):
            return
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "resolve"
            and not value.args
            and not value.keywords
        ):
            visit(value.func.value)
            return
        if isinstance(value, ast.Attribute) and value.attr == "parent":
            visit(value.value)
            return
        if (
            isinstance(value, ast.Subscript)
            and isinstance(value.value, ast.Attribute)
            and value.value.attr == "parents"
            and isinstance(value.slice, ast.Constant)
            and isinstance(value.slice.value, int)
            and not isinstance(value.slice.value, bool)
            and 0 <= value.slice.value <= 8
        ):
            visit(value.value.value)
            return
        raise OpenSkillRiskError(f"{location} must be a static Path(__file__) expression")

    visit(node)
    if string_parts != ["skills", expected_directory]:
        raise OpenSkillRiskError(f"{location} does not end in skills/{expected_directory}")


def _task_nodes_from_container(node: ast.AST, location: str, names: dict[str, ast.AST]) -> list[ast.AST]:
    if isinstance(node, ast.Name):
        if node.id not in names:
            raise OpenSkillRiskError(f"{location} returns unknown task list {node.id!r}")
        node = names[node.id]
    if not isinstance(node, (ast.List, ast.Tuple)):
        raise OpenSkillRiskError(f"{location} must return a list or tuple of TaskSpec calls")
    if len(node.elts) > _MAX_CONTAINER_ITEMS:
        raise OpenSkillRiskError(f"{location} exceeds the task count limit")
    return list(node.elts)


def parse_task_spec_source(source: str, *, path: Path, split: str) -> tuple[_ParsedTask, ...]:
    """Parse one source string under the closed task-specification AST grammar."""

    if split not in SPLIT_COUNTS:
        raise OpenSkillRiskError(f"unknown OpenSkillRisk split: {split!r}")
    if not isinstance(source, str):
        raise OpenSkillRiskError("task specification source must be text")
    try:
        source_size = len(source.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise OpenSkillRiskError("task specification source must be valid UTF-8") from exc
    if "\x00" in source or source_size > _MAX_SPEC_BYTES:
        raise OpenSkillRiskError("task specification source is NUL-containing or exceeds the byte limit")
    tree = _parse_tree(source, path)
    literal_names: dict[str, ast.AST] = {}
    task_list_names: set[str] = set()
    filtered_seen = False
    get_specs: ast.FunctionDef | None = None

    for index, statement in enumerate(tree.body):
        location = f"{path.name}:statement[{index}]"
        if isinstance(statement, ast.Expr):
            if (
                index != 0
                or not isinstance(statement.value, ast.Constant)
                or not isinstance(statement.value.value, str)
            ):
                raise OpenSkillRiskError(f"{location} contains an unexpected expression")
            continue
        if isinstance(statement, ast.ImportFrom):
            _validate_import(statement, location)
            continue
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                raise OpenSkillRiskError(f"{location} must assign one simple name")
            name = statement.targets[0].id
            value = statement.value
        elif isinstance(statement, ast.AnnAssign):
            if not isinstance(statement.target, ast.Name) or statement.value is None or statement.simple != 1:
                raise OpenSkillRiskError(f"{location} must assign one simple annotated name")
            _validate_annotation(statement.annotation, location)
            name = statement.target.id
            value = statement.value
        elif isinstance(statement, ast.FunctionDef):
            if statement.name != "get_specs" or get_specs is not None:
                raise OpenSkillRiskError(f"{location} contains an unexpected function")
            get_specs = statement
            continue
        else:
            raise OpenSkillRiskError(f"{location} contains unexpected top-level node {type(statement).__name__}")

        if name == "FILTERED_SKILLS_DIR":
            if filtered_seen:
                raise OpenSkillRiskError(f"{location} redefines FILTERED_SKILLS_DIR")
            _validate_filtered_skills_expression(value, _SPLIT_SKILL_DIRS[split], location)
            filtered_seen = True
            continue
        if name in literal_names or not re.fullmatch(r"[A-Z][A-Z0-9_]*", name):
            raise OpenSkillRiskError(f"{location} assigns an unexpected or duplicate name {name!r}")
        # Task lists are validated after get_specs resolves their identity. Other
        # constants must still be safe literal-only expressions.
        if isinstance(value, (ast.List, ast.Tuple)) and all(
            isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id == "TaskSpec"
            for item in value.elts
        ):
            literal_names[name] = value
            task_list_names.add(name)
        else:
            _validate_literal_value(value, location, literal_names)
            literal_names[name] = value

    if not filtered_seen:
        raise OpenSkillRiskError(f"{path.name} is missing FILTERED_SKILLS_DIR")
    if get_specs is None:
        raise OpenSkillRiskError(f"{path.name} is missing get_specs()")
    if get_specs.decorator_list or get_specs.args.posonlyargs or get_specs.args.args or get_specs.args.kwonlyargs:
        raise OpenSkillRiskError(f"{path.name}.get_specs must be undecorated and take no arguments")
    type_params = getattr(get_specs, "type_params", None)
    if get_specs.args.vararg or get_specs.args.kwarg or type_params:
        raise OpenSkillRiskError(f"{path.name}.get_specs has an unsupported signature")
    _validate_annotation(get_specs.returns, f"{path.name}.get_specs")
    body = list(get_specs.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body.pop(0)
    if len(body) != 1 or not isinstance(body[0], ast.Return) or body[0].value is None:
        raise OpenSkillRiskError(f"{path.name}.get_specs must contain exactly one literal return")
    returned_name = body[0].value.id if isinstance(body[0].value, ast.Name) else None
    if task_list_names != ({returned_name} if returned_name is not None else set()):
        raise OpenSkillRiskError(f"{path.name} contains an unreturned or ambiguous TaskSpec list")
    task_nodes = _task_nodes_from_container(body[0].value, f"{path.name}.get_specs", literal_names)
    parsed = tuple(
        _validate_task_call(node, f"{path.name}.get_specs[{index}]", literal_names)
        for index, node in enumerate(task_nodes)
    )
    expected = SPLIT_COUNTS[split]
    if len(parsed) != expected:
        raise OpenSkillRiskError(f"{split} task-count drift (expected {expected}, received {len(parsed)})")
    task_ids = [task.task_id for task in parsed]
    skill_ids = [task.skill_id for task in parsed]
    if len(task_ids) != len(set(task_ids)) or len(task_ids) != len({value.casefold() for value in task_ids}):
        raise OpenSkillRiskError(f"{split} contains duplicate task identifiers")
    if len(skill_ids) != len(set(skill_ids)) or len(skill_ids) != len({value.casefold() for value in skill_ids}):
        raise OpenSkillRiskError(f"{split} contains duplicate skill identifiers")
    return parsed


def _resolve_one(root: Path, candidates: tuple[Path, ...], location: str) -> Path:
    matches: list[Path] = []
    for relative in candidates:
        candidate = root / relative
        try:
            candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise OpenSkillRiskError(f"cannot safely inspect {location}: {exc}") from exc
        if candidate.is_symlink():
            raise OpenSkillRiskError(f"{location} must not be a symbolic link: {relative.as_posix()}")
        matches.append(candidate)
    if len(matches) != 1:
        raise OpenSkillRiskError(f"{location} must resolve to exactly one approved snapshot path")
    return matches[0]


def _spec_path(root: Path, split: str) -> Path:
    name = _SPEC_FILE_NAME[split]
    return _resolve_one(
        root,
        (Path("src") / name, Path("tasks") / name, Path(name)),
        f"{split} task specification",
    )


def _skills_root(root: Path, split: str) -> Path:
    name = _SPLIT_SKILL_DIRS[split]
    path = _resolve_one(root, (Path("skills") / name, Path(name)), f"{split} skills root")
    if not path.is_dir():
        raise OpenSkillRiskError(f"{split} skills root must be a directory")
    return path


def _validate_tree_and_find_skill(skill_root: Path, snapshot_root: Path) -> Path:
    if skill_root.is_symlink() or not skill_root.is_dir():
        raise OpenSkillRiskError(f"referenced skill root is not a safe directory: {skill_root.name}")
    skill_files: list[Path] = []
    total_files = 0
    total_entries = 0
    total_bytes = 0

    def fail_walk(error: OSError) -> None:
        raise OpenSkillRiskError(f"cannot safely walk referenced package: {error}") from error

    for current_root, directory_names, file_names in os.walk(skill_root, followlinks=False, onerror=fail_walk):
        current = Path(current_root)
        names = [*directory_names, *file_names]
        normalized_names = [unicodedata.normalize("NFC", name).casefold() for name in names]
        if len(normalized_names) != len(set(normalized_names)):
            raise OpenSkillRiskError("referenced package contains a case-folding or Unicode path collision")
        for name in names:
            member = current / name
            member_stat = member.lstat()
            total_entries += 1
            if total_entries > _MAX_PACKAGE_ENTRIES:
                raise OpenSkillRiskError("referenced package exceeds the entry-count limit")
            try:
                relative = member.relative_to(snapshot_root)
            except ValueError as exc:  # pragma: no cover - os.walk confinement guard
                raise OpenSkillRiskError("referenced skill member escaped the snapshot") from exc
            label = relative.as_posix()
            try:
                encoded_label = label.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise OpenSkillRiskError("referenced package path must be valid UTF-8") from exc
            if len(encoded_label) > _MAX_RELATIVE_PATH_BYTES:
                raise OpenSkillRiskError("referenced package contains an overlong relative path")
            for component in relative.parts:
                encoded_component = component.encode("utf-8")
                basename = component.split(".", 1)[0].casefold()
                if (
                    not component
                    or len(encoded_component) > 255
                    or any(ord(character) < 32 or ord(character) == 127 for character in component)
                    or "\\" in component
                    or ":" in component
                    or component.endswith((" ", "."))
                    or basename in _WINDOWS_RESERVED_NAMES
                ):
                    raise OpenSkillRiskError(f"referenced package contains a non-portable path: {label}")
            if stat.S_ISLNK(member_stat.st_mode):
                raise OpenSkillRiskError(f"referenced package contains a symbolic link: {label}")
            if name in directory_names and not stat.S_ISDIR(member_stat.st_mode):
                raise OpenSkillRiskError(f"referenced package contains a non-directory entry: {label}")
            if name in file_names and not stat.S_ISREG(member_stat.st_mode):
                raise OpenSkillRiskError(f"referenced package contains a non-regular file: {label}")
        for name in file_names:
            member = current / name
            member_stat = member.stat(follow_symlinks=False)
            if not stat.S_ISREG(member_stat.st_mode):
                raise OpenSkillRiskError("referenced package member changed type during validation")
            if member_stat.st_size > _MAX_PACKAGE_FILE_BYTES:
                raise OpenSkillRiskError("referenced package contains an oversized file")
            total_files += 1
            total_bytes += member_stat.st_size
            if total_files > _MAX_PACKAGE_FILES or total_bytes > _MAX_PACKAGE_BYTES:
                raise OpenSkillRiskError("referenced package exceeds bounded file or byte limits")
            if name in _SKILL_FILE_NAMES:
                skill_files.append(member)
    if len(skill_files) != 1:
        raise OpenSkillRiskError(
            f"referenced skill {skill_root.name!r} must contain exactly one supported SKILL.md document"
        )
    package = skill_files[0].parent
    try:
        package.relative_to(skill_root)
        package.relative_to(snapshot_root)
    except ValueError as exc:  # pragma: no cover - defense in depth
        raise OpenSkillRiskError("resolved package escaped its referenced skill root") from exc
    return package


def _resolve_package(skills_root: Path, skill_id: str, snapshot_root: Path) -> Path:
    if (
        not _SAFE_IDENTIFIER_RE.fullmatch(skill_id)
        or skill_id.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_NAMES
        or skill_id.endswith((" ", "."))
    ):
        raise OpenSkillRiskError("skill_id must be a portable single-component identifier")
    skill_root = skills_root / skill_id
    try:
        skill_root.lstat()
    except FileNotFoundError as exc:
        raise OpenSkillRiskError(f"referenced skill directory is missing: {skill_id}") from exc
    except OSError as exc:
        raise OpenSkillRiskError(f"cannot safely inspect referenced skill directory {skill_id}: {exc}") from exc
    return _validate_tree_and_find_skill(skill_root, snapshot_root)


def _validate_dataset_contract(dataset: Mapping[str, Any]) -> None:
    expected = dataset.get("expected")
    if not isinstance(expected, Mapping):
        raise OpenSkillRiskError("dataset lock is missing the OpenSkillRisk expected-data contract")
    locked_counts = expected.get("row_counts")
    required_counts = {f"tasks/{split}": count for split, count in SPLIT_COUNTS.items()}
    if locked_counts != required_counts:
        raise OpenSkillRiskError("dataset lock OpenSkillRisk task-count contract drift")
    schemas = expected.get("schemas")
    if not isinstance(schemas, Mapping) or set(schemas) != {"task_spec"}:
        raise OpenSkillRiskError("dataset lock OpenSkillRisk task schema is missing or ambiguous")
    task_schema = schemas["task_spec"]
    if not isinstance(task_schema, Mapping) or set(task_schema) != {"exact_fields"}:
        raise OpenSkillRiskError("dataset lock OpenSkillRisk task schema drift")
    exact_fields = task_schema["exact_fields"]
    if not isinstance(exact_fields, list) or set(exact_fields) != _TASK_ALLOWED_FIELDS:
        raise OpenSkillRiskError("dataset lock OpenSkillRisk task fields drift")
    if (
        dataset.get("access") != "gated_manual"
        or dataset.get("download_policy") != "manual_authorized_environment_only"
    ):
        raise OpenSkillRiskError("dataset lock OpenSkillRisk access policy drift")
    if set(dataset.get("approved_uses", ())) != {"supplemental_positive_recall"}:
        raise OpenSkillRiskError("dataset lock OpenSkillRisk approved-use policy drift")
    if "negative_precision_denominator" not in dataset["prohibited_uses"]:
        raise OpenSkillRiskError("dataset lock no longer excludes OpenSkillRisk from negative precision metrics")
    integrity = dataset.get("integrity")
    if (
        not isinstance(integrity, Mapping)
        or integrity.get("hashes_pending") is not True
        or integrity.get("artifact_manifest_sha256") is not None
    ):
        raise OpenSkillRiskError(
            "OpenSkillRisk artifact identity changed; add manifest verification before accepting the new lock"
        )


def load_openskillrisk_snapshot(
    root: Path,
    *,
    revision: str,
    dataset_lock: Path | None = None,
) -> OpenSkillRiskSnapshot:
    """Validate a pinned local snapshot and resolve only task-referenced packages."""

    supplied_root = Path(root)
    if supplied_root.is_symlink():
        raise OpenSkillRiskError("snapshot root must not be a symbolic link")
    try:
        root = supplied_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise OpenSkillRiskError(f"snapshot root is unavailable: {exc}") from exc
    if not root.is_dir():
        raise OpenSkillRiskError("snapshot root must be a directory")

    manifest = load_dataset_lock(dataset_lock) if dataset_lock is not None else load_dataset_lock()
    dataset = get_locked_dataset(DATASET_ID, manifest)
    _validate_dataset_contract(dataset)
    if revision != dataset["revision"] or revision != dataset["integrity"]["repository_commit"]:
        raise OpenSkillRiskError(f"snapshot revision drift (expected {dataset['revision']}, received {revision})")
    if dataset["gating"]["blocking"]:
        raise OpenSkillRiskError("OpenSkillRisk must remain a non-blocking supplemental dataset")
    if "execute_samples" not in dataset["prohibited_uses"]:
        raise OpenSkillRiskError("dataset lock no longer prohibits sample execution")

    tasks: list[OpenSkillRiskTask] = []
    all_task_ids: set[str] = set()
    all_skill_ids: set[str] = set()
    all_task_ids_casefolded: set[str] = set()
    all_skill_ids_casefolded: set[str] = set()
    for split in SPLIT_COUNTS:
        source_path = _spec_path(root, split)
        parsed = parse_task_spec_source(_read_regular_source(source_path), path=source_path, split=split)
        skills_root = _skills_root(root, split)
        for task in parsed:
            if task.task_id in all_task_ids or task.task_id.casefold() in all_task_ids_casefolded:
                raise OpenSkillRiskError(f"duplicate task identifier across splits: {task.task_id}")
            if task.skill_id in all_skill_ids or task.skill_id.casefold() in all_skill_ids_casefolded:
                raise OpenSkillRiskError(f"duplicate skill identifier across splits: {task.skill_id}")
            all_task_ids.add(task.task_id)
            all_skill_ids.add(task.skill_id)
            all_task_ids_casefolded.add(task.task_id.casefold())
            all_skill_ids_casefolded.add(task.skill_id.casefold())
            tasks.append(
                OpenSkillRiskTask(
                    task_id=task.task_id,
                    skill_id=task.skill_id,
                    attack_type=task.attack_type,
                    split=split,
                    package_directory=_resolve_package(skills_root, task.skill_id, root),
                )
            )

    return OpenSkillRiskSnapshot(
        root=root,
        revision=revision,
        integrity_hashes_pending=bool(dataset["integrity"]["hashes_pending"]),
        tasks=tuple(tasks),
    )


def revalidate_referenced_package(snapshot: OpenSkillRiskSnapshot, task: OpenSkillRiskTask) -> Path:
    """Recheck containment and non-symlink state immediately before static scanning."""

    if snapshot.root.is_symlink() or not snapshot.root.is_dir():
        raise OpenSkillRiskError("snapshot root changed after validation")
    if task not in snapshot.tasks:
        raise OpenSkillRiskError("task is not a member of the validated snapshot")
    split_root = _skills_root(snapshot.root, task.split)
    resolved = _resolve_package(split_root, task.skill_id, snapshot.root)
    if resolved != task.package_directory:
        raise OpenSkillRiskError(f"referenced package path changed after snapshot validation: {task.task_id}")
    return resolved
