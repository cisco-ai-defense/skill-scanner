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

"""The packing ladder: how a skill becomes a bounded System One request.

Sizes measured on the corpora decide the shape here.  MaliciousSkillBench rows
average 2,936 bytes and ClawHub rows 24,173, so the benchmark corpora almost
always fit whole.  Real-world skills do not: over 119 of them the median
scanner-relevant payload is 576,745 bytes across 80 files, and only 19% fit in a
32k-token window.  ``SKILL.md`` is the exception that makes chunking tractable,
at a 6,684-byte median with 96% under 24 KB, and it is also the instruction
surface where prompt injection lives.

Hence three tiers, tried in order:

``A`` whole record, when everything fits.
``B`` priority-ordered, filling ``SKILL.md`` first, then referenced scripts, then
      remaining code ordered by Magika type rather than extension, then
      documentation markdown truncated hardest.
``C`` candidate-centric, one request per finding, as the floor for the long tail.

Which tier a package lands in is recorded on every request, because a result
whose packing tier is unknown cannot be compared with another arm.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from evals.system_one.state import (
    bound_value,
    estimated_tokens,
    neutralize,
    relevance_score,
    safe_identifier,
)

CONFIG_PATH = Path(__file__).with_name("contexts-skill-v1.json")

# Extensions the scanner itself treats as inert or archived. Excluded from the
# payload because they are never the decision and they dominate real skills by
# bytes: the corpus is mostly PNG, TTF, GIF, MP4 and JAR.
SKIPPED_EXTENSIONS = frozenset(
    {
        ".bmp",
        ".db",
        ".eot",
        ".gif",
        ".ico",
        ".jpeg",
        ".jpg",
        ".otf",
        ".png",
        ".pyc",
        ".pyo",
        ".sqlite",
        ".sqlite3",
        ".tiff",
        ".ttf",
        ".webp",
        ".woff",
        ".woff2",
        ".7z",
        ".apk",
        ".bz2",
        ".docx",
        ".gz",
        ".jar",
        ".odp",
        ".ods",
        ".odt",
        ".pptx",
        ".rar",
        ".tar",
        ".tgz",
        ".war",
        ".xlsx",
        ".xz",
        ".zip",
        ".mp4",
        ".mp3",
        ".mov",
    }
)

SKIPPED_DIRECTORIES = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target", ".mypy_cache"}
)

# Mirrors the scanner's own per-file ceiling.
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES = 100


class PackingTier(str, Enum):
    """Which rung of the ladder produced a request."""

    WHOLE = "A"
    PRIORITIZED = "B"
    CANDIDATE = "C"
    OVERSIZE = "oversize"


class FileRole(str, Enum):
    """What a file is for, which drives packing priority."""

    SKILL_MD = "skill_md"
    REFERENCED_SCRIPT = "referenced_script"
    CODE = "code"
    DOCUMENTATION = "documentation"
    ASSET = "asset"


@dataclass(frozen=True)
class PackedFile:
    """One file selected for inclusion, with why it was ranked where it was."""

    relative_path: str
    role: FileRole
    magika_type: str
    byte_size: int
    text: str
    truncated: bool


@dataclass
class PackedRequest:
    """The bounded payload plus the accounting needed to interpret it."""

    tier: PackingTier
    files: list[PackedFile] = field(default_factory=list)
    context_bytes: int = 0
    truncated: bool = False
    dropped_fields: list[str] = field(default_factory=list)
    omitted_files: int = 0
    oversize_reason: str | None = None

    @property
    def is_sendable(self) -> bool:
        """An oversize request must never be sent; it would be answered blind."""
        return self.tier is not PackingTier.OVERSIZE

    def as_report(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "context_bytes": self.context_bytes,
            "estimated_tokens": estimated_tokens(str(self.context_bytes)) if self.context_bytes else 0,
            "truncated": self.truncated,
            "dropped_fields": list(self.dropped_fields),
            "file_count": len(self.files),
            "omitted_files": self.omitted_files,
            "oversize_reason": self.oversize_reason,
        }


def load_config(path: Path | None = None) -> dict[str, Any]:
    """Load the byte budgets and recipe definitions."""
    return json.loads((path or CONFIG_PATH).read_text(encoding="utf-8"))


def _magika_type(path: Path) -> str:
    """Classify by content, not extension.

    Extension alone misroutes a shell script named ``.txt``, which is exactly the
    disguise an adversarial package would use.
    """
    try:
        from skill_scanner.core.file_magic import detect_magic

        match = detect_magic(path)
    except Exception:  # noqa: BLE001 - classification is advisory, never fatal
        return "unknown"
    if match is None:
        return "unknown"
    return match.content_type or match.content_family or "unknown"


def classify_role(relative_path: str, magika_type: str) -> FileRole:
    """Assign a packing role from the path and the detected content type."""
    lowered = relative_path.lower()
    name = lowered.rsplit("/", 1)[-1]
    if name == "skill.md":
        return FileRole.SKILL_MD
    if magika_type.startswith(("image", "audio", "video", "font", "archive")):
        return FileRole.ASSET
    # Detected content type outranks the extension. A shell script named .txt is
    # exactly the disguise to expect, and classifying it as documentation would
    # truncate it hardest, which is the wrong way round for security.
    if magika_type.startswith("code"):
        return FileRole.CODE
    if lowered.endswith((".md", ".rst", ".txt")) or "/doc" in lowered or lowered.startswith("doc"):
        return FileRole.DOCUMENTATION
    if lowered.endswith((".py", ".js", ".ts", ".tsx", ".sh", ".bash", ".rb", ".pl", ".php", ".vue", ".go", ".rs")):
        return FileRole.CODE
    return FileRole.DOCUMENTATION


def _read_text(path: Path) -> str | None:
    """Read a file as text, or return None when it is not usable text."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        # Binary content is never the judged decision and would waste budget.
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    # Neutralize at read time, not at truncation time. Tier A returns file text
    # unchanged and so never passes through bound_value; without this, a whole-
    # record pack of a malicious SKILL.md would carry live framing tags. Tier A
    # is 100% of the benchmark corpus, so that gap would affect every request.
    # neutralize is idempotent, so bound_value applying it again is harmless.
    return neutralize(text)


def referenced_names(skill_md_text: str) -> set[str]:
    """File names mentioned by SKILL.md.

    Declared-and-referenced code is the actual execution surface, so it outranks
    code that merely sits in the package.
    """
    import re

    return {match.lower() for match in re.findall(r"[\w./-]+\.(?:py|js|ts|sh|bash|rb|pl|php|go|rs)", skill_md_text)}


def collect_files(skill_directory: Path) -> tuple[list[PackedFile], int]:
    """Gather scanner-relevant text files, returning them and the omitted count."""
    candidates: list[tuple[int, Path, str]] = []
    omitted = 0
    for path in sorted(skill_directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in SKIPPED_DIRECTORIES for part in path.parts):
            continue
        if path.suffix.lower() in SKIPPED_EXTENSIONS:
            omitted += 1
            continue
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > MAX_FILE_BYTES:
            omitted += 1
            continue
        candidates.append((size, path, str(path.relative_to(skill_directory))))

    # Mirror the scanner's file ceiling, keeping the largest, which carry the most signal.
    candidates.sort(key=lambda item: -item[0])
    if len(candidates) > MAX_FILES:
        omitted += len(candidates) - MAX_FILES
        candidates = candidates[:MAX_FILES]

    packed: list[PackedFile] = []
    for size, path, relative in candidates:
        text = _read_text(path)
        if text is None:
            omitted += 1
            continue
        magika = _magika_type(path)
        packed.append(
            PackedFile(
                relative_path=relative,
                role=classify_role(relative, magika),
                magika_type=magika,
                byte_size=size,
                text=text,
                truncated=False,
            )
        )
    return packed, omitted


def _role_priority(file: PackedFile, referenced: set[str]) -> tuple[int, int]:
    """Sort key implementing the documented fill order."""
    name = file.relative_path.lower().rsplit("/", 1)[-1]
    if file.role is FileRole.SKILL_MD:
        rank = 0
    elif file.role is FileRole.CODE and (name in referenced or file.relative_path.lower() in referenced):
        rank = 1
    elif file.role is FileRole.CODE:
        rank = 2
    elif file.role is FileRole.DOCUMENTATION:
        rank = 3
    else:
        rank = 4
    # Smaller files first within a rank, so budget buys more distinct evidence.
    return rank, file.byte_size


def pack_skill(
    skill_directory: Path,
    *,
    budget_bytes: int,
    hard_reject_bytes: int,
) -> PackedRequest:
    """Pack a skill into a bounded payload, choosing the highest viable tier."""
    files, omitted = collect_files(skill_directory)
    if not files:
        return PackedRequest(
            tier=PackingTier.OVERSIZE,
            omitted_files=omitted,
            oversize_reason="no readable text content",
        )

    total = sum(len(file.text.encode()) for file in files)

    # Tier A: everything fits, so send everything.
    if total <= budget_bytes:
        return PackedRequest(
            tier=PackingTier.WHOLE,
            files=files,
            context_bytes=total,
            truncated=False,
            omitted_files=omitted,
        )

    skill_md = next((file for file in files if file.role is FileRole.SKILL_MD), None)
    referenced = referenced_names(skill_md.text) if skill_md else set()
    ordered = sorted(files, key=lambda file: _role_priority(file, referenced))

    # Tier B: fill by priority. SKILL.md goes in whole because it fits 96% of the
    # time and it is the instruction surface.
    selected: list[PackedFile] = []
    used = 0
    any_truncated = False
    for file in ordered:
        remaining = budget_bytes - used
        if remaining <= 0:
            omitted += 1
            continue
        # Documentation is truncated hardest: it is the largest text volume in the
        # corpus and the least likely to carry the decision.
        share = remaining if file.role in {FileRole.SKILL_MD, FileRole.REFERENCED_SCRIPT} else remaining // 2
        share = max(share, min(remaining, 512))
        text, truncated = bound_value(file.text, share)
        cost = len(text.encode())
        if cost > remaining:
            omitted += 1
            continue
        selected.append(
            PackedFile(
                relative_path=file.relative_path,
                role=file.role,
                magika_type=file.magika_type,
                byte_size=file.byte_size,
                text=text,
                truncated=truncated,
            )
        )
        any_truncated |= truncated
        used += cost

    if not selected:
        return PackedRequest(
            tier=PackingTier.OVERSIZE,
            omitted_files=omitted,
            oversize_reason="no file fits the budget even truncated",
        )

    if used > hard_reject_bytes:
        # Defensive: never emit a body past the hard ceiling.
        return PackedRequest(
            tier=PackingTier.OVERSIZE,
            context_bytes=used,
            omitted_files=omitted,
            oversize_reason=f"packed body {used} bytes exceeds hard reject {hard_reject_bytes}",
        )

    return PackedRequest(
        tier=PackingTier.PRIORITIZED,
        files=selected,
        context_bytes=used,
        truncated=any_truncated,
        omitted_files=omitted,
    )


def package_shape(request: PackedRequest) -> dict[str, Any]:
    """Derived inventory facts, not content.

    Kept separate so a context recipe can include the shape of a package without
    including more of its text.
    """
    roles: dict[str, int] = {}
    types: dict[str, int] = {}
    for file in request.files:
        roles[file.role.value] = roles.get(file.role.value, 0) + 1
        types[file.magika_type] = types.get(file.magika_type, 0) + 1
    return {
        "file_count": len(request.files),
        "omitted_files": request.omitted_files,
        "roles": dict(sorted(roles.items())),
        "detected_types": dict(sorted(types.items())),
        "truncated_any": request.truncated,
    }


def render_state(
    request: PackedRequest,
    *,
    skill_name: str,
    declared_purpose: str = "",
    fields: Sequence[str] | None = None,
) -> dict[str, Any]:
    """Render a packed request as the untrusted-framed state payload.

    ``fields`` selects which parts of the state to include, which is what makes a
    context ablation mean anything: without it every recipe would send identical
    content and differ only by label.  An unknown field name is rejected rather
    than ignored, because silently falling back to the full context would make the
    ablation report a difference that was never sent.
    """
    if not request.is_sendable:
        raise ValueError(f"refusing to render an oversize request: {request.oversize_reason}")

    available: dict[str, Any] = {
        "skill_identity": safe_identifier(skill_name),
        "declared_purpose": neutralize(declared_purpose),
        "packing_tier": request.tier.value,
        "package_shape": package_shape(request),
        "files": [
            {
                "path": safe_identifier(file.relative_path),
                "role": file.role.value,
                "type": file.magika_type,
                "truncated": file.truncated,
                # Already neutralized and bounded at read time.
                "content": file.text,
            }
            for file in request.files
        ],
    }
    if fields is None:
        return available

    unknown = [name for name in fields if name not in available]
    if unknown:
        raise ValueError(f"context recipe names fields the renderer cannot produce: {unknown}")
    return {name: available[name] for name in fields}


def rank_candidates(candidates: Sequence[Any], *, cap: int) -> tuple[list[Any], int]:
    """Cap candidates per package, keeping the most severe.

    A package with 200 candidates is 200 requests.  The cap-hit rate is reported
    because a high rate means the package-level metric is being carried by the
    deterministic tier and the model tier's contribution is overstated.
    """
    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    def key(candidate: Any) -> tuple[int, str]:
        severity = getattr(getattr(candidate, "severity", None), "name", None) or str(
            getattr(candidate, "severity", "")
        )
        return severity_rank.get(str(severity).upper(), 5), str(getattr(candidate, "rule_id", ""))

    ordered = sorted(candidates, key=key)
    if len(ordered) <= cap:
        return list(ordered), 0
    return ordered[:cap], len(ordered) - cap


def dedupe_candidates(candidates: Iterable[Any], fingerprint: Any) -> tuple[list[Any], int]:
    """Collapse candidates sharing a fingerprint.

    One rule firing forty times in one file is one judgement, not forty.
    """
    seen: set[str] = set()
    kept: list[Any] = []
    duplicates = 0
    for candidate in candidates:
        key = str(fingerprint(candidate))
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        kept.append(candidate)
    return kept, duplicates


def rank_siblings(texts: Sequence[str], current: str, *, limit: int) -> list[str]:
    """Pick the most relevant sibling snippets for the K3 and K7 recipes."""
    scored = sorted(texts, key=lambda text: -relevance_score(text, current))
    return list(scored[:limit])
