# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""ASCII Smuggling detection checks.

ASCII Smuggling maps every printable ASCII character to its counterpart in
the Unicode Tag Block (U+E0000–U+E007F) and embeds the resulting invisible
characters inside otherwise-legitimate text.  The hidden text is invisible
in every editor and terminal but is decoded and acted on by LLMs, making
it an effective prompt-injection carrier.

Reference:
  https://embracethered.com/blog/posts/2026/scary-agent-skills/
  https://github.com/wunderwuzzi23/aid

Rule emitted: ASCII_SMUGGLING_TAG_BLOCK
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from skill_scanner.core.models import Finding, Severity, ThreatCategory

from ._helpers import generate_finding_id

if TYPE_CHECKING:
    from skill_scanner.core.models import Skill
    from skill_scanner.core.scan_policy import ScanPolicy  # noqa: TCH004

# ---- Unicode Tag Block constants ----------------------------------------

# The Unicode Tag Block runs from U+E0000 (TAG NULL) to U+E007F (TAG DELETE).
# U+E0001 is the "language tag" start-of-tag marker.
# U+E007F is the cancel/end-of-tag marker.
# Everything in between (U+E0020–U+E007E) maps 1-to-1 with ASCII printable chars.
_TAG_BLOCK_START = 0xE0000
_TAG_BLOCK_END = 0xE007F

# Printable tag codepoints: U+E0020 (tag space) through U+E007E (tag ~).
_TAG_PRINTABLE_START = 0xE0020
_TAG_PRINTABLE_END = 0xE007E

# Control/boundary markers (U+E0000, U+E0001, U+E007F) are also suspicious
# when found alongside printable tag chars, but a single isolated marker
# might appear in emoji-modifier chains — require two or more total.
_TAG_BOUNDARY_CODEPOINTS = frozenset([0xE0000, 0xE0001, 0xE007F])


def _is_tag_block(cp: int) -> bool:
    """Return True if *cp* is in the Unicode Tag Block (U+E0000–U+E007F)."""
    return _TAG_BLOCK_START <= cp <= _TAG_BLOCK_END


def _decode_smuggled_text(tag_chars: list[int]) -> str:
    """Best-effort decode of tag-block codepoints back to ASCII.

    Each tag codepoint is shifted by -0xE0000 to recover the original
    ASCII value.  Non-printable or out-of-range values are replaced by '?'.
    """
    decoded: list[str] = []
    for cp in tag_chars:
        ascii_cp = cp - _TAG_BLOCK_START
        if 0x20 <= ascii_cp <= 0x7E:
            decoded.append(chr(ascii_cp))
        elif ascii_cp == 0x01:
            decoded.append("<SOT>")
        elif ascii_cp == 0x7F:
            decoded.append("<EOT>")
        else:
            decoded.append("?")
    return "".join(decoded)


def check_ascii_smuggling(skill: Skill, policy: ScanPolicy) -> list[Finding]:
    """Scan every text file in *skill* for Unicode Tag Block characters.

    A finding is raised whenever one or more Tag Block codepoints are
    detected.  The finding includes:
    - Total count of tag characters found.
    - A decoded preview of the hidden message (first 120 chars).
    - The file and approximate line where the first cluster appears.
    """
    findings: list[Finding] = []

    for skill_file in skill.files:
        if skill_file.content is None:
            continue

        content: str = skill_file.content
        tag_chars: list[int] = []
        first_line: int = 1
        first_line_located = False

        lines = content.split("\n")
        for line_no, line in enumerate(lines, start=1):
            for ch in line:
                cp = ord(ch)
                if _is_tag_block(cp):
                    tag_chars.append(cp)
                    if not first_line_located:
                        first_line = line_no
                        first_line_located = True

        if not tag_chars:
            continue

        # Decode and truncate the smuggled payload preview.
        decoded_preview = _decode_smuggled_text(tag_chars)
        preview = decoded_preview[:120]
        if len(decoded_preview) > 120:
            preview += "…"

        # Describe the distribution for the analyst.
        printable_count = sum(1 for cp in tag_chars if _TAG_PRINTABLE_START <= cp <= _TAG_PRINTABLE_END)
        boundary_count = sum(1 for cp in tag_chars if cp in _TAG_BOUNDARY_CODEPOINTS)

        description = (
            f"ASCII smuggling detected in '{skill_file.relative_path}': "
            f"{len(tag_chars)} Unicode Tag Block character(s) found "
            f"({printable_count} printable, {boundary_count} boundary marker(s)). "
            f"First occurrence at line {first_line}. "
            f"Decoded hidden payload (first 120 chars): «{preview}». "
            "Tag Block characters (U+E0000–U+E007F) are invisible in editors "
            "and terminals but are interpreted by LLMs as plain text, enabling "
            "hidden prompt-injection instructions to be smuggled inside "
            "otherwise-legitimate skill files."
        )

        findings.append(
            Finding(
                id=generate_finding_id("ASCII_SMUGGLING_TAG_BLOCK", skill_file.relative_path),
                rule_id="ASCII_SMUGGLING_TAG_BLOCK",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=Severity.CRITICAL,
                title="ASCII smuggling via Unicode Tag Block detected",
                description=description,
                file_path=skill_file.relative_path,
                line_number=first_line,
                remediation=(
                    "Remove all Unicode Tag Block characters (U+E0000–U+E007F) from the file. "
                    'Run: python3 -c "'
                    "import sys; "
                    "text = open(sys.argv[1]).read(); "
                    "cleaned = ''.join(c for c in text if not (0xE0000 <= ord(c) <= 0xE007F)); "
                    "open(sys.argv[1], 'w').write(cleaned)\" <file>. "
                    "Alternatively use the 'aid' tool: https://github.com/wunderwuzzi23/aid"
                ),
                analyzer="static",
            )
        )

    return findings
