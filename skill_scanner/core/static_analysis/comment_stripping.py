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

"""Language-aware comment stripping for static-analysis inputs."""

import io
import tokenize


def _strip_python_comments(content: str) -> list[str]:
    """Return Python source lines with tokenizer-identified comments removed."""
    lines = content.split("\n")
    try:
        tokens = tokenize.generate_tokens(io.StringIO(content).readline)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            row, column = token.start
            if 1 <= row <= len(lines):
                lines[row - 1] = lines[row - 1][:column]
    except (IndentationError, SyntaxError, tokenize.TokenError):
        # Homoglyph analysis should remain available for malformed snippets.
        return _strip_bash_comments(content, require_token_boundary=False)
    return lines


def _strip_bash_comments(content: str, *, require_token_boundary: bool = True) -> list[str]:
    """Strip Bash comments while carrying quote state across physical lines."""
    stripped_lines: list[str] = []
    quote: str | None = None
    at_token_start = True

    for line in content.split("\n"):
        index = 0
        escaped = False
        comment_index: int | None = None

        while index < len(line):
            char = line[index]

            if escaped:
                escaped = False
                # Escaped whitespace and metacharacters remain part of the
                # current word, so a following hash cannot begin a comment.
                at_token_start = False
                index += 1
                continue

            if quote == "single":
                if char == "'":
                    quote = None
                index += 1
                continue

            if quote == "ansi_c":
                if char == "\\":
                    escaped = True
                elif char == "'":
                    quote = None
                index += 1
                continue

            if quote == "double":
                if char == "\\":
                    escaped = True
                elif char == '"':
                    quote = None
                index += 1
                continue

            if char == "\\":
                escaped = True
                index += 1
                continue
            if char == "$" and index + 1 < len(line) and line[index + 1] in {"'", '"'}:
                quote = "ansi_c" if line[index + 1] == "'" else "double"
                at_token_start = False
                index += 2
                continue
            if char == "'":
                quote = "single"
                at_token_start = False
                index += 1
                continue
            if char == '"':
                quote = "double"
                at_token_start = False
                index += 1
                continue
            if char == "#" and (not require_token_boundary or at_token_start):
                comment_index = index
                break
            if char.isspace() or char in ";|&()<>":
                at_token_start = True
            else:
                at_token_start = False
            index += 1

        stripped_lines.append(line if comment_index is None else line[:comment_index])
        if comment_index is not None or (quote is None and not escaped):
            # An unescaped physical newline terminates the current token.  A
            # trailing backslash or an open quote carries lexical state onward.
            at_token_start = True

    return stripped_lines


def comment_stripped_lines(content: str, file_type: str) -> list[str]:
    """Strip comments using the lexical rules of the executable file type."""
    if file_type == "python":
        return _strip_python_comments(content)
    if file_type == "bash":
        return _strip_bash_comments(content)
    return content.split("\n")
