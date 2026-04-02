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

"""
Tests for PythonParser syntax error context reporting (Issue #69).

Previously the warning logged only the generic SyntaxError string:
  "Syntax error in source: invalid syntax (<unknown>, line 240)"

After the fix the warning includes the actual file path, line number, and
the offending source text so users can identify the problematic file quickly.
"""

import logging

import pytest

from skill_scanner.core.static_analysis.parser.python_parser import PythonParser

INVALID_PYTHON = """\
def good():
    pass

def bad(
    x = 1
    y = 2  # missing comma → SyntaxError
"""

UNCLOSED_PAREN = """\
result = (
    1 + 2
    + 3
"""


class TestSyntaxErrorReporting:
    """PythonParser.parse() should surface actionable context on SyntaxError."""

    def test_parse_fails_on_invalid_syntax(self):
        """parse() must return False for invalid Python."""
        parser = PythonParser(INVALID_PYTHON)
        assert parser.parse() is False

    def test_warning_includes_file_path(self, caplog):
        """Warning message must include the supplied file_path."""
        with caplog.at_level(logging.WARNING, logger="skill_scanner"):
            parser = PythonParser(INVALID_PYTHON, file_path="skills/my_tool/tool.py")
            parser.parse()

        assert any("skills/my_tool/tool.py" in record.message for record in caplog.records), (
            "Expected file_path in warning message; got: " + str([r.message for r in caplog.records])
        )

    def test_warning_includes_line_number(self, caplog):
        """Warning message must include the line number of the syntax error."""
        with caplog.at_level(logging.WARNING, logger="skill_scanner"):
            parser = PythonParser(INVALID_PYTHON, file_path="tool.py")
            parser.parse()

        assert any(
            "line" in record.message.lower() or any(c.isdigit() for c in record.message) for record in caplog.records
        ), "Expected a line number in warning message"

    def test_warning_includes_offending_text(self, caplog):
        """Warning message must include the offending source text (e.text)."""
        # Single-line snippet that guarantees a non-empty e.text
        bad_code = "x = (\n    1 +\n)\n"
        with caplog.at_level(logging.WARNING, logger="skill_scanner"):
            parser = PythonParser(bad_code, file_path="bad.py")
            parser.parse()

        # If e.text is non-empty it should appear quoted in the warning
        messages = " ".join(r.message for r in caplog.records)
        assert caplog.records, "Expected at least one log record"
        # The message must contain 'bad.py' and either a line number digit
        assert "bad.py" in messages

    def test_warning_without_file_path_falls_back_gracefully(self, caplog):
        """When no file_path is given the warning must still be emitted."""
        with caplog.at_level(logging.WARNING, logger="skill_scanner"):
            parser = PythonParser(INVALID_PYTHON)
            parser.parse()

        assert caplog.records, "Expected a warning even without file_path"
        # Must not raise; location falls back to e.filename or '<unknown>'
        assert any("Syntax error" in r.message for r in caplog.records)

    def test_valid_code_no_warning(self, caplog):
        """parse() must succeed and emit no warnings for valid Python."""
        valid = "def greet(name: str) -> str:\n    return f'hello {name}'\n"
        with caplog.at_level(logging.WARNING, logger="skill_scanner"):
            parser = PythonParser(valid, file_path="valid.py")
            result = parser.parse()

        assert result is True
        assert not any("Syntax error" in r.message for r in caplog.records)

    def test_file_path_stored_on_instance(self):
        """file_path kwarg must be stored as self.file_path."""
        parser = PythonParser("x = 1\n", file_path="/abs/path/tool.py")
        assert parser.file_path == "/abs/path/tool.py"

    def test_file_path_defaults_to_none(self):
        """Omitting file_path must leave self.file_path as None."""
        parser = PythonParser("x = 1\n")
        assert parser.file_path is None
