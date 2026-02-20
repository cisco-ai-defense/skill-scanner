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

"""
Tests for API server configuration and module paths.

These tests verify that uvicorn module paths are correct and that
the server can be properly started. This prevents regressions where
module paths become invalid after refactoring.
"""

import ast
import importlib
import inspect
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


class TestModulePathsValid:
    """Test that all uvicorn module paths in the codebase are valid."""

    def _extract_uvicorn_paths_from_file(self, filepath: Path) -> list[tuple[int, str]]:
        """
        Extract uvicorn.run() module paths from a Python file.

        Returns list of (line_number, module_path) tuples.
        """
        paths = []
        content = filepath.read_text()

        # Parse the AST to find uvicorn.run calls
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return paths

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check if it's uvicorn.run()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "run":
                        # Check if it's uvicorn.run
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == "uvicorn":
                            # Get the first argument (module path)
                            if node.args and isinstance(node.args[0], ast.Constant):
                                paths.append((node.lineno, node.args[0].value))

        return paths

    def _validate_module_path(self, module_path: str) -> tuple[bool, str]:
        """
        Validate that a uvicorn module path is importable.

        Args:
            module_path: String like "module.submodule:app"

        Returns:
            Tuple of (is_valid, error_message)
        """
        if ":" not in module_path:
            return False, f"Invalid format: missing ':' separator in '{module_path}'"

        module_name, attr_name = module_path.split(":", 1)

        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            return False, f"Cannot import module '{module_name}': {e}"

        if not hasattr(module, attr_name):
            return False, f"Module '{module_name}' has no attribute '{attr_name}'"

        return True, ""

    def test_api_server_uvicorn_path_is_valid(self):
        """Test that api_server.py uses a valid uvicorn module path."""
        api_server_path = Path(__file__).parent.parent / "skill_scanner" / "api" / "api_server.py"

        if not api_server_path.exists():
            pytest.skip("api_server.py not found")

        paths = self._extract_uvicorn_paths_from_file(api_server_path)

        assert len(paths) > 0, "No uvicorn.run() calls found in api_server.py"

        for line_no, module_path in paths:
            is_valid, error = self._validate_module_path(module_path)
            assert is_valid, f"Invalid uvicorn path at line {line_no}: {error}"

    def test_api_cli_uvicorn_path_is_valid(self):
        """Test that api_cli.py uses a valid uvicorn module path."""
        api_cli_path = Path(__file__).parent.parent / "skill_scanner" / "api" / "api_cli.py"

        if not api_cli_path.exists():
            pytest.skip("api_cli.py not found")

        paths = self._extract_uvicorn_paths_from_file(api_cli_path)

        assert len(paths) > 0, "No uvicorn.run() calls found in api_cli.py"

        for line_no, module_path in paths:
            is_valid, error = self._validate_module_path(module_path)
            assert is_valid, f"Invalid uvicorn path at line {line_no}: {error}"

    def test_all_api_files_have_valid_uvicorn_paths(self):
        """Test all Python files in api/ directory for valid uvicorn paths."""
        api_dir = Path(__file__).parent.parent / "skill_scanner" / "api"

        if not api_dir.exists():
            pytest.skip("api/ directory not found")

        errors = []
        for py_file in api_dir.glob("*.py"):
            paths = self._extract_uvicorn_paths_from_file(py_file)
            for line_no, module_path in paths:
                is_valid, error = self._validate_module_path(module_path)
                if not is_valid:
                    errors.append(f"{py_file.name}:{line_no}: {error}")

        assert not errors, "Invalid uvicorn paths found:\n" + "\n".join(errors)


class TestModulePathFormat:
    """Test that module paths follow the correct format after refactoring."""

    def test_api_server_path_includes_api_subpackage(self):
        """Test that api_server.py path includes 'api' subpackage."""
        api_server_path = Path(__file__).parent.parent / "skill_scanner" / "api" / "api_server.py"
        content = api_server_path.read_text()

        # The path should be skill_scanner.api.api_server, not skill_scanner.api_server
        assert "skill_scanner.api.api_server" in content, (
            "api_server.py should use 'skill_scanner.api.api_server:app' not 'skill_scanner.api_server:app'"
        )

        # Should NOT have the incorrect path
        # Use regex to avoid matching the correct path
        incorrect_pattern = r'["\']skill_scanner\.api_server:'
        assert not re.search(incorrect_pattern, content), (
            "Found incorrect module path 'skill_scanner.api_server:' - should be 'skill_scanner.api.api_server:'"
        )

    def test_api_cli_path_includes_api_subpackage(self):
        """Test that api_cli.py path includes 'api' subpackage."""
        api_cli_path = Path(__file__).parent.parent / "skill_scanner" / "api" / "api_cli.py"
        content = api_cli_path.read_text()

        # The path should be skill_scanner.api.api, not skill_scanner.api
        assert "skill_scanner.api.api" in content, "api_cli.py should use 'skill_scanner.api.api:app' path"


class TestAppImportable:
    """Test that the FastAPI app objects are importable."""

    def test_api_app_importable(self):
        """Test that skill_scanner.api.api:app is importable."""
        try:
            from skill_scanner.api.api import app

            assert app is not None
            assert hasattr(app, "routes"), "app should be a FastAPI instance with routes"
        except ImportError as e:
            pytest.fail(f"Cannot import app from skill_scanner.api.api: {e}")

    def test_api_server_app_importable(self):
        """Test that skill_scanner.api.api_server:app is importable."""
        try:
            from skill_scanner.api.api_server import app

            assert app is not None
            assert hasattr(app, "routes"), "app should be a FastAPI instance with routes"
        except ImportError as e:
            pytest.fail(f"Cannot import app from skill_scanner.api.api_server: {e}")

    def test_api_init_exports_app(self):
        """Test that skill_scanner.api exports app."""
        try:
            from skill_scanner.api import app

            assert app is not None
        except ImportError as e:
            pytest.fail(f"Cannot import app from skill_scanner.api: {e}")


class TestRunServerFunction:
    """Test the run_server() function configuration."""

    def test_run_server_exists(self):
        """Test that run_server function exists in api_server.py."""
        from skill_scanner.api.api_server import run_server

        assert callable(run_server)

    def test_run_server_has_correct_signature(self):
        """Test that run_server has the expected parameters."""
        from skill_scanner.api.api_server import run_server

        sig = inspect.signature(run_server)
        params = list(sig.parameters.keys())

        assert "host" in params, "run_server should have 'host' parameter"
        assert "port" in params, "run_server should have 'port' parameter"
        assert "reload" in params, "run_server should have 'reload' parameter"

    def test_run_server_default_values(self):
        """Test that run_server has sensible default values."""
        from skill_scanner.api.api_server import run_server

        sig = inspect.signature(run_server)

        # Check default values
        assert sig.parameters["host"].default == "localhost"
        assert sig.parameters["port"].default == 8000
        assert sig.parameters["reload"].default is False

    @patch("uvicorn.run")
    def test_run_server_calls_uvicorn_with_correct_path(self, mock_uvicorn_run):
        """Test that run_server calls uvicorn.run with correct module path."""
        from skill_scanner.api.api_server import run_server

        # Call run_server
        run_server(host="127.0.0.1", port=9000, reload=True)

        # Verify uvicorn.run was called with correct arguments
        mock_uvicorn_run.assert_called_once()
        call_args = mock_uvicorn_run.call_args

        # First positional argument should be the module path
        module_path = call_args[0][0] if call_args[0] else call_args[1].get("app")

        assert module_path == "skill_scanner.api.api_server:app", (
            f"Expected 'skill_scanner.api.api_server:app', got '{module_path}'"
        )

        # Verify other arguments
        assert call_args[1]["host"] == "127.0.0.1"
        assert call_args[1]["port"] == 9000
        assert call_args[1]["reload"] is True


class TestApiCliMain:
    """Test the API CLI main function."""

    @patch("uvicorn.run")
    def test_api_cli_calls_uvicorn_with_correct_path(self, mock_uvicorn_run):
        """Test that api_cli.main() calls uvicorn.run with correct module path."""
        import sys
        from unittest.mock import patch as mock_patch

        # Mock sys.argv to provide arguments
        with mock_patch.object(sys, "argv", ["skill-scanner-api"]):
            from skill_scanner.api.api_cli import main

            main()

        # Verify uvicorn.run was called
        mock_uvicorn_run.assert_called_once()
        call_args = mock_uvicorn_run.call_args

        # First positional argument should be the module path
        module_path = call_args[0][0] if call_args[0] else call_args[1].get("app")

        assert module_path == "skill_scanner.api.api:app", f"Expected 'skill_scanner.api.api:app', got '{module_path}'"


class TestModulePathConsistency:
    """Test that module paths are consistent across the codebase."""

    def test_no_old_skillanalyzer_references(self):
        """Test that no old 'skillanalyzer' module paths remain."""
        api_dir = Path(__file__).parent.parent / "skill_scanner" / "api"

        for py_file in api_dir.glob("*.py"):
            content = py_file.read_text()

            # Check for old module references in uvicorn paths
            if "skillanalyzer" in content.lower():
                # Find the line for better error reporting
                for i, line in enumerate(content.split("\n"), 1):
                    if "skillanalyzer" in line.lower() and "uvicorn" in line.lower():
                        pytest.fail(f"Found old 'skillanalyzer' reference at {py_file.name}:{i}: {line.strip()}")

    def test_module_paths_use_skill_scanner_package(self):
        """Test that all uvicorn paths use 'skill_scanner' package name."""
        api_dir = Path(__file__).parent.parent / "skill_scanner" / "api"

        for py_file in api_dir.glob("*.py"):
            content = py_file.read_text()

            # Find uvicorn.run calls with string arguments
            uvicorn_pattern = r'uvicorn\.run\(["\']([^"\']+)["\']'
            matches = re.findall(uvicorn_pattern, content)

            for match in matches:
                assert match.startswith("skill_scanner."), (
                    f"Module path '{match}' in {py_file.name} should start with 'skill_scanner.'"
                )
