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

"""Name resolution analysis for skill code.

Tracks variable definitions and resolves name references to their definitions.
"""

import ast
from typing import Any, Optional


class Scope:
    """Represents a lexical scope."""

    def __init__(self, parent: Optional["Scope"] = None) -> None:
        """Initialize scope.

        Args:
            parent: Parent scope
        """
        self.parent = parent
        self.symbols: dict[str, Any] = {}
        self.children: list[Scope] = []

    def define(self, name: str, node: Any) -> None:
        """Define a symbol in this scope.

        Args:
            name: Symbol name
            node: AST node defining the symbol
        """
        self.symbols[name] = node

    def lookup(self, name: str) -> Any | None:
        """Look up a symbol in this scope or parent scopes.

        Args:
            name: Symbol name

        Returns:
            AST node or None if not found
        """
        if name in self.symbols:
            return self.symbols[name]
        elif self.parent:
            return self.parent.lookup(name)
        return None


class NameResolver:
    """Resolves names to their definitions."""

    def __init__(self, ast_root: ast.AST):
        """Initialize name resolver.

        Args:
            ast_root: Root AST node
        """
        self.ast_root = ast_root
        self.global_scope = Scope()
        self.current_scope = self.global_scope
        self.name_to_def: dict[Any, Any] = {}

    def resolve(self) -> None:
        """Resolve all names in the AST."""
        self._resolve_python(self.ast_root)

    def _resolve_python(self, node: ast.AST) -> None:
        """Resolve names in Python AST.

        Args:
            node: Python AST node
        """
        self._visit_node(node)

    def _visit_node(self, node: ast.AST) -> None:
        """Visit a node and its children with proper scope tracking.

        Args:
            node: AST node to visit
        """
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function(node)
        elif isinstance(node, ast.ClassDef):
            self._visit_class(node)
        elif isinstance(node, ast.Assign):
            self._define_assignment(node)
            for child in ast.iter_child_nodes(node):
                self._visit_node(child)
        elif isinstance(node, ast.Import):
            self._define_import(node)
        elif isinstance(node, ast.ImportFrom):
            self._define_import_from(node)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            self._resolve_name(node)
        else:
            for child in ast.iter_child_nodes(node):
                self._visit_node(child)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit function with proper scope management.

        Args:
            node: Function definition node
        """
        self.current_scope.define(node.name, node)

        func_scope = Scope(parent=self.current_scope)
        self.current_scope.children.append(func_scope)
        old_scope = self.current_scope
        self.current_scope = func_scope

        for arg in node.args.args:
            func_scope.define(arg.arg, arg)

        for child in node.body:
            self._visit_node(child)

        self.current_scope = old_scope

    def _visit_class(self, node: ast.ClassDef) -> None:
        """Visit class with proper scope management.

        Args:
            node: Class definition node
        """
        self.current_scope.define(node.name, node)

        class_scope = Scope(parent=self.current_scope)
        self.current_scope.children.append(class_scope)
        old_scope = self.current_scope
        self.current_scope = class_scope

        for child in node.body:
            self._visit_node(child)

        self.current_scope = old_scope

    def _define_assignment(self, node: ast.Assign) -> None:
        """Define variables from assignment.

        Args:
            node: Assignment node
        """
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.current_scope.define(target.id, node)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        self.current_scope.define(elt.id, node)

    def _define_import(self, node: ast.Import) -> None:
        """Define imported names.

        Args:
            node: Import node
        """
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.current_scope.define(name, node)

    def _define_import_from(self, node: ast.ImportFrom) -> None:
        """Define names from 'from ... import' statement.

        Args:
            node: ImportFrom node
        """
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.current_scope.define(name, node)

    def _resolve_name(self, node: ast.Name) -> None:
        """Resolve a name reference to its definition.

        Args:
            node: Name node
        """
        definition = self.current_scope.lookup(node.id)
        if definition:
            self.name_to_def[node] = definition

    def get_definition(self, node: Any) -> Any | None:
        """Get the definition for a name usage.

        Args:
            node: Name usage node

        Returns:
            Definition node or None
        """
        return self.name_to_def.get(node)
