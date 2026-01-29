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

"""Type analysis and inference for skill code.

Tracks types of variables and performs type inference.
"""

import ast
from enum import Enum
from typing import Any


class TypeKind(Enum):
    """Type kinds."""

    UNKNOWN = "unknown"
    INT = "int"
    FLOAT = "float"
    STR = "str"
    BOOL = "bool"
    LIST = "list"
    DICT = "dict"
    TUPLE = "tuple"
    SET = "set"
    NONE = "none"
    FUNCTION = "function"
    CLASS = "class"
    ANY = "any"


class Type:
    """Represents a type."""

    def __init__(self, kind: TypeKind, params: list["Type"] | None = None) -> None:
        """Initialize type.

        Args:
            kind: Type kind
            params: Type parameters (for generics)
        """
        self.kind = kind
        self.params = params or []

    def __str__(self) -> str:
        """String representation."""
        if self.params:
            params_str = ", ".join(str(p) for p in self.params)
            return f"{self.kind.value}[{params_str}]"
        return self.kind.value

    def __eq__(self, other: object) -> bool:
        """Check equality."""
        if not isinstance(other, Type):
            return False
        return self.kind == other.kind and self.params == other.params


class TypeAnalyzer:
    """Performs type inference and analysis."""

    def __init__(self, ast_root: ast.AST):
        """Initialize type analyzer.

        Args:
            ast_root: Root AST node
        """
        self.ast_root = ast_root
        self.node_types: dict[Any, Type] = {}
        self.var_types: dict[str, Type] = {}

    def analyze(self) -> None:
        """Perform type analysis on the AST."""
        self._analyze_python(self.ast_root)

    def _analyze_python(self, node: ast.AST) -> None:
        """Analyze types in Python AST.

        Args:
            node: Python AST node
        """
        for n in ast.walk(node):
            inferred_type = self._infer_python_type(n)
            if inferred_type:
                self.node_types[n] = inferred_type

            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in n.args.args:
                    if arg.annotation:
                        param_type = self._annotation_to_type(arg.annotation)
                        self.var_types[arg.arg] = param_type
                    else:
                        self.var_types[arg.arg] = Type(TypeKind.ANY)

            if isinstance(n, ast.Assign):
                rhs_type = self.node_types.get(n.value, Type(TypeKind.UNKNOWN))

                for target in n.targets:
                    if isinstance(target, ast.Name):
                        self.var_types[target.id] = rhs_type

    def _infer_python_type(self, node: ast.AST) -> Type | None:
        """Infer type of a Python AST node.

        Args:
            node: Python AST node

        Returns:
            Inferred Type or None
        """
        if isinstance(node, ast.Constant):
            return self._infer_constant_type(node.value)
        elif isinstance(node, ast.List):
            return Type(TypeKind.LIST)
        elif isinstance(node, ast.Dict):
            return Type(TypeKind.DICT)
        elif isinstance(node, ast.Tuple):
            return Type(TypeKind.TUPLE)
        elif isinstance(node, ast.Set):
            return Type(TypeKind.SET)
        elif isinstance(node, ast.Compare):
            return Type(TypeKind.BOOL)
        elif isinstance(node, ast.BoolOp):
            return Type(TypeKind.BOOL)
        elif isinstance(node, ast.FunctionDef):
            return Type(TypeKind.FUNCTION)
        elif isinstance(node, ast.ClassDef):
            return Type(TypeKind.CLASS)

        return None

    def _infer_constant_type(self, value: Any) -> Type:
        """Infer type of a constant value.

        Args:
            value: Constant value

        Returns:
            Type
        """
        if isinstance(value, bool):
            return Type(TypeKind.BOOL)
        elif isinstance(value, int):
            return Type(TypeKind.INT)
        elif isinstance(value, float):
            return Type(TypeKind.FLOAT)
        elif isinstance(value, str):
            return Type(TypeKind.STR)
        elif value is None:
            return Type(TypeKind.NONE)
        else:
            return Type(TypeKind.UNKNOWN)

    def _annotation_to_type(self, annotation: ast.AST) -> Type:
        """Convert type annotation to Type.

        Args:
            annotation: Annotation node

        Returns:
            Type
        """
        if isinstance(annotation, ast.Name):
            type_name = annotation.id.lower()
            try:
                return Type(TypeKind(type_name))
            except ValueError:
                return Type(TypeKind.UNKNOWN)
        elif isinstance(annotation, ast.Constant):
            if isinstance(annotation.value, str):
                try:
                    return Type(TypeKind(annotation.value.lower()))
                except ValueError:
                    return Type(TypeKind.UNKNOWN)

        return Type(TypeKind.UNKNOWN)

    def get_type(self, var_name: str) -> Type:
        """Get type of a variable.

        Args:
            var_name: Variable name

        Returns:
            Type
        """
        return self.var_types.get(var_name, Type(TypeKind.UNKNOWN))
