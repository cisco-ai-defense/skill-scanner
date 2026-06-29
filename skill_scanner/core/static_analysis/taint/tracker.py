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

"""Taint tracking for dataflow analysis.

Simplified taint tracking system for parameter flow analysis.
Tracks taint status and labels for variables to enable accurate
dataflow tracking through control structures.
"""

from dataclasses import dataclass, field
from enum import Enum


class TaintStatus(Enum):
    """Taint status."""

    TAINTED = "tainted"
    UNTAINTED = "untainted"
    UNKNOWN = "unknown"


@dataclass
class Taint:
    """Taint information with labels and sources."""

    status: TaintStatus = TaintStatus.UNTAINTED
    labels: set[str] = field(default_factory=set)

    def is_tainted(self) -> bool:
        """Check if tainted."""
        return self.status == TaintStatus.TAINTED

    def add_label(self, label: str) -> None:
        """Add a taint label."""
        self.labels.add(label)

    def has_label(self, label: str) -> bool:
        """Check if has a specific label."""
        return label in self.labels

    def merge(self, other: "Taint") -> "Taint":
        """Merge two taints."""
        if not self.is_tainted() and not other.is_tainted():
            return Taint(status=TaintStatus.UNTAINTED)

        return Taint(
            status=TaintStatus.TAINTED,
            labels=self.labels | other.labels,
        )

    def copy(self) -> "Taint":
        """Create a copy."""
        return Taint(
            status=self.status,
            labels=self.labels.copy(),
        )


class ShapeEnvironment:
    """Environment for tracking taint shapes of variables."""

    def __init__(self) -> None:
        """Initialize shape environment."""
        self._shapes: dict[str, TaintShape] = {}

    def get(self, var_name: str) -> "TaintShape":
        """Get taint shape for a variable (READ-ONLY access).

        After ``copy()`` the returned shape may be shared with another
        environment (copy-on-write). Callers MUST treat the result as
        read-only -- mutating it in place (e.g. ``set_field``/``set_element``)
        would leak the change into the source environment and break the
        fixpoint. The only sanctioned mutation path is ``set_taint``, which
        clones the shape before writing. The forward-dataflow analysis only
        ever reads via ``get`` and writes via ``set_taint``; this invariant is
        pinned by the copy-isolation regression test.

        Args:
            var_name: Variable name

        Returns:
            Taint shape (creates new if not exists)
        """
        if var_name not in self._shapes:
            self._shapes[var_name] = TaintShape()
        return self._shapes[var_name]

    def set_taint(self, var_name: str, taint: Taint) -> None:
        """Set taint for a variable.

        Args:
            var_name: Variable name
            taint: Taint to set
        """
        # Copy-on-write: copy() shares TaintShape objects with the source
        # environment, so we must never mutate an existing shape in place here —
        # it may be shared with another (copied) environment. Clone the shape
        # before writing so the write is isolated to this environment.
        old_shape = self._shapes.get(var_name)
        shape = old_shape.copy() if old_shape is not None else TaintShape()
        shape.set_taint(taint)
        self._shapes[var_name] = shape

    def get_taint(self, var_name: str) -> Taint:
        """Get taint for a variable.

        Args:
            var_name: Variable name

        Returns:
            Taint (UNTAINTED if not found)
        """
        if var_name in self._shapes:
            return self._shapes[var_name].get_taint()
        return Taint(status=TaintStatus.UNTAINTED)

    def copy(self) -> "ShapeEnvironment":
        """Create a copy-on-write copy of the environment.

        The returned environment shares TaintShape objects with this one; each
        shape is cloned lazily only when it is written (see ``set_taint``). This
        makes copying O(number of variables) instead of deep-copying every shape,
        which dominates fixpoint cost on large/looping functions. Safe because the
        dataflow only mutates shapes through ``set_taint`` and ``get`` is read-only.
        """
        new_env = ShapeEnvironment()
        new_env._shapes = dict(self._shapes)  # shallow: shapes shared until written
        return new_env

    def __eq__(self, other: object) -> bool:
        """Compare environments by content, not identity.

        Required for dataflow fixpoint convergence: the worklist algorithm
        decides it has reached a fixpoint when a node's out-fact stops
        changing. Without content-based equality, freshly-copied environments
        always compare unequal, so the analysis never converges and instead
        spins until the iteration safety cap (which is catastrophically slow
        on large files).
        """
        if not isinstance(other, ShapeEnvironment):
            return NotImplemented
        return self._shapes == other._shapes

    __hash__ = None  # type: ignore[assignment]  # mutable; compared by content, never hashed

    def merge(self, other: "ShapeEnvironment") -> "ShapeEnvironment":
        """Merge two environments.

        Args:
            other: Other environment to merge

        Returns:
            Merged environment
        """
        merged = ShapeEnvironment()

        # Get all variable names from both
        all_vars = set(self._shapes.keys()) | set(other._shapes.keys())

        for var_name in all_vars:
            self_taint = self.get_taint(var_name)
            other_taint = other.get_taint(var_name)
            merged.set_taint(var_name, self_taint.merge(other_taint))

        return merged


class TaintShape:
    """Represents the shape of tainted data structures."""

    MAX_DEPTH = 3  # Cap nesting depth to prevent explosion

    def __init__(self, taint: Taint | None = None, depth: int = 0):
        """Initialize taint shape.

        Args:
            taint: Base taint for scalar values
            depth: Current nesting depth (for bounding)
        """
        self.scalar_taint = taint or Taint()
        self.fields: dict[str, TaintShape] = {}
        self.element_shape: TaintShape | None = None
        self.is_object = False
        self.is_array = False
        self.depth = depth
        self.collapsed = depth >= self.MAX_DEPTH

    def get_taint(self) -> Taint:
        """Get the taint of this shape."""
        return self.scalar_taint

    def set_taint(self, taint: Taint) -> None:
        """Set the taint of this shape."""
        self.scalar_taint = taint

    def get_field(self, field: str) -> Taint:
        """Get taint of a specific field.

        Args:
            field: Field name

        Returns:
            Taint of the field
        """
        if self.scalar_taint.is_tainted():
            return self.scalar_taint

        if field in self.fields:
            return self.fields[field].get_taint()

        return Taint(status=TaintStatus.UNTAINTED)

    def set_field(self, field: str, taint: Taint) -> None:
        """Set taint of a specific field.

        Args:
            field: Field name
            taint: Taint to set
        """
        if self.collapsed:
            self.scalar_taint = self.scalar_taint.merge(taint)
            return

        self.is_object = True

        if field not in self.fields:
            self.fields[field] = TaintShape(depth=self.depth + 1)

        self.fields[field].set_taint(taint)

    def get_element(self) -> Taint:
        """Get taint of array elements.

        Returns:
            Taint of elements
        """
        if self.scalar_taint.is_tainted():
            return self.scalar_taint

        if self.element_shape:
            return self.element_shape.get_taint()

        return Taint(status=TaintStatus.UNTAINTED)

    def set_element(self, taint: Taint) -> None:
        """Set taint of array elements.

        Args:
            taint: Taint to set
        """
        if self.collapsed:
            self.scalar_taint = self.scalar_taint.merge(taint)
            return

        self.is_array = True

        if not self.element_shape:
            self.element_shape = TaintShape(depth=self.depth + 1)

        self.element_shape.set_taint(taint)

    def copy(self) -> "TaintShape":
        """Create a copy."""
        new_shape = TaintShape(taint=self.scalar_taint.copy(), depth=self.depth)
        new_shape.is_object = self.is_object
        new_shape.is_array = self.is_array
        new_shape.collapsed = self.collapsed

        for field_name, shape in self.fields.items():
            new_shape.fields[field_name] = shape.copy()

        if self.element_shape:
            new_shape.element_shape = self.element_shape.copy()

        return new_shape

    def __eq__(self, other: object) -> bool:
        """Compare shapes by content, not identity.

        Needed so that ``ShapeEnvironment`` equality (and therefore dataflow
        fixpoint detection) reflects the actual taint state rather than object
        identity. Recurses into fields and array element shapes.
        """
        if not isinstance(other, TaintShape):
            return NotImplemented
        return (
            self.scalar_taint == other.scalar_taint
            and self.is_object == other.is_object
            and self.is_array == other.is_array
            and self.collapsed == other.collapsed
            and self.fields == other.fields
            and self.element_shape == other.element_shape
        )

    __hash__ = None  # type: ignore[assignment]  # mutable; compared by content, never hashed
