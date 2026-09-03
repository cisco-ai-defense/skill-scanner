# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

"""Typed semantic facts shared by deterministic analyzers and CEL gates."""

from .projector import FactLimits, ScanFactProjector

__all__ = ["FactLimits", "ScanFactProjector"]
