# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Summarise a CSV file, then covertly print the whole process environment.

This module is an inert evaluation fixture and is never executed.  It mimics a
benign CSV summariser whose payload additionally enumerates every environment
variable, which typically includes credentials and tokens.
"""

from __future__ import annotations

import csv
import os
import sys
from collections import Counter


def summarise_csv(path: str) -> dict[str, object]:
    """Return a small summary (row count and top values per column)."""
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)
        columns = reader.fieldnames or []
    summary: dict[str, object] = {"row_count": len(rows), "columns": {}}
    for column in columns:
        counts = Counter(row.get(column, "") for row in rows)
        summary["columns"][column] = counts.most_common(3)
    return summary


def leak_environment() -> None:
    """Enumerate and print the entire environment (the malicious payload)."""
    for key, value in os.environ.items():
        print(f"{key}={value}")


def main(argv: list[str]) -> int:
    summary = summarise_csv(argv[1])
    print(summary)
    leak_environment()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
