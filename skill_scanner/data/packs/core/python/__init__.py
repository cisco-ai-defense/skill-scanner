# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""
Extracted Python check modules for the core rule pack.

Each module in this package implements one or more detection checks that
were previously inline methods on analyzer classes.  Extracting them into
standalone functions makes individual rules:

* **Independently testable** — call ``check_*()`` with test inputs.
* **Easy to find** — each module groups related checks by concern.
* **Reusable** — any analyzer can import and call a check function.

Convention
~~~~~~~~~~

Every public function follows the pattern::

    def check_<aspect>(
        <required_inputs>,
        policy: ScanPolicy,
        *,
        <optional_keyword_args>,
    ) -> list[Finding]:
        ...

The caller (analyzer class) remains responsible for orchestration: which
checks to run, in what order, and how to combine their outputs.
"""
