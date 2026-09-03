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

"""Deterministic public finding-identity primitives."""

from __future__ import annotations

import hashlib

_DOMAIN = b"skill-scanner-finding-id-v1\0"


def stable_finding_suffix(*parts: str) -> str:
    """Return a process-independent eight-hex suffix for ordered text parts.

    Each part is length-prefixed so identities such as ``("ab", "c")`` and
    ``("a", "bc")`` cannot alias through concatenation. ``surrogatepass``
    keeps unusual filesystem names deterministic without accepting bytes or
    arbitrary object representations into the public identity contract.
    """

    if not parts:
        raise ValueError("finding identity requires at least one text part")
    digest = hashlib.sha256(_DOMAIN)
    for part in parts:
        if not isinstance(part, str):
            raise TypeError("finding identity parts must be strings")
        encoded = part.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()[:8]
