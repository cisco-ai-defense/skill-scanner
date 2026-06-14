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

"""Archive metadata helpers for preflight limits."""

from __future__ import annotations

import struct
from pathlib import Path

_EOCD_SIGNATURE = b"PK\x05\x06"
_ZIP64_LOCATOR_SIGNATURE = b"PK\x06\x07"
_ZIP64_EOCD_SIGNATURE = b"PK\x06\x06"
_EOCD_SEARCH_BYTES = 65_557
_ZIP16_MAX = 0xFFFF


def read_zip_member_count(path: Path) -> int | None:
    """Read ZIP member count from EOCD metadata without constructing ``ZipFile``."""
    try:
        file_size = path.stat().st_size
        with open(path, "rb") as f:
            read_size = min(file_size, _EOCD_SEARCH_BYTES)
            f.seek(file_size - read_size)
            tail = f.read(read_size)
            eocd_index = tail.rfind(_EOCD_SIGNATURE)
            if eocd_index < 0 or len(tail) - eocd_index < 22:
                return None

            eocd = tail[eocd_index : eocd_index + 22]
            total_entries = struct.unpack_from("<H", eocd, 10)[0]
            if total_entries != _ZIP16_MAX:
                return total_entries

            eocd_abs_offset = file_size - read_size + eocd_index
            locator_offset = eocd_abs_offset - 20
            if locator_offset < 0:
                return _ZIP16_MAX
            f.seek(locator_offset)
            locator = f.read(20)
            if len(locator) != 20 or locator[:4] != _ZIP64_LOCATOR_SIGNATURE:
                return _ZIP16_MAX

            zip64_eocd_offset = struct.unpack_from("<Q", locator, 8)[0]
            f.seek(zip64_eocd_offset)
            zip64_eocd = f.read(56)
            if len(zip64_eocd) < 56 or zip64_eocd[:4] != _ZIP64_EOCD_SIGNATURE:
                return _ZIP16_MAX
            return struct.unpack_from("<Q", zip64_eocd, 32)[0]
    except OSError:
        return None
