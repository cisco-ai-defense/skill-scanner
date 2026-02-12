# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Archive extraction and Office threat checks.

Rules: ARCHIVE_EXTRACTION_FAILED, ARCHIVE_NESTED_TOO_DEEP,
       ARCHIVE_ZIP_BOMB, ARCHIVE_PATH_TRAVERSAL,
       OFFICE_VBA_MACRO, OFFICE_EMBEDDED_OLE.

Note: These rules remain implemented inline in ContentExtractor because
they are tightly coupled to the extraction process (they fire mid-extraction
as structural issues are discovered). This module re-exports the rule IDs
and metadata for registry/audit purposes but does NOT duplicate the logic.

The actual implementations live in:
  skill_scanner/core/extractors/content_extractor.py
"""

# Rule IDs provided by the content extractor (for documentation only)
ARCHIVE_RULE_IDS = [
    "ARCHIVE_EXTRACTION_FAILED",
    "ARCHIVE_NESTED_TOO_DEEP",
    "ARCHIVE_ZIP_BOMB",
    "ARCHIVE_PATH_TRAVERSAL",
    "OFFICE_VBA_MACRO",
    "OFFICE_EMBEDDED_OLE",
]
