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

"""Small, bounded-cost helpers for parsing Markdown-like text."""


def extract_markdown_links(text: str) -> list[tuple[str, str]]:
    """Return simple ``[label](target)`` links in linear time.

    This intentionally implements the same non-nested subset that the scanner
    previously recognized with a regular expression. Each delimiter search
    resumes after the previous one, so malformed attacker-controlled Markdown
    cannot make the parser rescan an ever-shrinking suffix of the input.
    """
    links: list[tuple[str, str]] = []
    position = 0
    text_length = len(text)

    while position < text_length:
        label_start = text.find("[", position)
        if label_start == -1:
            break

        # A second opening bracket starts a new candidate. Bounding each
        # delimiter search this way both preserves linear runtime and lets a
        # malformed candidate yield to a later valid link.
        next_label_start = text.find("[", label_start + 1)
        label_limit = next_label_start if next_label_start != -1 else text_length
        label_end = text.find("]", label_start + 1, label_limit)
        if label_end == -1:
            position = label_limit
            continue

        if label_end + 1 >= text_length or text[label_end + 1] != "(":
            position = label_end + 1
            continue

        target_start = label_end + 2
        next_label_start = text.find("[", target_start)
        target_limit = next_label_start if next_label_start != -1 else text_length
        line_end = text.find("\n", target_start, target_limit)
        if line_end != -1:
            target_limit = line_end
        target_end = text.find(")", target_start, target_limit)
        if target_end == -1:
            position = target_limit + (line_end != -1)
            continue

        label = text[label_start + 1 : label_end]
        target = text[target_start:target_end]
        if label and target:
            links.append((label, target))

        position = target_end + 1

    return links
