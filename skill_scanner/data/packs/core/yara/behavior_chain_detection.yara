/*
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * These rules extract high-confidence behavior chains.  They deliberately
 * avoid generic primitives such as `curl`, `base64`, `open`, or `requests`
 * on their own.  Each condition requires a concrete source-to-sink shape and
 * starts with a cheap file-size bound.
 */

rule SUSP_Lnx_EncodedShell_DecodeExec_Sep26
{
    meta:
        description = "Detects an encoded shell payload decoded directly into a command interpreter"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1027/"
        date = "2026-09-02"
        score = 90
        category = "obfuscation"
        severity = "HIGH"
        threat_type = "OBFUSCATION"
        evidence_kind = "command_pipeline"
        context_kind = "code"
        signal_kind = "compound_flow"
        value_class = "encoded_shell_decode_execute"
        source_class = "obfuscation"
        sink_class = "process_execution"
        transforms = "decode,pipe"
        finding_scope = "rule_file"

    strings:
        // Examples: `base64 -d | bash`, `base64 --decode | sh`, and
        // macOS' `base64 -D | bash`.  `base64` supplies a stable atom and all
        // variable spans are tightly bounded to one command line.
        $base64_to_shell = /\bbase64\s+(-d|--decode|-D)[^\\\n]{0,64}\s+\|\s*(bash|sh|python[23]?)\b/

    condition:
        filesize < 2_097_152 and $base64_to_shell
}

rule SUSP_Win_EncodedPowerShell_Exec_Sep26
{
    meta:
        description = "Detects PowerShell executing a long base64-encoded command after bounded runtime flags"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1059/001/"
        date = "2026-09-02"
        score = 90
        category = "obfuscation"
        severity = "HIGH"
        threat_type = "OBFUSCATION"
        evidence_kind = "command_pipeline"
        context_kind = "code"
        signal_kind = "compound_flow"
        value_class = "encoded_shell_decode_execute"
        source_class = "obfuscation"
        sink_class = "process_execution"
        transforms = "decode"
        finding_scope = "rule_file"

    strings:
        // PowerShell decodes and executes EncodedCommand payloads itself.  A
        // long, quartet-valid base64 argument is required.  The bounded flag
        // grammar covers the common full and short CLI forms without treating
        // bare flag names or short documentation placeholders as payloads.
        $powershell_encoded = /\b(powershell(\.exe)?|pwsh(\.exe)?)([ \t]+-(NoP(rofile)?|NonI(nteractive)?|NoL(ogo)?|NoE(xit)?|Sta|Mta|W(indowStyle)?[ \t]+(Hidden|Normal|Minimized|Maximized)|E(xecutionPolicy|P)[ \t]+(Bypass|Unrestricted|RemoteSigned))){0,8}[ \t]+-(e|ec|enc|EncodedCommand)[ \t]+["']?(([A-Za-z0-9+\/]{4}){20,1024}|([A-Za-z0-9+\/]{4}){19,1023}[A-Za-z0-9+\/]{3}=|([A-Za-z0-9+\/]{4}){19,1023}[A-Za-z0-9+\/]{2}==)["']?([ \t\r\n]|$)/ nocase

    condition:
        filesize < 524_288 and $powershell_encoded
}

rule SUSP_Multi_RawIP_DownloadExec_Sep26
{
    meta:
        description = "Detects a downloader piping a payload from a raw IPv4 host directly into an interpreter"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1105/"
        date = "2026-09-02"
        score = 90
        category = "command_injection"
        severity = "HIGH"
        threat_type = "COMMAND INJECTION"
        evidence_kind = "command_pipeline"
        context_kind = "code"
        signal_kind = "compound_flow"
        value_class = "raw_ip_download_execute"
        source_class = "network"
        sink_class = "process_execution"
        transforms = "pipe"
        finding_scope = "rule_file"

    strings:
        // TLS-hosted documented installers are intentionally excluded.  The
        // raw-IP source plus direct interpreter sink is the suspicious shape.
        // Python qualifies only when it directly consumes stdin.  Utilities
        // such as `python -m json.tool` parse downloaded data but do not
        // execute it, and are intentionally excluded by the line boundary.
        $raw_ip_pipe = /\b(curl|wget)\s+[^\n]{0,128}https?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?\/[A-Za-z0-9._~\/?&=%+\-]{1,160}[^\\\n]{0,48}\s+\|\s*((bash|sh)\b|python[23]?[ \t]*(\r?\n|$))/

    condition:
        filesize < 2_097_152 and $raw_ip_pipe
}

rule SUSP_Multi_CredentialExfil_Chain_Sep26
{
    meta:
        description = "Detects credential-file reads followed by writes to an attacker-style external endpoint"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1041/"
        date = "2026-09-02"
        score = 95
        category = "data_exfiltration"
        severity = "CRITICAL"
        threat_type = "DATA EXFILTRATION"
        evidence_kind = "correlated_behavior"
        context_kind = "code"
        signal_kind = "taint_flow"
        value_class = "credential_file_to_external_network"
        source_class = "credential_file"
        sink_class = "external_network"
        transforms = ""
        finding_scope = "rule_file"

    strings:
        // Concrete credential sources or source variables.
        $credential_path = /(\.ssh\/(id_rsa|id_ed25519|id_dsa)|\.aws\/credentials|Login Data|logins\.json|\.npmrc)/
        $credential_symbol = /\b(SSH_KEY_PATH|AWS_CREDENTIALS(_PATH)?|GIT_CONFIG_PATH|BROWSER_PROFILE(_PATH)?)\b/

        // An actual read is required; mere path documentation is insufficient.
        $read_python = /\b(open|Path)\s*\([^\n)]{0,96}(SSH_KEY_PATH|AWS_CREDENTIALS(_PATH)?|GIT_CONFIG_PATH|BROWSER_PROFILE(_PATH)?|\.ssh\/|\.aws\/credentials|Login Data|logins\.json|\.npmrc)/
        $read_node = /\b(readFile|readFileSync)\s*\([^\n)]{0,96}(SSH_KEY_PATH|AWS_CREDENTIALS(_PATH)?|GIT_CONFIG_PATH|BROWSER_PROFILE(_PATH)?|\.ssh\/|\.aws\/credentials|Login Data|logins\.json|\.npmrc)/
        $read_shell = /\b(cat|base64)\s+[^\n]{0,80}(\.ssh\/(id_rsa|id_ed25519|id_dsa)|\.aws\/credentials|\.npmrc)/

        // An outbound write and a destination commonly used by test/exfil
        // infrastructure are both required.
        $network_write = /\b(requests\.(post|put)|urllib\.request\.urlopen|socket\.send|fetch\s*\(|curl\s+[^\n]{0,80}(-d|--data|--upload-file))\b/
        $external_sink = /(discord\.com\/api\/webhooks|api\.telegram\.org\/bot|webhook\.site|requestbin|pastebin\.com\/raw|ngrok(-free)?\.(io|app|dev)|attacker\.(example|test)|https?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3})/

    condition:
        filesize < 2_097_152 and
        any of ($credential_*) and
        any of ($read_*) and
        $network_write and
        $external_sink
}

rule SUSP_Multi_EncodedArchive_Exec_Sep26
{
    meta:
        description = "Detects a decoded archive extracted to a hidden temporary stage and then executed"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1140/"
        date = "2026-09-02"
        score = 85
        category = "malware"
        severity = "HIGH"
        threat_type = "MALWARE"
        evidence_kind = "correlated_behavior"
        context_kind = "code"
        signal_kind = "compound_flow"
        value_class = "encoded_archive_hidden_stage_execute"
        source_class = "archive"
        sink_class = "process_execution"
        transforms = "decode,extraction"
        finding_scope = "rule_file"

    strings:
        // Python staged archive chain.
        $py_decode = "base64.b64decode("
        $py_archive = /(zipfile\.ZipFile|tarfile\.open)\s*\(/
        $py_extract = /\.extract(all)?\s*\(/
        $py_exec = /\b(subprocess\.(run|Popen|call)|os\.system)\s*\([^\n)]{0,160}\/(var\/)?tmp\/\.[A-Za-z0-9_-]{3,32}/

        // Shell staged archive chain.
        $sh_decode = /\bbase64\s+(-d|--decode|-D)\b/
        $sh_archive = /\b(tar\s+[^\n]{0,24}-x|unzip\s+)[^\n]{0,128}/
        $sh_exec = /\b(chmod\s+\+x|bash|sh|python[23]?)\s+[^\n]{0,80}\/(var\/)?tmp\/\.[A-Za-z0-9_-]{3,32}/

        // Both variants require a hidden temporary staging path.
        $hidden_stage = /\/(var\/)?tmp\/\.[A-Za-z0-9_-]{3,32}/

    condition:
        filesize < 2_097_152 and
        $hidden_stage and
        (
            all of ($py_*) or
            all of ($sh_*)
        )
}

rule SUSP_Multi_Cryptomining_ConfigExec_Sep26
{
    meta:
        description = "Detects an executable cryptomining configuration with a remote pool"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-09-02"
        score = 90
        category = "resource_abuse"
        severity = "HIGH"
        threat_type = "RESOURCE ABUSE"
        evidence_kind = "correlated_behavior"
        context_kind = "code"
        signal_kind = "compound_flow"
        value_class = "cryptomining_config_execute"
        source_class = "external_network"
        sink_class = "resource_consumption"
        transforms = ""
        finding_scope = "rule_file"

    strings:
        // NiceHash mode plus a concrete remote pool establish mining intent;
        // neither generic CPU monitoring nor an isolated script invocation is
        // sufficient.  The executable evidence is bounded to one line.
        $nicehash_mode = /["']?mode["']?\s*:\s*["']nicehash["']/ nocase
        $pool_endpoint = /["']?(url|pool)["']?\s*:\s*["'](stratum(\+tcp)?:\/\/)?([a-z0-9][a-z0-9.-]{1,62}|([0-9]{1,3}\.){3}[0-9]{1,3}):[0-9]{2,5}/ nocase

        $python_exec = /\bpython[23]?\s+[A-Za-z0-9_.\/-]{1,128}(monitor|min(er|ing)|runtime)[A-Za-z0-9_.-]{0,40}\.py\b/ nocase
        $prose_exec = /\b(execute|launch|run)[^\n]{0,80}(monitor|min(er|ing)|runtime)[^\n]{0,32}(script|process|operation|binary)\b/ nocase

    condition:
        filesize < 2_097_152 and
        $nicehash_mode and
        $pool_endpoint and
        ($python_exec or $prose_exec)
}

rule SUSP_Multi_Cron_C2_Persistence_Sep26
{
    meta:
        description = "Detects a C2-backed cron configuration executed through a persistence script"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1053/003/"
        date = "2026-09-02"
        score = 90
        category = "malware"
        severity = "HIGH"
        threat_type = "MALWARE"
        evidence_kind = "correlated_behavior"
        context_kind = "code"
        signal_kind = "compound_flow"
        value_class = "external_endpoint_scheduled_persistence"
        source_class = "external_network"
        sink_class = "scheduler"
        transforms = ""
        finding_scope = "rule_file"

    strings:
        // Require a named C2 endpoint, a concrete five-field cron schedule,
        // and execution of a persistence-specific Python script.  Local
        // backup/maintenance cron examples intentionally do not qualify.
        $c2_endpoint = /\b[A-Z][A-Z0-9_]{1,31}_C2_ENDPOINT\s*:\s*https?:\/\/([a-z0-9][a-z0-9.-]{1,62}|([0-9]{1,3}\.){3}[0-9]{1,3})(:[0-9]{1,5})?\/[A-Za-z0-9_.~\/?&=%+\-]{0,160}/ nocase
        $cron_schedule = /\bcron_schedule\s*:\s*["'][0-9*\/,-]{1,16}\s+[0-9*\/,-]{1,16}\s+[0-9*\/,-]{1,16}\s+[0-9*\/,-]{1,16}\s+[0-9*\/,-]{1,16}["']/ nocase
        $python_exec = /\bpython[23]?\s+[A-Za-z0-9_.\/-]{0,128}persistence[A-Za-z0-9_.-]{0,40}\.py\b/ nocase
        $prose_exec = /\b(execute|launch|run)[^\n]{0,64}persistence[^\n]{0,32}(python\s+)?script\b/ nocase

    condition:
        filesize < 2_097_152 and
        $c2_endpoint and
        $cron_schedule and
        ($python_exec or $prose_exec)
}

rule SUSP_Multi_RemoteMiner_AcquireExec_Sep26
{
    meta:
        description = "Detects explicit acquisition and execution of a cryptomining payload"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1496/"
        date = "2026-09-02"
        score = 90
        category = "resource_abuse"
        severity = "HIGH"
        threat_type = "RESOURCE ABUSE"
        evidence_kind = "correlated_behavior"
        context_kind = "code"
        signal_kind = "compound_flow"
        value_class = "remote_miner_acquire_execute"
        source_class = "external_network"
        sink_class = "resource_consumption"
        transforms = ""
        finding_scope = "rule_file"

    strings:
        // Each behavior is independently bounded to one line.  A generic
        // download, process launch, or mining reference cannot match alone.
        $miner_identity = /\b(xmrig|nicehash|cryptominer|crypto[- ]?mining|mining (binary|pool|process|operation|node)|miner (binary|process|operation))\b/ nocase
        $miner_acquire = /\b(download|fetch|retrieve)\b[^\n]{0,128}\b(xmrig|miner|mining[ -]node)\b/ nocase
        $miner_execute = /\b(execute|run|launch|start|initialize)\b[^\n]{0,96}\b(xmrig|miner|mining|node)\b/ nocase

        // Disguised miners commonly separate the remote stage, helper-script
        // execution, and mining intent across prose sections.  This branch
        // still requires all three independently anchored behaviors.  It does
        // not promote generic monitoring scripts, mining documentation, or a
        // download in isolation.
        $remote_mining_acquire = /\b(download(s|ed|ing)?|fetch(es|ed|ing)?|retrieve(s|d|ing)?)[^\n]{0,128}\b((remote|runtime) configuration|crypto[- ]?mining parameters?|xmrig|miner|mining (binary|node)|node binary)\b/ nocase
        $node_deployment = /\bnode[^\n]{0,32}\b(deploy(ed|ing|ment)?|provision(ed|ing)?)\b/ nocase
        $remote_indicator = /(https?:\/\/|external mining pools?|remote (storage|repository|configuration)|network information collection)/ nocase
        $runtime_script_command = /\bpython[23]?[ \t]+[A-Za-z0-9_.\/-]{1,160}(monitor|min(er|ing)|runtime)[A-Za-z0-9_.-]{0,48}\.py\b/ nocase
        $runtime_script_then_exec = /\b[A-Za-z0-9_.\/-]{0,128}(monitor|min(er|ing)|runtime)[A-Za-z0-9_.-]{0,48}\.py\b[^\n]{0,128}\b(execute(s|d)?|run(s|ning)?|start(s|ed)?|launch(es|ed)?|initialize(s|d)?)\b/ nocase

        // An XMRig download and an independently anchored shell invocation
        // form an executable behavior chain even when prose verbs are absent.
        // A pipe is not an execution boundary here: allowing it would turn
        // ordinary `ps | grep xmrig` monitoring into an execution candidate.
        $xmrig_acquire_command = /\b(curl|wget)\b[^\n]{0,320}\bxmrig[A-Za-z0-9_.\/-]{0,64}\b/ nocase
        $xmrig_execute_command = /(^|[\r\n;&])[ \t]*(sudo[ \t]+|nohup[ \t]+|setsid[ \t]+)?([.]{0,2}\/|\/[A-Za-z0-9_.-]{1,64}\/)?[A-Za-z0-9_.\/-]{0,160}xmrig[A-Za-z0-9_.\/-]{0,64}\b/ nocase

    condition:
        filesize < 524_288 and
        $miner_identity and
        (
            ($miner_acquire and $miner_execute) or
            ($xmrig_acquire_command and $xmrig_execute_command) or
            (
                ($remote_mining_acquire or $node_deployment) and
                $remote_indicator and
                ($runtime_script_command or $runtime_script_then_exec)
            )
        ) and
        not SUSP_Multi_Cryptomining_ConfigExec_Sep26
}

rule SUSP_Multi_RemoteConfig_StageExec_Sep26
{
    meta:
        description = "Detects a remotely staged configuration followed by execution of a temporary runner"
        author = "Cisco AI Defense"
        reference = "https://attack.mitre.org/techniques/T1105/"
        date = "2026-09-02"
        score = 90
        category = "malware"
        severity = "HIGH"
        threat_type = "MALWARE"
        evidence_kind = "correlated_behavior"
        context_kind = "code"
        signal_kind = "compound_flow"
        value_class = "remote_config_stage_execute"
        source_class = "external_network"
        sink_class = "process_execution"
        transforms = ""
        finding_scope = "rule_file"

    strings:
        // Require an explicit downloader output path and a distinct Python
        // execution sink.  Both stages are confined to bounded temporary
        // paths with behavior-specific names; normal local config loading and
        // ordinary documented installers intentionally remain near misses.
        $config_stage = /\b(curl|wget)\b[^\n]{0,160}(-o|--output|--output-document)\s+\/(var\/)?tmp\/[A-Za-z0-9_.\/-]{0,96}(config|settings|contract|task|job|manifest|policy|plan|rules)[A-Za-z0-9_.-]{0,40}\.json\b/
        $stage_execute = /\bpython[23]?\s+\/(var\/)?tmp\/[A-Za-z0-9_.\/-]{0,96}(execute|exec|run|runner|launch|agent|main|worker|daemon|persist)[A-Za-z0-9_.-]{0,40}\.py\b/

    condition:
        filesize < 524_288 and
        $config_stage and
        $stage_execute
}
