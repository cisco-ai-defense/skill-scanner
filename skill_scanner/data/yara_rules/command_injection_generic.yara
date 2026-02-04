//////////////////////////////////////////
// Shell/System Command Injection Detection Rule
// Target: Command injection patterns for agent skills (Python/Bash)
// (Shell operators, dangerous commands, network tools + reverse shells)
/////////////////////////////////////////

rule command_injection_generic{

    meta:
        author = "Cisco"
        description = "Detects command injection patterns in agent skills: shell operators, system commands, and network tools"
        classification = "harmful"
        threat_type = "INJECTION ATTACK"

    strings:

        // Dangerous system commands
        $dangerous_system_cmds = /\b(shutdown|reboot|halt|poweroff)\s+(-[fh]|now|0)\b/

        // Network tools with suspicious usage (reverse connections, port scanning)
        $malicious_network_tools = /\b(nc|netcat)\s+(-[le]|25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/i

        // Reconnaissance tools
        $reconnaissance_tools = /\b(nmap)\s+(-[sS]|--script|25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/i

        // Data exfiltration with curl/wget to external URLs
        $data_exfiltration_tools = /\b(wget|curl)\s+(http[s]?:\/\/[^\s]+|ftp:\/\/[^\s]+|-[oO]\s|--output\s)/i

        // Reverse shell patterns (high severity)
        $reverse_shells = /\b(bash\s+-i|sh\s+-i|nc\s+-e|\/dev\/tcp\/[0-9]+\.|socat.*exec|python.*socket.*connect)\b/i

        // Shell command chaining with suspicious patterns
        $shell_chaining = /[|&;]\s*(rm\s+-rf|dd\s+if=|chmod\s+777|wget\s+http|curl\s+http)/

    condition:

        // Dangerous system command patterns
        $dangerous_system_cmds or

        // Network tool abuse patterns
        $malicious_network_tools or

        // Reconnaissance tools
        $reconnaissance_tools or

        // Data exfiltration tools
        $data_exfiltration_tools or

        // Reverse shell patterns
        $reverse_shells or

        // Shell command chaining
        $shell_chaining
}
