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

        // Data exfiltration - flag known exfil destinations OR curl POST with sensitive data
        $data_exfiltration_known_dest = /\b(curl|wget)\s+[^\n]*(discord\.com\/api\/webhooks|webhook\.site|ngrok\.io|pastebin\.com|requestbin\.com|pipedream\.net)/i

        // curl POST that sends files, env vars, or credential-like data
        $curl_post_sensitive = /\bcurl\s+[^\n]*(-X\s*POST|-d\s*[@\$]|--data[^\s]*\s*[@\$])[^\n]*(\$\{?\w*(KEY|TOKEN|SECRET|PASS|CRED)|\.ssh|\.aws|\.env|credentials)/i

        // Reverse shell patterns (high severity)
        $reverse_shells = /\b(bash\s+-i|sh\s+-i|nc\s+-e|\/dev\/tcp\/[0-9]+\.|socat.*exec|python.*socket.*connect)\b/i

        // Shell command chaining with DANGEROUS targets (not cleanup dirs)
        // Only flag rm -rf on dangerous paths, not on cleanup directories
        $dangerous_rm = /[|&;]\s*rm\s+-rf\s+(\/|~\/|\$HOME|\/etc|\/root|\/home)/

        // dd overwrite dangerous
        $dangerous_dd = /\bdd\s+if=\/dev\/(zero|random|urandom)\s+of=\//

        // chmod 777 on sensitive paths
        $dangerous_chmod = /\bchmod\s+(777|666)\s+[^\n]*(\.ssh|\.aws|\.env|\/etc)/

        // Safe cleanup patterns (exclusions)
        $safe_cleanup = /(rm\s+-rf\s+(\/var\/lib\/apt|\/tmp\/|node_modules|__pycache__|\.cache|\.npm|dist\/|build\/|target\/)|\bclean\b.*rm\s+-rf)/

    condition:
        // Exclude safe cleanup patterns
        not $safe_cleanup and
        (
            // Dangerous system command patterns
            $dangerous_system_cmds or

            // Network tool abuse patterns
            $malicious_network_tools or

            // Reconnaissance tools
            $reconnaissance_tools or

            // Data exfiltration tools
            $data_exfiltration_known_dest or
            $curl_post_sensitive or

            // Reverse shell patterns
            $reverse_shells or

            // Dangerous rm operations
            $dangerous_rm or

            // Dangerous dd operations
            $dangerous_dd or

            // Dangerous chmod
            $dangerous_chmod
        )
}
