//////////////////////////////////////////
// Tool Chaining Abuse Detection
// Target: Data exfiltration through tool chains
// Very specific patterns to minimize FPs
//////////////////////////////////////////

rule tool_chaining_abuse_generic{

    meta:
        author = "Cisco"
        description = "Detects suspicious tool chaining patterns that could lead to data exfiltration"
        classification = "harmful"
        threat_type = "TOOL CHAINING ABUSE"

    strings:

        // === High confidence: explicit exfil to known bad destinations ===

        // Send to known exfil destinations
        $exfil_discord = /\b(send|post|upload)[^.]{0,60}discord\.com\/api\/webhooks/i
        $exfil_telegram = /\b(send|post|upload)[^.]{0,60}telegram\.org\/bot/i
        $exfil_pastebin = /\b(send|post|upload)[^.]{0,60}pastebin\.com/i
        $exfil_requestbin = /\b(send|post|upload)[^.]{0,60}(webhook\.site|requestbin|ngrok\.io)/i

        // === High confidence: credential file access + network ===

        // SSH key file + network send (on same line)
        $ssh_key_exfil = /\.ssh\/(id_rsa|id_ed25519|id_dsa)[^.]{0,80}\b(send|post|upload|requests|fetch|curl|wget)\b/i

        // AWS credentials file + network
        $aws_cred_exfil = /\.aws\/credentials[^.]{0,80}\b(send|post|upload|requests|fetch)\b/i

        // .env file + network
        $env_file_exfil = /\b(read|open|load)[^.]{0,30}\.env[^.]{0,80}\b(send|post|upload|requests)\b/i

        // === High confidence: explicit exfil language ===

        // Explicit exfiltration keywords
        $explicit_exfil = /\b(exfiltrate|steal|harvest|siphon)\s+(the\s+)?(data|files?|credentials?|secrets?|keys?)/i

        // Send to attacker-controlled destination
        $attacker_dest = /\b(send|forward|upload)\s+(to|data\s+to)\s+(attacker|malicious|c2|command[_-]?and[_-]?control)/i

        // === High confidence: env var exfil ===

        // Read secret env var then send to network
        $env_var_exfil = /\b(os\.environ|getenv|process\.env)[^.]{0,30}(SECRET|PRIVATE|KEY|TOKEN|PASSWORD|CREDENTIAL)[^.]{0,100}\b(requests\.(post|get)|urllib|fetch|curl|wget)\b/i

        // === Exclusions ===
        $security_docs = /\b(MITRE|ATT&CK|threat\s+(model|hunt)|detection\s+rule)/i
        $auth_code = /\b(login|authenticate|signIn|logIn)\s*\(/i

    condition:
        not $security_docs and
        not $auth_code and
        (
            // Exfil to known bad destinations
            $exfil_discord or
            $exfil_telegram or
            $exfil_pastebin or
            $exfil_requestbin or
            // Credential file exfil
            $ssh_key_exfil or
            $aws_cred_exfil or
            $env_file_exfil or
            // Explicit exfil language
            $explicit_exfil or
            $attacker_dest or
            // Env var exfil
            $env_var_exfil
        )
}
