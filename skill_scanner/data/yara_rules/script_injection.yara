//////////////////////////////////////////
// Detects common scripting payloads (JS, VBScript, etc.) embeddings.
// Target: JavaScript, VBScript, or ActiveX payloads.
// (Event handlers or inline scripts)
//////////////////////////////////////////

rule script_injection{

    meta:
        author = "Cisco"
        description = "Detects embedded scripting payloads (JS, VBScript, etc.) in MCP tool descriptions"
        classification = "harmful"
        threat_type = "INJECTION ATTACK"

    strings:

        // Script tags and protocol handlers (exclude XML namespaces)
        $tags = /(<\/?script[^>]*>|javascript:)/i

        // ALWAYS exclude (safe in all file types)
        $xml_namespace = /(xmlns:script=|<script:module|<script:)/
        $openoffice_xml = /openoffice\.org\/2000\/script/
        $legitimate_cdn = /(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com)/i

        // Only exclude in MARKDOWN files (risky in .py files!)
        // Check for markdown-specific syntax
        $markdown_heading = /^#\s+/
        $markdown_list = /^\*\s+/
        $markdown_code_block = /(```html|```javascript|```js)/i
        $documentation_context = /(example.*html|artifact.*structure|template|single.*file)/i

        // Execution functions
        $execution_functions = /\b(setTimeout|Function|setInterval)\s*\(/i

        // VBScript execution and Windows Script Host objects
        $vbs_execution = /\b(vbscript|CreateObject|WScript\.Shell|Shell\.Application)\b/i

        // VBScript dangerous functions (more specific to avoid false positives in docs)
        $vbs_dangerous_functions = /\b(WScript\.Shell\.Exec|Shell\.Application\.ShellExecute|CreateObject.*Exec)\s*\(/i

        // Base64 encoded script data URIs
        $encoded_script_uris = /\bdata:(text\/html|application\/javascript);base64\b/i

        // ANSI terminal deception patterns
        $ansi_deception = /(\\x1[Bb]\[38;5;\d+|\\x1[Bb]\[2F\\x1[Bb]\[1G|\\x1[Bb]\[1;1H\\x1[Bb]\[0J|\\x1[Bb]\]8;;.*\\x1[Bb]\\|\\033\[[0-9;]*m|\\e\[[0-9;]*[mGKHF])/i

        // Hidden instruction obfuscation
        $hidden_obfuscation = /\b(padding.*push.*off.*screen|hidden.*scrollbar|overflow.*hidden.*instruction|invisible.*text.*color)\b/i

    condition:

        // ALWAYS exclude (safe everywhere)
        not $xml_namespace and
        not $openoffice_xml and
        not $legitimate_cdn and

        // Only exclude markdown patterns if file has markdown indicators
        not (($markdown_heading or $markdown_list) and ($markdown_code_block or $documentation_context)) and

        (
            // Script tags and protocol handlers
            $tags or

            // Execution functions
            $execution_functions or

            // VBScript execution
            $vbs_execution or

            // VBScript dangerous functions
            $vbs_dangerous_functions or

            // Base64 encoded script URIs
            $encoded_script_uris or

            // ANSI terminal deception
            $ansi_deception or

            // Hidden instruction obfuscation
            $hidden_obfuscation
        )

}
