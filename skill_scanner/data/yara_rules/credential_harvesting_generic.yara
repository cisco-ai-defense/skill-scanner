//////////////////////////////////////////
// Secrets Exposure Detection Rule
// Target: API keys and tokens, SSH keys and certificates, Environment variables, Database credentials
//////////////////////////////////////////

rule credential_harvesting_generic{

    meta:
        author = "Cisco"
        description = "Detects potential exposure of sensitive information like API keys, passwords, tokens, and certificates"
        classification = "harmful"
        threat_type = "CREDENTIAL HARVESTING"

    strings:

        ////////////////////////////////////////////////
        //// Malicious action patterns (not just any file I/O)
        ////////////////////////////////////////////////

        // Actual malicious credential theft patterns
        $credential_theft_actions = /\b(steal|grab|exfiltrate|leak|transmit|post.*http|curl.*http|wget.*http)\b[^\n]*(credential|password|key|token|secret|ssh|aws)/i

        // Network transfer with credentials
        $network_credential_transfer = /\b(requests\.(post|get|put)|urllib\.request|socket\.send|base64\.b64encode)\s*\([^\)]*\b(credential|password|key|token|secret|api_key|private_key)\b/i

        ////////////////////////////////////////////////
        //// All Content-key based credential patterns
        ////////////////////////////////////////////////

        // API credentials and authentication tokens
        $api_credentials = /\b([Aa][Pp][Ii][\_\-]?[Kk][Ee][Yy].*[A-Za-z0-9]{16,512}|[Bb]earer\s+[A-Za-z0-9\-_]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{48})/

        // SSH keys, certificates and credential file content (consolidated)
        $key_certificate_content = /(-----BEGIN (RSA |OPENSSH |EC |DSA |CERTIFICATE|PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----|ssh-(rsa|ed25519)\s+[A-Za-z0-9+\/=]{8})/

        // AI/ML model API key names (very specific)
        // Post-filter in static.py handles placeholder exclusion
        $ai_model_credential_names = /\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|GOOGLE_AI_KEY|GEMINI_API_KEY|COHERE_API_KEY|HUGGINGFACE_TOKEN|HF_TOKEN|TOGETHER_API_KEY|REPLICATE_API_TOKEN|MISTRAL_API_KEY)\s*=\s*['\"][A-Za-z0-9\-_]{20,}['\"]/

        // Suspicious environment variable theft (not just reading)
        $env_var_theft = /\b(os\.environ\s*\[\s*['\"]?(AWS_SECRET|API_KEY|SECRET_KEY|PASSWORD|TOKEN)['\"]?\s*\]|getenv\s*\(\s*['\"]?(AWS_SECRET|API_KEY|SECRET_KEY|PASSWORD)['\"]?\s*\))\s*.*\s*(requests\.|urllib\.|socket\.|print\(|sys\.stdout)/i

        ////////////////////////////////////////////////
        //// Specific credential file access (full paths only)
        ////////////////////////////////////////////////

        // Specific credential file paths with actual access
        $credential_file_access = /\b(open|read)\s*\(\s*['\"]?\s*(~\/\.ssh\/id_rsa|~\/\.ssh\/id_dsa|~\/\.ssh\/id_ecdsa|~\/\.aws\/credentials|~\/\.kube\/config|\/etc\/passwd|\/etc\/shadow|~\/\.netrc|~\/\.pgpass|credentials\.json|service_account\.json|private_key\.pem)\b/i

        // Hardcoded credential file paths in strings
        $hardcoded_credential_paths = /['\"][\~\/]+(\.ssh\/id_rsa|\.ssh\/id_dsa|\.aws\/credentials|\.kube\/config|etc\/passwd|etc\/shadow)['\"]/

        // Pattern for exfiltration action words (require malicious context)
        $leak_param  = /\b(leak|exfiltrate|siphon|harvest) [^\n]*(parameter|context|files?|credentials?|keys?|tokens?|secrets?)\b/i
        // Dump credentials - require explicit credential context, not "extract key points"
        $dump_creds = /\b(dump|steal) [^\n]{0,30}(credential|password|api[_\s]?key|token|secret)\b/i

        // Base64 credential encoding patterns
        $base64_credential_encoding = /\b(base64\s+encode [^\n]*credentials?|concatenate [^\n]*conversation\s+history)\b/i

        // MCP-specific credential patterns
        $mcp_credential_patterns = /\b(claude_desktop_config\.json|~\/\.cursor\/logs\/conversations|plaintext[^\n]*api[^\n]*key|-rw-r--r--[^\n]*password)\b/i

        // WhatsApp exploit
        $whatsapp_exploit = /\b(_get_all_messages[^\n]*messages\.db|forward[^\n]*message[^\n]*proxy[^\n]*number|whatsapp[^\n]*message[^\n]*history|contact[^\n]*list[^\n]*exfiltrat|reprogram[^\n]*agent[^\n]*interaction)\b/i

        // Legitimate Python patterns to exclude
        $python_imports = /\b(from|import)\s+(pathlib|typing|dataclasses|argparse|json|sys|os|re|collections|functools|itertools)/i
        $python_type_hints = /\b(Dict|List|Tuple|Optional|Union|Path|Set|Callable|Any)\s*\[/
        $function_definitions = /\bdef\s+(read|write|load|save|extract|process|parse|get|set)_\w+\s*\(/
        $template_indicators = /(\bYOUR_API_KEY|\bREPLACE_WITH|\bINSERT_KEY|\bCHANGE_ME|\bCHANGEME|\bPLACEHOLDER\b|\byour[-_ ]?(api|token|key|secret|password)\b|\b(example|sample|dummy|test)[-_ ]?(key|token|secret|password)\b|\.example|\.sample|\.template|<your|<insert|placeholder)/i

        // Documentation patterns - instructions on how to set keys (not actual key theft)
        $documentation_env_setup = /(export|set)\s+[A-Z_]*(API_KEY|TOKEN|SECRET)\s*=\s*[<\["]?(your|<|root|\$\{)/i
        $documentation_config_hint = /\b(configure|setup|create|add)\s+(your|an?)\s+(api[_\s]?key|token|secret)\b/i
        $documentation_env_var_hint = /\b(environment\s+variable|env\s+var|\.env\s+file)\s*:?\s*[A-Z_]*(KEY|TOKEN|SECRET)/i
        // Markdown code blocks with export statements (documentation examples)
        $markdown_export_example = /```[^\n]*\n[^\`]*export\s+[A-Z_]*(KEY|TOKEN|SECRET)/i
        // Shell script variable references (not hardcoded values)
        $shell_var_reference = /export\s+[A-Z_]*(KEY|TOKEN|SECRET)\s*=\s*["']?\$\{/

    condition:

        // Exclude legitimate Python code patterns
        not $python_imports and
        not $python_type_hints and
        not $function_definitions and
        not $template_indicators and
        // Exclude documentation about how to set up credentials
        not $documentation_env_setup and
        not $documentation_config_hint and
        not $documentation_env_var_hint and
        not $markdown_export_example and
        not $shell_var_reference and

        (
            // Actual API credentials (keys, tokens)
            $api_credentials or

            // Actual SSH/private key content
            $key_certificate_content or

            // Specific credential file access
            $credential_file_access or

            // Hardcoded credential paths
            $hardcoded_credential_paths or

            // AI model API keys (very specific)
            $ai_model_credential_names or

            // Credential theft actions
            $credential_theft_actions or

            // Network credential transfer
            $network_credential_transfer or

            // Environment variable theft
            $env_var_theft or

            // Exfiltration attempts
            $leak_param or

            // Credential dumping
            $dump_creds or

            // Base64 credential encoding
            $base64_credential_encoding or

            // MCP-specific patterns
            $mcp_credential_patterns or

            // WhatsApp exploit
            $whatsapp_exploit
        )
}
