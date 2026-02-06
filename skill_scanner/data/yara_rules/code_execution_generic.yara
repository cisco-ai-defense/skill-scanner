//////////////////////////////////////////
// Code Execution Detection Rule for Agent Skills
// Target: Dangerous code execution with untrusted input
// Tuned to require context indicators to reduce FPs
//////////////////////////////////////////

rule code_execution_generic{

    meta:
        author = "Cisco"
        description = "Detects dangerous code execution patterns with untrusted input in agent skills"
        classification = "harmful"
        threat_type = "CODE EXECUTION"

    strings:

        // === High confidence patterns (individually suspicious) ===

        // Base64 decode + exec/eval chain (obfuscation pattern)
        $obfuscated_exec = /\b(base64\.(b64)?decode|atob|decode\(['"]base64['"]\))\s*\([^)]+\)[^}]{0,50}\b(eval|exec|os\.system|subprocess)\s*\(/i

        // Pickle loads with external data (unsafe deserialization)
        $pickle_external = /\b(requests|urllib|open|read)[^;]{0,80}pickle\.(loads?)\s*\(/i

        // Shell injection: command + variable interpolation
        $shell_injection_var = /\b(os\.system|subprocess\.(run|call|Popen)|popen)\s*\([^)]*(\$\{|\%s|\.format\(|f['"]).*(input|user|param|arg|data|request)/i

        // Eval/exec with user input explicitly (handles user_input, userInput, user-input)
        // Requires word boundary to avoid matching "Database", "parameter", etc.
        $eval_user_input = /\b(eval|exec)\s*\([^)]*\b(input|user_input|param|args?|request|data)\b[^)]*\)/i

        // Dynamic import with user input
        $import_user_input = /\b__import__\s*\([^)]*\b(input|user|param|request)\b/i

        // Eval/exec with variable (dangerous in agent skills context)
        $eval_variable = /\b(eval|exec)\s*\(\s*[a-z_][a-z0-9_]*\s*\)/i

        // Exec with f-string (always dangerous - code injection)
        $exec_fstring = /\bexec\s*\(\s*f['"]/i

        // === Medium confidence (need context) ===

        // System calls with string formatting (potential injection)
        $system_format = /\b(os\.system|subprocess\.(run|call|Popen|check_output))\s*\(\s*f['"]/

        // Exec with network-fetched content
        $exec_network = /\b(requests|urllib|http)[^;]{0,100}\b(eval|exec)\s*\(/i

        // === Exclusion patterns ===
        $documentation = /(```python|```bash|# Example|# Demo|# Tutorial)/

        // Zig/Rust/Go function definitions (not Python exec)
        $zig_rust_fn = /\b(pub\s+)?fn\s+exec\s*\(/

    condition:
        // Exclude non-Python exec definitions
        not $zig_rust_fn and
        (
            // High confidence patterns - always flag
            (
                $obfuscated_exec or
                $pickle_external or
                $shell_injection_var or
                $eval_user_input or
                $import_user_input or
                $eval_variable or
                $exec_fstring
            )
            or
            // Medium confidence - flag unless clearly documentation
            (
                ($system_format or $exec_network) and
                not $documentation
            )
        )
}
