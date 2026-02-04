//////////////////////////////////////////
// Code Execution Detection Rule for Agent Skills
// Target: Python and Bash execution patterns
// (eval, exec, subprocess, shell injection)
/////////////////////////////////////////

rule code_execution_generic{

    meta:

        author = "Cisco"
        description = "Detects dangerous code execution patterns in agent skills (Python/Bash)"
        classification = "harmful"
        threat_type = "CODE EXECUTION"

    strings:

        // Python dangerous execution (eval, exec with actual content)
        $python_eval_exec = /\b(eval|exec)\s*\([^)]{5,}\)/i

        // Python system/subprocess execution
        $python_system_calls = /\b(os\.(system|popen|execv?p?e?|spawnv?p?e?)|subprocess\.(run|call|Popen|check_output))\s*\(/i

        // Python __import__ with user input
        $python_import_abuse = /\b__import__\s*\([^)]*input/i

        // Bash shell execution with variables
        $bash_shell_exec = /\b(system|exec|popen|spawn)\s*\([^)]*[\$\{]/i

        // Base64 decode followed by exec/eval (obfuscation)
        $obfuscated_execution = /\b(base64\.b64decode|decode\(|atob)\s*\([^)]+\)[\s\n]*.*\b(eval|exec|os\.system|subprocess)\s*\(/i

        // Shell command injection patterns
        $shell_injection = /[\"|\']\s*[;&|]\s*(rm|wget|curl|nc|bash|sh|python)\s+/

        // Pickle deserialization (unsafe)
        $unsafe_deserialize = /\bpickle\.(loads?|load)\s*\(/i

    condition:

        // Python eval/exec with content
        $python_eval_exec or

        // Python system calls
        $python_system_calls or

        // Python import abuse
        $python_import_abuse or

        // Bash shell execution
        $bash_shell_exec or

        // Obfuscated execution
        $obfuscated_execution or

        // Shell injection
        $shell_injection or

        // Unsafe deserialization
        $unsafe_deserialize
}
