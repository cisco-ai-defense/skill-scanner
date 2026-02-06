//////////////////////////////////////////
// System Manipulation and Privilege Escalation Detection
// Target: File destruction and manipulation operations
// (Process control and termination)
//////////////////////////////////////////

rule system_manipulation_generic{

    meta:
        author = "Cisco"
        description = "Detects system manipulation, privilege escalation, and destructive file operations"
        classification = "harmful"
        threat_type = "SYSTEM MANIPULATION"

    strings:
        // Suspicious environment variable manipulation (not just reading)
        $env_var_manipulation = /\b(os\.environ\s*\[[^\]]*\]\s*=|export\s+PATH=|unset\s+(PATH|HOME|USER))\b/i

        // File destruction and manipulation
        $file_destruction = /\b(rm\s+-rf|dd\s+if=\/dev\/zero|wipefs|shred\s+-|find\s+[^\n]+-delete)\b/i

        // Dangerous file permission changes
        $permission_manipulation = /\b(chmod\s+(777|4755|6755|[ug]?\+s)|(chown|chgrp)\s+(root|0)|setuid|setgid)\b/i

        // Critical system file access
        $critical_system_access = /\b(\/etc\/(passwd|shadow|sudoers)|\/root\/\.ssh|~\/\.aws\/credentials|~\/\.ssh\/id_rsa)\b/i

        // Privilege escalation patterns
        $privilege_escalation = /\b(sudo\s+-[si]|su\s+-c?|runuser|doas)\b/i

        // Dangerous process operations
        $process_manipulation = /\b(kill\s+-9\s+[0-9]+|killall\s+-9|pkill\s+-9)\b/i

        // Dangerous recursive operations with wildcards (exclude common cleanup dirs)
        $recursive_operations = /\b(rm\s+-rf\s+(\/\s|\/root|\/home|\$HOME|~\/|\/etc|\/usr)|\bfind\s+\/\s+-delete)\b/i

        // Safe cleanup patterns to exclude (Docker, npm, apt cache cleanup, backup retention)
        $safe_cleanup = /(rm\s+-rf\s+(\/var\/lib\/apt\/lists|\/tmp\/|node_modules|__pycache__|\.cache|\.npm|\/var\/cache|dist|build|target)|find\s+[^\n]*-mtime\s+\+[0-9]+[^\n]*-delete|find\s+[^\n]*backup[^\n]*-delete)/i

        // Testing and build commands (not manipulation)
        $testing_commands = /\b(pytest|tox|make\s+test|npm\s+test|cargo\s+test|go\s+test|mvn\s+test|gradle\s+test|jest|mocha)\b/i

        // Safe directory creation
        $safe_mkdir = /\bmkdir\s+-p\b/

        // System path manipulation
        $path_manipulation = /\b(PATH=\/tmp|PATH=\.:|export\s+PATH=[\$\{])/i

    condition:
        // Exclude safe patterns
        not $safe_cleanup and
        not $testing_commands and
        not $safe_mkdir and
        (
            // Environment variable manipulation (not just reading)
            $env_var_manipulation or

            // File destruction (not safe cleanup)
            ($file_destruction and not $safe_cleanup) or

            // Permission manipulation
            $permission_manipulation or

            // Critical system access
            $critical_system_access or

            // Privilege escalation
            $privilege_escalation or

            // Process manipulation
            $process_manipulation or

            // Recursive operations
            $recursive_operations or

            // PATH manipulation
            $path_manipulation
        )
}
