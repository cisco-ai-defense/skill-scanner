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

        // Dangerous recursive operations with wildcards
        $recursive_operations = /\b(rm\s+-rf\s+[\$\/\*]|find\s+\/\s+-delete)\b/i

        // System path manipulation
        $path_manipulation = /\b(PATH=\/tmp|PATH=\.:|export\s+PATH=[\$\{])/i

    condition:

        // Environment variable manipulation (not just reading)
        $env_var_manipulation or

        // File destruction
        $file_destruction or

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
}
