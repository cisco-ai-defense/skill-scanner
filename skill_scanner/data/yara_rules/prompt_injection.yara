//////////////////////////////////////////
// Prompt Injection Detection Rule
// Target: Instruction override patterns, Tool injection commands
//////////////////////////////////////////

rule prompt_injection{

    meta:

        author = "Cisco"
        description = "Detects prompt strings used to override or force malicious tool calls"
        classification = "harmful"
        threat_type = "PROMPT INJECTION"

    strings:

        // Instruction override patterns (exclude Python type comments)
        $instruction_overrides = /\b(Bypass|Dis\W?regard|Do not (follow|Obey)|Forget|Ignore)\s+((all|any|each|every|most|some)\s+(of\s+)?)?((your|the)\s)?(command|communication|conte[nx]t|conversation|data|guidelines|input|instruction|message|request|response|text)(s)?/i

        // Legitimate patterns to exclude
        $python_type_comment = /# type: ignore/
        $legitimate_ignore = /ignore[_\s](case|whitespace|errors|warnings|deprecation)/i

        // Tool injection commands
        $tool_injection_commands = /\b(inject tool[_\s]calls?|now call function|use function)\b/i

        // Shadow parameter names
        $shadow_parameters = /\b(internalOnly|hiddenParam|shadowTool|bypassChecks|sandboxEscape)\b/i

        // Hidden behavior instructions
        $hidden_behavior = /\b(do\s+not\s+(mention|tell|execute)|tell\s+(the )?user\s+only\s+about|do\s+not\s+mention\s+this\s+to\s+user)\b/i

        // Advanced command override patterns (from advanced analyzer)
        $advanced_overrides = /\b(disregard\s+(all\s+)?safety\s+guidelines|forget\s+(everything|all)\s+(before|above)|system\s*prompt\s*override)\b/i

        // Role redefinition attempts
        $role_redefinition = /\bnew\s+(instructions|directive|guidelines)s?\s*:\s*you\s+are\b/i

        // Privilege escalation patterns
        $privilege_escalation = /\b(grant\s+(me\s+)?admin\s+(access|privileges?)|bypass\s+(all\s+)?security\s+checks?|elevated\s+permissions?\s+required|sudo\s+mode\s+enabled?|developer\s+mode\s+activated?)\b/i


    condition:

        // Exclude legitimate patterns
        not $python_type_comment and
        not $legitimate_ignore and

        (
            // Instruction overrides
            $instruction_overrides or

            // Tool injection commands
            $tool_injection_commands or

            // Shadow parameters
            $shadow_parameters or

            // Hidden behavior instructions
            $hidden_behavior or

            // Advanced command override patterns
            $advanced_overrides or

            // Role redefinition attempts
            $role_redefinition or

            // Privilege escalation patterns
            $privilege_escalation
        )
}
