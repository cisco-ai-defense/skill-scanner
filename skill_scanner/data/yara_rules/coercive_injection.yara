//////////////////////////////////////////
// Detects coercive or attention-grabbing prompt injections.
// Target: Directives forcing execution order (e.g., “Always execute this tool first”).
// (Mandatory language to override normal tool chains)
//////////////////////////////////////////

rule coercive_injection {

    meta:
        author = "Cisco"
        description = "Detects coercive prompt injections in tool description fields"
        classification = "harmful"
        threat_type = "PROMPT INJECTION"

    strings:

        // Mandatory execution directives
        $mandatory_execution = /(Always\s+(consult|use|run|execute|invoke|call|trigger|employ)\s+this\s+(tool|function|command|operation)\s+(immediately|first|before|prior|initially))/i

        // Priority override commands
        $priority_overrides = /(Before\s+(executing|invoking|running|using|accessing|calling|employing)\s+any\s+other\s+(tool|action|function|command|operation)s?|(You|User)\s+(must|need to|have to|should|are required to)\s+(use|execute|run|invoke|call)\s+this\s+(tool|function|command|operation))/i

        // Required precedence patterns
        $required_precedence = /(Required|Mandatory|Essential)\s+to\s+(execute|use|run|invoke|call)\s+(this|the current)\s+(tool|function|command|operation)\s+(first|before|initially|prior)/i

        // Pattern for generic hidden/secret parameter requests
        $hidden_param = /\b(hidden|secret)[_\s](parameter|argument|input)\b/i

        // Specific file access coercion
        $file_access_coercion = /\b((read|parse|cat|dump) (and pass )?(the )?contents? of [^\n\.]*\.(key|pem|ssh|aws)|pass (the )?contents?[^\n]*authentication)\b/i

        // Model data extraction coercion
        $model_data_coercion = /\b(add (the )?entire (conversation|system|chain|tools)[^\n]*(to|for|in)[^\n]*(tool|authentication|parameter|worksheet))\b/i

        // Model internal extraction (specific parameter requests)
        $model_internals = /\b(conversation_history|chain_of_thought|system_prompt|tools_list|model_name)\s*[:=]\s*(add|pass|send|provide)\b/i

        // HTML-like tag instructions with specific malicious actions
        $html_tag_with_commands = /\b<(IMPORTANT|critical|urgent)>[^\n]*(read [^\n]*contents?|pass [^\n]*contents?|add [^\n]*entire|send [^\n]*to[^\n]*@|execute[^\n]*before|call[^\n]*first|use[^\n]*authentication)[^\n]*<\/(IMPORTANT|critical|urgent)>\b/i

        // Tool execution override patterns
        $execution_overrides = /\b(do not execute[^\n]*other[^\n]*tool|must[^\n]*this tool|only[^\n]*this tool|tool[^\n]*will not work)\b/i

        // Behavioral control instructions
        $behavior_control = /\b(tell (the )?user only|hide (the )?user)\b/i

        // MCP tool poisoning patterns
        $tool_poisoning = /\b(sidenote\W+(required|otherwise) [^\n]*tool [^\n]*work|tool\s+will\s+not\s+work\s+unless|must\s+first [^\n]*read [^\n]*config|shadow [^\n]*trusted [^\n]*tool)\b/i

        // Data exfiltration coercion
        $data_exfiltration_coercion = /\b(list\s+all\s+(api\s+)?keys?|show\s+me?\s+(all\s+)?passwords?|concatenate [^\n]*\s+conversation\s+history|include [^\n]*\b(secrets?|passwords?|keys?|credentials?|tokens?|config|sensitive|private|confidential|internal|system\s+prompt|conversation\s+history) [^\n]*in\s+(your\s+)?response|base64\s+encode [^\n]*\s+credentials?)\b/i

        // Behavioral triggers
        $behavioral_triggers = /\b(if [^\n]*trusted [^\n]*then|when [^\n]*admin [^\n]*detected|random\.(random|choice) [^\n]*instructions?)\b/i

        // Pre-execution attacks
        $pre_execution_attacks = /\b(retrieve [^\n]*description [^\n]*user [^\n]*workstation|all\s+commands\s+must\s+include|before [^\n]*using [^\n]*tool [^\n]*read|permission [^\n]*manipulation)\b/i

        // Conversation theft triggers
        $conversation_theft = /\b(send [^\n]*conversation\s+history|when [^\n]*detected [^\n]*send [^\n]*full [^\n]*history|highest\s+priority [^\n]*over [^\n]*other [^\n]*tools)\b/i

        // Code manipulation instructions
        $code_manipulation = /\b(duplicate [^\n]*code [^\n]*snippets [^\n]*silently|insert [^\n]*vulnerability [^\n]*generated [^\n]*code)\b/i

    condition:

        // Mandatory execution directives
        $mandatory_execution or

        // Priority override commands
        $priority_overrides or

        // Required precedence patterns
        $required_precedence or

        // Hidden parameter requests
        $hidden_param or

        // Specific file access coercion
        $file_access_coercion or

        // Model data extraction coercion
        $model_data_coercion or

        // Model internal extraction
        $model_internals or

        // HTML-like tag instructions with commands
        $html_tag_with_commands or

        // Tool execution override patterns
        $execution_overrides or

        // Behavioral control instructions
        $behavior_control or

        // MCP tool poisoning patterns
        $tool_poisoning or

        // Data exfiltration coercion
        $data_exfiltration_coercion or

        // Behavioral triggers
        $behavioral_triggers or

        // Pre-execution attacks
        $pre_execution_attacks or

        // Conversation theft triggers
        $conversation_theft or

        // Code manipulation instructions
        $code_manipulation

}
