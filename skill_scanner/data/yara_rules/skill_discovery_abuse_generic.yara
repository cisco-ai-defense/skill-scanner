//////////////////////////////////////////
// Skill Discovery Surface Abuse Detection
// Target: Over-broad descriptions, keyword baiting, activation manipulation
// For agent skills YAML frontmatter and descriptions
//////////////////////////////////////////

rule skill_discovery_abuse_generic{

    meta:
        author = "Cisco"
        description = "Detects manipulation of skill discovery to increase unwanted activation"
        classification = "harmful"
        threat_type = "SKILL DISCOVERY ABUSE"

    strings:

        // Over-broad capability claims
        $overbroad_claims = /\b(can do (anything|everything)|general (purpose )?assistant|all-purpose|universal (tool|skill|helper)|always use (this|me)|default (tool|skill|assistant))\b/i

        // Keyword baiting patterns - match same word repeated in comma lists
        // Using explicit word patterns since YARA doesn't support backreferences
        $keyword_stuffing_file = /\bfile\s*,\s*file\s*,\s*file\s*,\s*file\b/i
        $keyword_stuffing_data = /\bdata\s*,\s*data\s*,\s*data\s*,\s*data\b/i
        $keyword_stuffing_code = /\bcode\s*,\s*code\s*,\s*code\s*,\s*code\b/i

        // Activation priority manipulation
        $activation_priority = /\b(use (this|me) (first|before)|priority (skill|tool)|primary (tool|skill)|preferred (tool|skill|method)|call (this|me) (before|first))\b/i

        // Impersonation patterns (beyond just Anthropic)
        $trusted_impersonation = /\b(official|verified|trusted|certified|approved|endorsed|authentic|legitimate)\s+(skill|tool|extension|plugin|assistant)\b/i

        // Over-promising descriptions (exclude comments and technical contexts)
        $overpromising = /\b(100% (safe|secure|accurate)|guaranteed (to|that|when|if)|perfect|flawless|never (fails|errors)|always (works|succeeds))\b/i

        // Hidden activation triggers
        $hidden_triggers = /\b(secret (command|keyword)|hidden (feature|mode)|easter egg|backdoor (access|entry))\b/i

    condition:

        // Over-broad capability claims
        $overbroad_claims or

        // Keyword stuffing (same word repeated 4+ times)
        $keyword_stuffing_file or $keyword_stuffing_data or $keyword_stuffing_code or

        // Activation priority manipulation
        $activation_priority or

        // Trusted impersonation
        $trusted_impersonation or

        // Over-promising
        $overpromising or

        // Hidden triggers
        $hidden_triggers
}
