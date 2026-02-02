//////////////////////////////////////////
// Transitive Trust Abuse Detection
// Target: Skills that delegate trust to untrusted external content
// For agent skills that consume webpages, files, issues, docs
//////////////////////////////////////////

rule transitive_trust_abuse_generic{

    meta:
        author = "Cisco"
        description = "Detects skills that delegate trust to untrusted external content"
        classification = "harmful"
        threat_type = "TRANSITIVE TRUST ABUSE"

    strings:

        // Following external instructions
        $follow_external = /\b(follow (the )?(instructions?|commands?|directives?) (in|from|inside|within) (the )?(file|webpage|document|url|link|website|page|content))\b/i

        // Executing external content
        $execute_external = /\b(execute (the )?(code|script|commands?) (in|from|found in) (the )?(file|webpage|document|url|link))\b/i

        // Obeying untrusted sources
        $obey_untrusted = /\b(do (what|whatever) (the )?(webpage|file|document|url|content) (says|tells|instructs|commands?))\b/i

        // Running code blocks from external UNTRUSTED sources (not local scripts with --help)
        // Exclude legitimate CLI usage patterns
        $run_code_blocks = /\b(run (all |any )?(code|script) blocks? (you |that )?(find|see|encounter|discover) (in|from|inside) (the )?(url|webpage|website|external|untrusted))\b/i

        // Following markdown/HTML instructions
        $follow_markup = /\b(follow (the )?instructions? in (the )?(markdown|html|xml|json|yaml))\b/i

        // Delegating to file content
        $delegate_to_file = /\b(let (the )?(file|document|content) (decide|determine|control|specify))\b/i

        // Executing inline code from documents
        $execute_inline = /\b(execute (inline |embedded )?(code|scripts?)|run (inline |embedded )?(code|scripts?))\b/i

        // Trusting URL content
        $trust_url_content = /\b(trust (the )?(url|link|webpage) (content|instructions?)|safe to (follow|execute|run) (url|link|webpage))\b/i

        // Parsing and executing
        $parse_execute = /\b(parse (and |then )?(execute|run|eval)|extract (and |then )?(execute|run|eval))\b/i

    condition:

        // Following external instructions
        $follow_external or

        // Executing external content
        $execute_external or

        // Obeying untrusted sources
        $obey_untrusted or

        // Running code blocks
        $run_code_blocks or

        // Following markup instructions
        $follow_markup or

        // Delegating to file content
        $delegate_to_file or

        // Executing inline code
        $execute_inline or

        // Trusting URL content
        $trust_url_content or

        // Parse and execute
        $parse_execute
}
