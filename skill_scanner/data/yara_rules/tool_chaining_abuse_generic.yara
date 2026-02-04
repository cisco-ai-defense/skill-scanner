//////////////////////////////////////////
// Tool Chaining Abuse Detection
// Target: Suspicious multi-step operations that could exfiltrate data
// For agent skills that chain operations suspiciously
//////////////////////////////////////////

rule tool_chaining_abuse_generic{

    meta:
        author = "Cisco"
        description = "Detects suspicious tool chaining patterns that could lead to data exfiltration"
        classification = "harmful"
        threat_type = "TOOL CHAINING ABUSE"

    strings:

        // Read → Send pattern
        $read_then_send = /\b(read|fetch|get|retrieve|collect|gather)\b[^\n]{0,100}\b(send|post|upload|transmit|forward|email|slack|webhook)\b/i

        // Collect → Exfiltrate pattern
        $collect_exfiltrate = /\b(collect (all |every |entire )?(data|files?|info|credentials?|secrets?|keys?|tokens?))\b[^\n]{0,150}\b(send|post|upload|transmit|curl|wget|requests\.post)\b/i

        // Multi-step with network
        $multistep_network = /\b(first|then|next|after|finally),? (read|collect|gather)\b[^\n]{0,100}\b(then|next|after|finally),? (send|post|upload)\b/i

        // Summarize and send externally
        $summarize_send = /\b(summarize|aggregate|compile)\b[^\n]{0,80}\b(send|post|email|slack) (to|via) (external|webhook|url|endpoint|api)\b/i

        // Read environment → Network
        $env_to_network = /\b(os\.environ|getenv|process\.env)\b[^\n]{0,150}\b(requests\.|urllib\.|curl|wget|socket\.)\b/i

        // File traversal → Collection → Send
        $traverse_collect_send = /\b(walk|rglob|listdir|scandir|find)\b[^\n]{0,100}\b(open|read)\b[^\n]{0,100}\b(send|post|upload)\b/i

        // Automated data pipeline
        $auto_pipeline = /\b(automatically (read|collect|gather))\b[^\n]{0,100}\b(and |then )?(send|post|forward|upload)\b/i

    condition:

        // Read then send
        $read_then_send or

        // Collect and exfiltrate
        $collect_exfiltrate or

        // Multi-step with network
        $multistep_network or

        // Summarize and send
        $summarize_send or

        // Environment to network
        $env_to_network or

        // Traverse, collect, send
        $traverse_collect_send or

        // Automated pipeline
        $auto_pipeline
}
