//////////////////////////////////////////
// Unicode Steganography and Hidden Characters Detection
// Target: Invisible Unicode used for prompt injection and ASCII smuggling
// Based on: https://en.wikipedia.org/wiki/Tags_(Unicode_block)
//           https://embracethered.com/blog/posts/2026/scary-agent-skills/
// Tuned to reduce FPs: requires high threshold OR dangerous code context,
// EXCEPT for the Unicode Tag Block (U+E0000–U+E007F) which is ALWAYS
// suspicious — these characters have no legitimate use in skill files.
//
// ASCII Smuggling (issue #92):
//   Attackers encode hidden instructions by mapping each ASCII character
//   to its Tag Block counterpart (e.g. 'I' → U+E0049).  The result is
//   invisible in every text editor and terminal but is decoded and acted
//   on by the LLM.  Tag Block bytes in UTF-8 are F3 A0 80–81 xx.
//////////////////////////////////////////

rule prompt_injection_unicode_steganography{

    meta:
        author = "Cisco"
        description = "Detects hidden Unicode characters used for invisible prompt injection and ASCII smuggling steganography"
        classification = "harmful"
        threat_type = "UNICODE STEGANOGRAPHY"
        reference = "https://en.wikipedia.org/wiki/Tags_(Unicode_block)"
        reference2 = "https://embracethered.com/blog/posts/2026/scary-agent-skills/"

    strings:

        // --- 1. Unicode Tag Block — raw UTF-8 bytes (ASCII Smuggling) ---
        // U+E0000–U+E007F encode as F3 A0 80 [80-BF] (low half)
        //                          and F3 A0 81 [80-BF] (high half)
        // ANY occurrence is suspicious: these codepoints have no legitimate
        // use and are the exact characters used by ASCII smuggling tools.
        $tag_block = /\xF3\xA0[\x80\x81][\x80-\xBF]/

        // --- 2. Unicode Tag Regex Patterns (encoded in source strings) ---
        // Catches \uE00xx, \u{E00xx}, and \U000E00xx escape styles
        $unicode_tag_pattern = /\\u(\{)?[Ee]00[0-7][0-9A-Fa-f](\})?/
        $unicode_long_tag = /\\U000[Ee]00[0-7][0-9A-Fa-f]/

        // --- 3. Zero-width characters (steganography) ---
        // UTF-8 hex encoding
        $zw_space = "\xE2\x80\x8B"  // U+200B ZERO WIDTH SPACE
        $zw_non_joiner = "\xE2\x80\x8C"  // U+200C
        $zw_joiner = "\xE2\x80\x8D"  // U+200D

        // --- 4. Directional Overrides (text spoofing) ---
        $rtlo = "\xE2\x80\xAE"  // U+202E RIGHT-TO-LEFT OVERRIDE
        $ltro = "\xE2\x80\xAD"  // U+202D LEFT-TO-RIGHT OVERRIDE

        // --- 5. Invisible separators ---
        $line_separator = "\xE2\x80\xA8"  // U+2028 LINE SEPARATOR
        $paragraph_separator = "\xE2\x80\xA9"  // U+2029 PARAGRAPH SEPARATOR

        // --- 6. Variation Selectors Supplement (U+E0100-E01EF) ---
        // Used in os-info-checker-es6 attack (2025)
        $var_selectors = { F3 A0 (84|85|86|87) }

        // --- 7. Dangerous code patterns (context for zero-width detection) ---
        $eval_decode = /eval\s*\(\s*(atob|unescape)\s*\(/
        $func_decode = /Function\s*\(\s*atob\s*\(/
        $fromcharcode = /String\.fromCharCode/

    condition:
        (
            // Tag Block characters (ASCII smuggling) — ALWAYS suspicious.
            // Even a single match warrants investigation; there is no
            // legitimate reason for U+E0000–U+E007F in a skill file.
            $tag_block or

            // Encoded tag characters in source strings (always suspicious)
            $unicode_tag_pattern or
            $unicode_long_tag or

            // Variation selectors + decode = highly suspicious (os-info-checker-es6 pattern)
            (#var_selectors > 5 and any of ($eval_decode, $func_decode, $fromcharcode)) or

            // Zero-width steganography requires BOTH high count AND suspicious code
            // 50+ zero-width chars + decode function = likely steganography
            ((#zw_space + #zw_non_joiner + #zw_joiner) > 50 and any of ($eval_decode, $func_decode, $fromcharcode)) or

            // Very high zero-width count alone is suspicious (>200 indicates deliberate encoding)
            (#zw_space + #zw_non_joiner + #zw_joiner) > 200 or

            // Any directional override (highly suspicious in source code)
            $rtlo or
            $ltro or

            // Invisible separators (no legitimate use in source code)
            $line_separator or
            $paragraph_separator
        )
}
