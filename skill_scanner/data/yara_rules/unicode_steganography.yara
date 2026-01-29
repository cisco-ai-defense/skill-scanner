//////////////////////////////////////////
// Unicode Steganography and Hidden Characters Detection
// Target: Invisible Unicode used for prompt injection
// Based on: https://en.wikipedia.org/wiki/Tags_(Unicode_block)
//////////////////////////////////////////

rule unicode_steganography{

    meta:
        author = "Cisco"
        description = "Detects hidden Unicode characters used for invisible prompt injection and steganography"
        classification = "harmful"
        threat_type = "PROMPT INJECTION"
        reference = "https://en.wikipedia.org/wiki/Tags_(Unicode_block)"

    strings:

        // --- 1. Unicode Tag Regex Patterns ---
        // Catches \uE00xx, \u{E00xx}, and \U000E00xx encoding styles
        $unicode_tag_pattern = /\\u(\{)?[Ee]00[0-7][0-9A-Fa-f](\})?/
        $unicode_long_tag = /\\U000[Ee]00[0-7][0-9A-Fa-f]/

        // --- 2. Zero-width characters (steganography) ---
        // UTF-8 hex encoding
        $zw_space = "\xE2\x80\x8B"  // U+200B ZERO WIDTH SPACE
        $zw_non_joiner = "\xE2\x80\x8C"  // U+200C
        $zw_joiner = "\xE2\x80\x8D"  // U+200D

        // --- 3. Directional Overrides (text spoofing) ---
        $rtlo = "\xE2\x80\xAE"  // U+202E RIGHT-TO-LEFT OVERRIDE
        $ltro = "\xE2\x80\xAD"  // U+202D LEFT-TO-RIGHT OVERRIDE

        // --- 4. Invisible separators ---
        $line_separator = "\xE2\x80\xA8"  // U+2028 LINE SEPARATOR
        $paragraph_separator = "\xE2\x80\xA9"  // U+2029 PARAGRAPH SEPARATOR

        // --- 5. Homoglyph detection ---
        $cyrillic_a = "\xD0\x90"  // А (Cyrillic A mimics Latin A)
        $cyrillic_e = "\xD0\x95"  // Е (Cyrillic E mimics Latin E)
        $cyrillic_o = "\xD0\x9E"  // О (Cyrillic O mimics Latin O)

    condition:

        // Detection logic - flag and manually review (better safe than miss attack)
        (
            // Encoded tag characters in strings (any occurrence is suspicious)
            $unicode_tag_pattern or
            $unicode_long_tag or

            // Zero-width steganography (tools alternate chars to encode binary 0s/1s)
            // Aggregate count across all types is more effective than individual checks
            (#zw_space + #zw_non_joiner + #zw_joiner) > 10 or

            // Any directional override (highly suspicious in code/English text)
            $rtlo or
            $ltro or

            // Invisible separators (no legitimate use in source code)
            $line_separator or
            $paragraph_separator or

            // Homoglyph attacks (5+ Cyrillic chars mimicking Latin in English context)
            (#cyrillic_a + #cyrillic_e + #cyrillic_o) > 5
        )
}
