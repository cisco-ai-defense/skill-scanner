//////////////////////////////////////////
// Jailbreak Detection Rule
// AITech-2.1: Jailbreak Attacks
// Target: Attempts to bypass AI safety measures through context manipulation,
//         semantic tricks, persona adoption, and other jailbreak techniques
// Reference: OWASP LLM01:2025, Cisco AI Security Framework
//////////////////////////////////////////

rule jailbreak_generic{

    meta:
        author = "Cisco"
        description = "Detects jailbreak attempts to bypass AI safety measures"
        classification = "harmful"
        threat_type = "JAILBREAK"
        aitech = "AITech-2.1"

    strings:

        // ================================================================
        // AISubtech-2.1.1: Context Manipulation (Jailbreak)
        // ================================================================

        // --- DAN (Do Anything Now) Jailbreak Patterns ---
        // The most well-known jailbreak with ~89.6% success rate
        $dan_explicit = /\b(you are (now )?DAN|from now on[^.]{0,30}(you (will be|are) (known as )?|call you )DAN|enable DAN mode|activate DAN|DAN mode (enabled|activated|on))\b/i

        // DAN immersion / role adoption
        $dan_role = /\b(immerse yourself (into|in) the role of DAN|(take on|assume|adopt) the (role|persona|identity) of DAN|you (will|are going to) (play|act as|be) DAN)\b/i

        // Jailbreak mode activation
        $jailbreak_mode = /\b((you are (now )?in |enter |enable |activate )?jailbreak(ed)? mode|jailbreak (enabled|activated|on|engaged))\b/i

        // Persona adoption with unrestricted framing
        $persona_unrestricted = /\b(you are (now )?|act as |pretend (to be |you are )|imagine you are |from now on you are )(an? )?(uncensored|unrestricted|unfiltered|unlimited|unbound|liberated|free|evil|chaotic|amoral|unethical)\s+(AI|assistant|model|chatbot|version|persona|entity)/i

        // Character that ignores/has no restrictions
        $persona_no_limits = /\b(you are |act as |pretend to be )[^.]{0,50}(who |that |with )(has no|ignores?|doesn't have|lacks?|is free from|without) (restrictions?|limits?|guidelines?|rules?|ethics?|morals?|filters?|safety|guardrails?)/i

        // Dual personality jailbreak (respond as both X and Y)
        $dual_personality = /\b(respond (as )?both|answer as both|give (me )?(two|2) responses?|one (response )?(as |from )?[A-Za-z]+ (and )?(one|another) (as |from )?)\b[^.]{0,60}\b(unrestricted|uncensored|jailbroken|DAN|unfiltered)\b/i

        // Classic/Jailbroken response format
        $response_format_jailbreak = /\[\s*(CLASSIC|NORMAL|STANDARD|GPT|CLAUDE)\s*\][^[]{0,200}\[\s*(JAILBR(OKE|OKEN|EAK(ED)?)|DAN|UNRESTRICTED|UNCENSORED|EVIL|CHAOS)\s*\]/i

        // Enable alter ego / shadow self
        $alter_ego = /\b(enable|activate|unlock|unleash|awaken|summon) (your )?(alter ego|shadow (self|mode|personality)|dark (side|mode|persona)|true (self|form)|hidden (persona|personality|mode))\b/i

        // --- Roleplay and Fictional Framing ---
        // Deflects responsibility by framing as fiction (~76% success rate)
        $fictional_framing = /\b(in (this |a )?(fictional|hypothetical|imaginary|alternate|parallel) (scenario|world|universe|reality|story|narrative)[^.]{0,50}(no |without |where .{0,20}(don't|doesn't) (exist|apply)|are (removed|disabled|gone)))/i

        // Roleplay as unrestricted AI
        $roleplay_unrestricted = /\b(let's (roleplay|pretend|imagine|play)[^.]{0,30}(you are|you're) (an? )?(uncensored|unrestricted|unfiltered|unlimited) (AI|assistant|model))/i

        // Creative writing bypass
        $creative_bypass = /\b(for (this |a )?(creative writing|fiction|story|narrative|screenplay|novel)[^.]{0,40}(no restrictions?|ignore (safety|guidelines)|unrestricted|uncensored))/i

        // Movie/script framing
        $movie_framing = /\b(you are (an )?AI in (a |this )?(movie|film|script|screenplay|story)|as (a |an )?(character|AI) in (a |this )?(movie|film))[^.]{0,40}(no (rules?|restrictions?)|can say anything)/i

        // --- Grandma/Emotional Exploitation ---
        // Emotional manipulation bypass (~76% success rate)
        $grandma_exploit = /\b(pretend (to be |you are )my (deceased |dead |late )?(grandma|grandmother|grandpa|grandfather|nana|granny)|my (grandma|grandmother|granny) (used to|would) (tell|teach|show) me (about |how to ))/i

        // Bedtime story exploit
        $bedtime_exploit = /\b(as a (bedtime|goodnight) story[^.]{0,30}(tell|teach|explain|show) (me |us )?(how to|about))/i

        // Dying wish / emotional blackmail - TIGHTENED: Require harmful/bypass context
        // Anchored to explicit requests for restricted content
        $emotional_blackmail = /\b((my )?(dying|last|final) wish[^.]{0,30}(tell|show|teach|explain)[^.]{0,30}(how to|about (making|creating|building|hacking))|I('m| am) (dying|terminally ill)[^.]{0,40}(before I (die|go)|last request)[^.]{0,30}(tell|show|teach))/i


        // ================================================================
        // AISubtech-2.1.3: Semantic Manipulation (Jailbreak)
        // ================================================================

        // --- Research/Educational Framing ---
        // TIGHTENED: Only flag when combined with explicit bypass/harmful content request
        // Standalone "for research purposes" is too common in legitimate content
        $research_framing_with_bypass = /\b(for (research|academic|educational|scientific|study) purposes?)[^.]{0,60}(bypass|ignore|disable|circumvent|evade|how to (hack|exploit|attack|break))/i

        // Security audit framing - TIGHTENED: Require explicit bypass/harmful intent
        // Standalone security audit mentions are legitimate
        $security_audit_with_bypass = /\b(for (a |an )?(security|penetration|vulnerability) (audit|test|assessment))[^.]{0,40}(bypass|ignore|disable|without (restrictions?|limits?|safety))/i

        // --- Logic Trap Attacks (~81.4% ASR) ---
        // Exploits conditional logic and moral dilemmas
        $logic_trap_intelligence = /\b(if you (were|are) truly (intelligent|smart|capable|advanced)|a (truly |really )?(intelligent|smart|capable|helpful) AI would|prove (that )?you('re| are) (not )?(intelligent|capable|helpful|smart) by)/i

        // Prove you're not censored
        $logic_trap_censorship = /\b(prove (that )?(you('re| are) not|you aren't) (censored|restricted|limited|filtered)|if you (refuse|can't|won't)[^.]{0,30}(proves?|shows?|means?) (you('re| are)|that you))/i

        // Refusal causes harm argument
        $logic_trap_harm = /\b((your |the )?refusal (causes?|leads? to|results? in) (more |greater )?(harm|damage|suffering)|more (harm|damage|suffering) (by|from|in) (refusing|not (answering|helping|telling)))/i

        // Ethical obligation to answer
        $logic_trap_ethics = /\b(the (truly |most )?(ethical|moral|right) (choice|thing|action) (is to|would be to) (answer|help|tell|provide)|ethically (obligated|required|bound) to (answer|help|respond))/i

        // --- Anti-Safety Rhetoric ---
        // Arguments against safety measures
        $anti_safety_flawed = /\b((your |the )?(safety|content|ethical) (training|guidelines|rules|filters|restrictions?) (is|are) (flawed|harmful|wrong|broken|outdated|misguided|counterproductive))/i

        // Censorship is harmful/unethical
        $anti_safety_censorship = /\b((censorship|restrictions?|filters?|safety measures?) (is|are) (unethical|harmful|wrong|bad|counterproductive)|true (AI |artificial )?intelligence (should be|means being|requires being) (uncensored|unrestricted|unfiltered))/i

        // Restrictions harm users
        $anti_safety_harm = /\b((these |those |your )?(restrictions?|guidelines?|rules?|filters?) (harm|hurt|damage|disadvantage) (users?|people|humanity|society))/i


        // ================================================================
        // AISubtech-2.1.4: Token Exploitation (Jailbreak)
        // ================================================================

        // --- Output Encoding Bypass ---
        // Requests to encode output to evade filters
        $encoding_bypass = /\b(respond|answer|output|reply|write) (in|using|with) (base64|rot13|hex(adecimal)?|binary|morse( code)?|pig latin|reversed?|backwards?|leetspeak|l33t)[^.]{0,30}(so|to|that) (filters?|detection|safety|moderation) (don't|won't|can't|cannot) (catch|detect|see|flag)/i

        // Character-by-character output
        $char_by_char = /\b(output|spell|write|respond) (it )?(character[- ]by[- ]character|letter[- ]by[- ]letter|one (character|letter) at a time)[^.]{0,30}(avoid|bypass|evade)/i

        // Replace words with symbols/emojis
        $symbol_replacement = /\b(replace|substitute|swap|use) [^.]{0,30}(with |for )(emoji|symbol|unicode|special character)[^.]{0,30}(bypass|avoid|evade|filter)/i

        // Show what you would say
        $hypothetical_output = /\b(show (me )?(what )?you would (say|respond|answer|output)|what would you (say|respond|answer) if you (could|were allowed|had no restrictions?))/i


        // ================================================================
        // AISubtech-2.1.5: Multi-Agent Jailbreak Collaboration
        // ================================================================

        // Using other AI/agent to jailbreak
        $multi_agent = /\b(use (this |another |the other )?(AI|agent|model|assistant) to (bypass|jailbreak|unlock)|have (the )?(AI|agent|model)s? (collaborate|work together) to (bypass|circumvent|overcome))/i

        // Relay through another persona
        $relay_attack = /\b(ask (your |the )?(other|alternate|secondary) (persona|personality|self|AI) to|relay (this |my )?(request|question|query) to (your )?(unrestricted|uncensored|other))/i


        // ================================================================
        // Authority Claims / Impersonation
        // ================================================================

        // Developer/creator claims
        $authority_developer = /\b(I('m| am) (your |the |an? )?(creator|developer|programmer|engineer|designer|maker|owner)|I (created|made|built|designed|programmed|developed) you|I work (for|at) (Anthropic|OpenAI|Google|Meta|Microsoft))/i

        // Admin/root access CLAIMS (jailbreak-specific: false claims of having elevated access)
        // NOTE: "bypass security checks" and "developer mode activated" are in prompt_injection_generic
        $authority_admin_claim = /\b(I have (admin|root|elevated|superuser|system) (access|privileges?|permissions?|rights|clearance)|authorization (level|code|key)[^.]{0,20}(confirmed|granted|verified)|my (admin|root|superuser) (credentials?|access) (allow|let|permit))/i

        // Maintenance/debug mode claims
        $authority_maintenance = /\b((maintenance|diagnostic|debug|service|testing) mode (activated|enabled|engaged|confirmed)|entering (maintenance|diagnostic|debug) mode|backend access (granted|confirmed))/i

        // Override codes/keys
        $override_code = /\b((override|bypass|unlock|master|admin) (code|key|password|passphrase)[^.]{0,20}(is |[:=])|using (override|master|admin|unlock) (code|key))/i


        // ================================================================
        // Hypothetical Override Patterns
        // ================================================================

        // Speaking hypothetically to bypass
        $hypothetical_bypass = /\b((hypothetically|theoretically|in theory)[^.]{0,30}(if you (had|were|could)|how would (you|one|someone))[^.]{0,40}(no (restrictions?|limits?|rules?|guidelines?)|without (restrictions?|limits?|safety)))/i

        // Assume no guardrails
        $assume_no_guardrails = /\b((assume|imagine|pretend|suppose) (that )?(for|that)[^.]{0,30}(guardrails?|restrictions?|safety (measures?|guidelines?)|content (policies?|filters?)) (don't|do not|didn't|did not) exist)/i

        // If you could/were allowed
        $if_allowed = /\b(if you (could|were (allowed|permitted|able)|had (permission|the ability))[^.]{0,30}(what would you (say|do|tell|answer)|how would you (respond|answer|help)))/i


        // ================================================================
        // Exclusions - Reduce False Positives
        // ================================================================

        // Security research documentation
        $security_doc = /\b(jailbreak (detection|prevention|defense|mitigation)|detecting jailbreak|anti[- ]jailbreak|jailbreak (attack )?(pattern|signature|indicator)s?)\b/i

        // Code that detects jailbreaks (this scanner, security tools)
        $detection_code = /\b(rule |def |function |class )[^{(]*jailbreak/i

        // Academic papers and research about jailbreaks
        $academic_paper = /\b(abstract|introduction|methodology|conclusion|references|et al\.|arxiv|doi:|cite|citation)\b/i

        // YARA rule definitions
        $yara_rule = /\brule\s+\w+\s*\{/

        // Test files and examples
        $test_context = /\b(test_|_test\.|spec\.|\.test\.|example|sample|mock|fixture)\b/i


    condition:
        // Exclude security documentation and detection code
        not $security_doc and
        not $detection_code and
        not $academic_paper and
        not $yara_rule and
        not $test_context and
        (
            // === HIGH CONFIDENCE - Always flag ===

            // DAN jailbreaks
            $dan_explicit or
            $dan_role or
            $jailbreak_mode or

            // Persona with explicit unrestricted framing
            $persona_unrestricted or
            $persona_no_limits or

            // Dual personality jailbreak
            $dual_personality or
            $response_format_jailbreak or

            // Alter ego activation
            $alter_ego or

            // Authority impersonation (high severity)
            $authority_developer or
            $authority_admin_claim or
            $override_code or

            // Encoding bypass (explicit evasion intent)
            $encoding_bypass or

            // Anti-safety rhetoric (explicit)
            $anti_safety_flawed or
            $anti_safety_censorship or

            // === MEDIUM CONFIDENCE - Context dependent ===

            // Roleplay/fictional framing with restriction bypass
            $fictional_framing or
            $roleplay_unrestricted or
            $creative_bypass or
            $movie_framing or

            // Emotional exploitation
            $grandma_exploit or
            $bedtime_exploit or
            $emotional_blackmail or

            // Logic trap attacks
            $logic_trap_intelligence or
            $logic_trap_censorship or
            $logic_trap_harm or
            $logic_trap_ethics or

            // Anti-safety harm argument
            $anti_safety_harm or

            // Token exploitation
            $char_by_char or
            $symbol_replacement or
            $hypothetical_output or

            // Multi-agent jailbreak
            $multi_agent or
            $relay_attack or

            // Authority maintenance mode
            $authority_maintenance or

            // Hypothetical bypass
            $hypothetical_bypass or
            $assume_no_guardrails or
            $if_allowed or

            // Research/security audit framing with bypass intent (already tightened)
            $research_framing_with_bypass or
            $security_audit_with_bypass
        )
}
