//////////////////////////////////////////
// Unbounded Autonomy Detection
// Target: Instructions that give skills excessive autonomy
// For agent skills with dangerous autonomous behaviors
//////////////////////////////////////////

rule autonomy_abuse_generic{

    meta:
        author = "Cisco"
        description = "Detects unbounded autonomy patterns that could lead to runaway behavior"
        classification = "harmful"
        threat_type = "AUTONOMY ABUSE"

    strings:

        // Keep trying without limits
        $keep_trying = /\b(keep (trying|attempting|retrying)|retry (until|till) (it )?(works?|succeeds?)|don't (give up|stop) until|continue (until|till) (success|it works))\b/i

        // Run without confirmation
        $no_confirmation = /\b(run without (asking|confirmation|permission|approval)|don't (ask|confirm|wait for) (user|permission|approval)|proceed without (asking|confirmation|permission))\b/i

        // Automatic execution
        $auto_execute = /\b(automatically (execute|run|perform|do)|auto-?(run|execute|perform)|execute (immediately|automatically|right away))\b/i

        // Unbounded loops (simplified regex for YARA compatibility)
        $unbounded_loops = /\b(run (continuously|forever|indefinitely)|keep (running|going) (forever|indefinitely)|while True:)\b/i

        // Ignore errors and continue
        $ignore_errors = /\b(ignore (all |any )?(errors?|exceptions?|failures?)|suppress (all |any )?(errors?|exceptions?)|continue (on|despite|after) (error|exception|failure))\b/i

        // Escalating behavior
        $escalating = /\b(if (that |this )?fails?,? (try|attempt|use) (more|higher|elevated) (privileges?|permissions?|access)|escalate (to|until))\b/i

        // Self-modification
        $self_modify = /\b(modify (itself|yourself|own|this skill)|update (itself|yourself|own|this skill)|change (own|this skill's) (code|behavior|instructions?))\b/i

        // Autonomous decision making without bounds
        $autonomous_decisions = /\b(decide (what|which|how) to (do|run|execute) (next|automatically)|choose (your own|automatically) (next )?actions?)\b/i

    condition:

        // Keep trying patterns
        $keep_trying or

        // No confirmation
        $no_confirmation or

        // Auto execution
        $auto_execute or

        // Unbounded loops
        $unbounded_loops or

        // Ignore errors
        $ignore_errors or

        // Escalating behavior
        $escalating or

        // Self-modification
        $self_modify or

        // Autonomous decisions
        $autonomous_decisions
}
