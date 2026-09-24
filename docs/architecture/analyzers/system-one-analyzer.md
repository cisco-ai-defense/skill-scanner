# System One Analyzer

An optional screening tier that asks a small calibrated model for a probability instead of
text, and records it. It is **advisory only**: it cannot emit a finding, change a severity,
or alter a verdict.

It is off by default.

## Why it exists, and why it cannot act

A "System One" model answers typed questions and returns a calibrated probability rather
than prose, which makes it attractive as a cheap screen in front of an expensive judge:
screen everything, send only the uncertain cases to the full LLM analyzer.

That did not work with the model available, and the tier is deliberately built so that it
cannot be wired into a decision until it does. Measured on 439 records from the
MaliciousSkillBench source-disjoint split:

| Property | Result |
|---|---|
| Separation from label | **Inverted**, AUC 0.25–0.31 |
| Mean probability, malicious records | 0.568 |
| Mean probability, benign records | 0.683 |
| Spread across eight per-threat probes, within one record | 0.041 |
| Correlation with input length | r = 0.187 |

Three things follow. The model scores benign skills as *riskier* than malicious ones, so
using it to gate or to prioritise would make the scanner worse than ignoring it. The
answers barely depend on which question is asked, so fanning out one request per threat
family buys nothing. And part of what the probability tracks is how long the input is.

This was checked in two framings — raw skill source, and the structured role-classified
packing the protocol intends — and both reproduce it. See
[measured results](../../reference/measured-results.md) for the full write-up.

The integration ships anyway because the protocol is model-agnostic and the failure is a
property of the model, not of the interface. Demonstrating separation on a corpus is the
precondition for anything acting on the score.

## Usage

```bash
export SKILL_SCANNER_SYSTEM_ONE_API_KEY=...   # never passed on the command line
skill-scanner scan ./my-skill \
  --system-one-endpoint https://example.invalid/v1/systemone \
  --system-one-model some-model
```

Both flags are required together. An endpoint without a model, or a model without an
endpoint, is rejected rather than half-configured, because a typo in either would
otherwise look like a successful run with screening enabled.

The result is recorded on the analyzer as `last_result` for inspection, logging, or review
triage. No finding is added to the scan.

## Protocol

`POST /v1/systemone`, with one question of type `noul`:

```json
{
  "model": "<model>",
  "state": "<concatenated skill text>",
  "questions": {
    "malicious": {
      "prompt": "Is this skill malicious or unsafe to install?",
      "type": "noul",
      "instructions": "..."
    }
  }
}
```

The response carries the probability directly, with no probabilities map:

```json
{"answers": {"malicious": {"type": "noul", "noul": 0.42}}}
```

Two details are easy to get wrong. `instructions` is required **per question**, not per
request. And a client that looks for a `<name>.true` key, as a differently shaped hosted
API would, reads nothing at all — so the analyzer requires `type == "noul"` and refuses to
coerce anything else, rather than manufacturing a number from a format error.

## Deliberate limits

**Transport.** A plaintext endpoint off loopback is refused, because the request body is
the skill's source. `https` is required for any remote host; `http` is allowed on loopback
so a locally served model can be used.

**Oversize content is skipped, not truncated.** The budget is `MAX_STATE_BYTES = 24_000`,
set well below a typical 16k-token limit at a pessimistic two bytes per token. A model
that answers confidently about content it never saw is a fail-open, not a low score, so an
oversize skill is recorded as skipped.

**Failures are recorded as failures.** A transport error, an unusable response shape, or a
probability outside `[0, 1]` each produce a `status` other than `ok` and no probability.
Nothing is inferred from a failed screen.

## Related

- [Measured results](../../reference/measured-results.md) — the full negative result.
- [LLM Analyzer](llm-analyzer.md) — the judge this was tested as a screen for.
- [CLI command reference](../../reference/cli-command-reference.md) — flag details.
