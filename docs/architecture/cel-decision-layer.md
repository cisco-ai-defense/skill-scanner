# CEL Decision Layer

> [!IMPORTANT]
> Skill Scanner uses the official `cel.dev/cel-go` engine at exactly
> `v0.32.0` through a bundled local helper. The Python process accepts protocol
> version 2 and the pinned `ScanFacts` descriptor hash only. Release reports
> additionally require the helper build version to match the scanner producer;
> development helpers cannot satisfy release gates.

Skill Scanner uses CEL as a bounded decision layer over findings that concrete
detectors have already produced. It does not replace signature, YARA, AST,
dataflow, archive, document, dependency, or binary analysis.

## Pipeline position

```text
package -> deterministic analyzers -> typed fact projection -> CEL gate
        -> LLM adjudication/enrichment -> policy normalization -> report
```

An extractor remains deliberately broad enough to find candidate behavior. A
CEL expression can retain the candidate or, after promotion, suppress it when
package context shows that it is a benign near miss. CEL cannot create a
finding or change its rule ID, category, or severity.

This split keeps parsing and dataflow in Python and gives contextual decisions
a small, auditable input and expression language.

## Typed fact contract

Every evaluation receives one protobuf value named `f` with type
`skill_scanner.semantic.v1.ScanFacts`. The schema version is `v1`.

| Field | Contents |
|---|---|
| `f.skill` | Manifest capabilities, bounded files, commands, URLs, flows, reference edges, and co-occurring signals |
| `f.candidate` | The candidate rule, analyzer, category, severity, location, context, and associated structured file/command/URL/flow |
| `f.projection` | Completeness, explicit truncation status, serialized size, and stable error codes |

The projector consumes analyzer-produced `metadata.semantic_facts`; it never
re-parses evidence snippets. Producers should emit normalized classifications,
such as `context_kind: documentation`, `downloads: true`, or
`sink_class: command_execution`. They must not emit secrets, full package
content, arbitrary objects, unrestricted maps, or protobuf `Any` values.

The activation limits are deliberately fixed:

- 1,024 file facts;
- 4,096 combined commands, URLs, flows, reference edges, and signals;
- 4 KiB per string; and
- 2 MiB serialized activation size.

Crossing a limit sets `f.projection.complete` to `false` and
`f.projection.truncated` to `true`. Ordinary projection errors remain explicitly
incomplete without claiming truncation. A candidate associated with either an
incomplete or truncated projection is retained without evaluation.

## Decision semantics

CEL has two independent controls: the scan mode and each rule's rollout state.

| Scan mode | Rule rollout | Expression result | Outcome |
|---|---|---|---|
| `off` | any | compiled and type-checked, not evaluated | Retain |
| `shadow` | any | `true` | Retain and record `keep` |
| `shadow` | any | `false` | Retain and record `would_suppress` |
| `enforce` | `shadow` | `false` | Retain and record `would_suppress` |
| `enforce` | `enforce` | `false` | Suppress |
| `shadow` or `enforce` | any | runtime/projection error | Retain and record `fallback` |

Parse and type errors are configuration errors and fail scanner startup. At
runtime, incomplete facts, evaluator errors, non-Boolean values, and an open
slow/error circuit fail open. They never suppress a finding.

The CEL pre-validator permits only the typed root `f`, field selection,
Boolean operators, comparisons, membership, `has`, at most two nested
`exists`/`all` comprehensions, and literal arguments to `startsWith`,
`endsWith`, `contains`, and `matches`. It rejects dynamic regular expressions,
arbitrary indexing, arithmetic, collection construction, custom functions,
extensions, and dynamic values.

Expressions are limited to 16 KiB, 4,096 tokens/AST nodes, nesting depth 64,
two nested comprehensions, and 512-byte literal regular expressions. The
official compiler still performs authoritative syntax and type checking.

## Rule-pack schema v2

CEL gates belong to concrete signature or YARA rules in an administrator-
trusted version 2 manifest:

```yaml
schema_version: 2
name: example-security-rules
version: "1.0.0"
description: Context-aware local rules

rules:
  EXAMPLE_FETCH_EXECUTE:
    source: signature
    category: command_execution
    severity: HIGH
    description: Download followed by execution
    knobs:
      enabled: true
    cel:
      fact_schema: v1
      rollout: shadow
      expression: >-
        f.candidate.command.downloads &&
        f.candidate.command.executes &&
        f.candidate.context_kind != "documentation"
```

For version 2 packs, the manifest is authoritative. Loading fails on duplicate
keys or rule IDs, unknown fields or enum values, unsupported schema versions,
missing implementations, metadata disagreement between a signature and its
manifest, or invalid regex, YARA, or CEL.

An explicitly trusted local pack may contain signatures, YARA, and CEL gates.
It may not load Python code. Skill Scanner does not fetch remote rule packs or
treat downloaded expressions as trusted.

The staged CLI interface is:

```bash
# Built-in validation compiles and type-checks CEL with the bundled helper.
skill-scanner validate-rules

# A local pack must be selected explicitly. Repeat the flag for multiple packs.
skill-scanner validate-rules --trusted-rule-pack ./org-rules

# Observe decisions without suppressing findings.
skill-scanner scan ./my-skill \
  --trusted-rule-pack ./org-rules \
  --cel-mode shadow \
  --format json

# Suppression still requires cel.rollout: enforce on the individual rule.
skill-scanner scan ./my-skill --cel-mode enforce
```

The equivalent policy setting is:

```yaml
cel:
  mode: shadow  # off | shadow | enforce
```

The CLI flag overrides the policy for that invocation. `--rule-packs` continues
to select bundled packs, while `--custom-rules` continues to load custom YARA;
neither implicitly trusts a CEL pack.

The built-in presets currently select these modes:

| Preset | CEL mode | Correlation analyzer | Effect |
|---|---|---|---|
| `balanced` (default) | `shadow` | enabled | Record bounded CEL decisions without suppression |
| `strict` | `shadow` | enabled | Preserve maximum deterministic coverage while collecting the same decision telemetry |
| `permissive` | `off` | disabled | Skip contextual evaluation and structured correlation for the lowest-noise preset |

Every bundled CEL gate currently declares `rollout: shadow`. Consequently,
setting the global mode to `enforce` does not yet suppress a bundled finding;
suppression begins only after that individual rule passes the documented
promotion gates and its rollout changes to `enforce`.

The `core` pack is the release-gated configuration for this modernization. ATR
remains an optional bundled pack selected explicitly with `--rule-packs atr`.
Its shadow telemetry can inform later rule work, but ATR results are reported
separately and do not determine the core + CEL release result.

`off` disables decisions, not validation: when selected packs contain CEL,
startup still compiles the complete immutable generation with the helper and
records the runtime and expression-set identity. Missing or invalid helpers
therefore fail startup for all modes that select CEL rules.

## Audit metadata

JSON scan metadata records:

- mode, runtime and version, fact schema, and expression-set hash;
- evaluated, retained, would-suppress, suppressed, fallback, and incomplete-
  projection counts;
- aggregate CEL time plus bounded error codes; and
- an authoritative per-rule identity and counter table, including the pack,
  rollout, expression hash, and keep/would-suppress/suppressed/fallback totals.

Retained findings evaluated by CEL include the decision, reason, fact schema,
expression hash, pack, and rollout. In shadow mode, findings remain compatible
with existing consumers; the metadata explains what enforcement would change.
When ordinary same-issue normalization merges candidates, the winning finding
keeps bounded, counted `metadata.cel_decisions` lineage for every merged CEL
decision. Release evidence fails closed unless that lineage, explicit suppressed
records, per-rule counters, and aggregate counters reconcile exactly. Suppressed
records retain only bounded candidate identity and classification context (rule,
category, severity, analyzer, and count), never raw source. This lets promotion
checks account for enforce-only removals and reject any rule that would remove a
malicious HIGH or CRITICAL finding.

## Runtime qualification and platform support

Production qualification is exact rather than range-based. It binds cel-go
`v0.32.0`, helper protocol 2, the canonical `ScanFacts` descriptor SHA-256,
the expression-set hash, and a release helper build matching the scanner
version. Qualification must verify:

1. helper binary hashes for every claimed CPython/platform wheel;
2. compile and type-check success for every shipped expression;
3. deterministic results under repeated and concurrent scans;
4. no runtime or incomplete-projection fallback on mandatory corpora; and
5. the latency and detection rollout gates in the detection evaluation guide.

The CEL-helper support target is CPython 3.11-3.14 on glibc Linux
x86-64/ARM64, macOS x86-64/ARM64 (minimum macOS 13), and Windows x86-64 when a
matching bundled helper is present. Wheels use an explicit compressed interpreter tag for
CPython 3.11, 3.12, 3.13, and 3.14 with `none` ABI; they do not claim `abi3` or
unbounded future-Python support. Each wheel contains exactly one target helper
and a hash-bound manifest. The complete scanner currently requires macOS 14+
because the YARA-X dependency has a higher wheel floor than the CEL helper.
Alpine/musl, PyPy, and Windows ARM remain unsupported. Python 3.10 and Python
3.15 or newer are unsupported; consumers that require Python 3.10 must pin the
previous Skill Scanner release.

Source checkouts require Go 1.27.1 or newer. An editable `uv sync` builds the
host helper automatically; `uv run python scripts/build_cel_helper.py
--in-place` is the explicit repair/bootstrap command. Production wheel builds
use the qualified release toolchain, test the helper natively on all five
targets, and export Go-module checksums plus helper hashes in the release SBOM.
The `SKILL_SCANNER_CEL_GO_HELPER` path is a trusted local administrator or
developer override and intentionally bypasses packaged-manifest discovery; it
must never reference an executable supplied by a scanned package or dataset.

Enforcement remains gated on five clean frozen-generation runs with identical
non-timing output and one complete pinned public release-corpus run. CEL is a
decision layer only; Python analyzers and YARA remain the candidate producers.
