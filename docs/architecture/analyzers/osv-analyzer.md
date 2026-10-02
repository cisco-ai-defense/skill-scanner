# OSV Analyzer

## Overview

The OSV Analyzer checks the exactly pinned Python and JavaScript dependencies a
skill declares against the [OSV.dev](https://osv.dev) vulnerability database — a
free, open aggregator of security advisories (GHSA, PYSEC, CVE, and more). It is
an **opt-in external analyzer** (like VirusTotal): it requires network access,
needs **no API key**, and **fails open** so a network problem never breaks a
scan.

## What It Detects

- **Known-vulnerable dependency versions** — a dependency pinned to an exact
  release (`package==1.2.3`, or `"package": "1.2.3"`) that has one or more
  advisories in OSV is flagged as `SUPPLY_CHAIN_KNOWN_VULNERABILITY` (HIGH),
  with the advisory IDs and links.

Only dependencies pinned to an **exact** version are queried. An open range
(`package>=1`, or a `package.json` `^4.17.0`) has no single version to look up;
that risk is surfaced by the static
[unpinned-dependency check](static-analyzer.md) instead.

## Sources Scanned

### PyPI

| Source | Notes |
|--------|-------|
| `requirements*.txt` | `requirements.txt`, `requirements-dev.txt`, etc. |
| `pyproject.toml` | `[project]` dependencies and optional-dependencies (PEP 621) |
| `setup.cfg` | `[options] install_requires` and `[options.extras_require]` |
| `setup.py` | String literals inside `install_requires=[...]` (parsed via AST, not executed) |
| `Pipfile` | `[packages]` and `[dev-packages]` sections |
| Manifest `metadata.dependencies` | Optional list of requirement strings in SKILL.md frontmatter |

### npm

| Source | Notes |
|--------|-------|
| `package.json` | `dependencies`, `devDependencies` (recorded with `dev: true` in metadata) and `optionalDependencies` |

`peerDependencies` is excluded — the declaring package does not install its
peers, the consumer does. `bundleDependencies` lists names already declared
elsewhere and carries no version of its own.

A spec is queried only when it names exactly one release: `1.2.3`, `=1.2.3`,
`v1.2.3`, or the aliased form `npm:real-pkg@1.2.3`, which is looked up under the
real package name rather than the alias. Ranges (`^4.17.0`), dist-tags
(`latest`) and partial versions (`1.x`) name no single release. Specs bound to
a particular artifact — `file:`, `link:`, `workspace:`, `git+`,
`github:owner/repo` and tarball URLs — are skipped, exactly as a Python URL or
VCS requirement is.

**Yield depends on how the manifest pins.** Application repositories commonly
declare exact versions and rely on a lockfile for transitives, so their
manifests are productive: measured against a real monorepo, 467 unique exact
pins produced 19 flagged packages and 50 advisories. Libraries and any manifest
written with ranges (`^4.17.0`) yield nothing, and the
[unpinned-dependency check](static-analyzer.md) is what carries the signal
there.

What the manifest cannot show is transitive dependencies. On the same repository
the resolved lockfile flagged 97 packages, so the ~78 difference is entirely
indirect dependencies — real advisories, but not ones the manifest declares or
the author can fix by editing it.

### Lockfiles are not a source

No lockfile is parsed, in either ecosystem: not `Pipfile.lock`, `poetry.lock` or
`uv.lock`, and not `package-lock.json`, `yarn.lock` or `pnpm-lock.yaml`. The
analyzer reads what a package *declares*, not what a particular install
resolved.

Two consequences are worth knowing. Transitive dependencies are never checked,
whatever the manifest says. And a fully locked project whose manifest holds only
ranges produces no OSV findings at all, with its unpinned-dependency findings
suppressed too because a lockfile is present (see
[static analyzer](static-analyzer.md)).

Reading lockfiles would close both gaps and is the natural follow-up. It needs
advisory-volume handling first: a real monorepo lockfile flags on the order of a
hundred packages, mostly transitive and mostly not reachable from the skill's
own code, and every finding is currently HIGH.

## Usage

### Command Line

```bash
# Enable OSV dependency scanning (no API key needed)
skill-scanner scan /path/to/skill --use-osv

# Combine with other analyzers
skill-scanner scan /path/to/skill --use-osv --use-behavioral
```

### Python API

```python
from skill_scanner.core.analyzers.osv_analyzer import OSVAnalyzer
from skill_scanner.core.loader import SkillLoader

analyzer = OSVAnalyzer(enabled=True)
skill = SkillLoader().load_skill("/path/to/skill")
findings = analyzer.analyze(skill)
```

### API

Set `use_osv: true` on the scan request (see the
[API Endpoint Reference](../../reference/api-endpoint-reference.md)).

## How It Works

1. **Collect pinned dependencies** — parse every supported source (see
   [Sources Scanned](#sources-scanned)) into `(ecosystem, name, version)`
   records, keeping only exact pins.
2. **Deduplicate** — the same release is often declared twice (two manifests
   listing one pin, or a package present in both `dependencies` and
   `optionalDependencies`), so records are collapsed on ecosystem, name and
   version.
3. **Batch query** — POST the records to `https://api.osv.dev/v1/querybatch`
   (`{"package": {"ecosystem": ..., "name": ...}, "version": ...}`). Each query
   carries its own ecosystem, so Python and JavaScript dependencies are looked
   up in the same request.
4. **Generate findings** — for each package that returns advisories, emit a
   `SUPPLY_CHAIN_KNOWN_VULNERABILITY` finding listing the advisory IDs.

### Bounds

A skill can declare a large dependency set. Two limits keep a scan
proportionate:

| Limit | Default | Behavior |
|-------|---------|----------|
| `QUERY_CHUNK_SIZE` | 200 queries per request | Keeps each request well inside OSV's pagination thresholds |
| `MAX_DEPENDENCIES` | 1000 per skill | Beyond this, the analyzer logs a warning and queries the first 1000 |

Both are constructor arguments (`chunk_size`, `max_dependencies`) for callers
that need different bounds.

Advisory lists are not paginated: a package returning more than OSV's per-query
page of advisories reports a truncated ID list, but is still flagged.

## Error Handling

The analyzer fails open, **per chunk**. On any network/HTTP error it logs a
warning and treats that chunk as returning no advisories, so a transient failure
costs coverage of those packages rather than discarding the chunks that
succeeded. An offline or air-gapped environment simply skips the check rather
than failing the scan.

## Dependencies

Uses `httpx`, which is already a scanner dependency — enabling OSV adds **no new
runtime dependency** and no API key.

## Related Pages

- [Analyzer Selection Guide](meta-and-external-analyzers.md) — when to enable `--use-osv`
- [Static Analyzer](static-analyzer.md) — the complementary unpinned-dependency check
