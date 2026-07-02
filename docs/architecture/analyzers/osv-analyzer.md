# OSV Analyzer

## Overview

The OSV Analyzer checks a skill's declared Python dependencies against the
[OSV.dev](https://osv.dev) vulnerability database — a free, open aggregator of
security advisories (GHSA, PYSEC, CVE, and more). It is an **opt-in external
analyzer** (like VirusTotal): it requires network access, needs **no API key**,
and **fails open** so a network problem never breaks a scan.

## What It Detects

- **Known-vulnerable dependency versions** — a pinned dependency
  (`package==1.2.3`) that has one or more advisories in OSV is flagged as
  `SUPPLY_CHAIN_KNOWN_VULNERABILITY` (HIGH), with the advisory IDs and links.

Only dependencies pinned to an **exact** version are queried. An open range
(`package>=1`) has no single version to look up; that risk is already surfaced
by the static [unpinned-dependency check](static-analyzer.md).

## Sources Scanned

| Source | Notes |
|--------|-------|
| `requirements*.txt` | `requirements.txt`, `requirements-dev.txt`, etc. |
| `pyproject.toml` | `[project]` dependencies and optional-dependencies (PEP 621) |
| `setup.cfg` | `[options] install_requires` and `[options.extras_require]` |
| `setup.py` | String literals inside `install_requires=[...]` (parsed via AST, not executed) |
| `Pipfile` | `[packages]` and `[dev-packages]` sections |
| Manifest `metadata.dependencies` | Optional list of requirement strings in SKILL.md frontmatter |

Ecosystem defaults to `PyPI`.

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

1. **Collect pins** — parse every supported dependency source (see
   [Sources Scanned](#sources-scanned)), keeping only exact `==` pins as
   `(name, version)` pairs.
2. **Batch query** — POST all pins to `https://api.osv.dev/v1/querybatch`
   (`{"package": {"ecosystem": "PyPI", "name": ...}, "version": ...}`).
3. **Generate findings** — for each package that returns advisories, emit a
   `SUPPLY_CHAIN_KNOWN_VULNERABILITY` finding listing the advisory IDs.

## Error Handling

The analyzer fails open. On any network/HTTP error it logs a warning and
returns no findings, so an offline or air-gapped environment simply skips the
check rather than failing the scan.

## Dependencies

Uses `httpx`, which is already a scanner dependency — enabling OSV adds **no new
runtime dependency** and no API key.

## Related Pages

- [Analyzer Selection Guide](meta-and-external-analyzers.md) — when to enable `--use-osv`
- [Static Analyzer](static-analyzer.md) — the complementary unpinned-dependency check
