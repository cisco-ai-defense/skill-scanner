# Security Policies and Procedures

This document outlines security procedures and general policies for the
`skill-scanner` project.

- [Disclosing a security issue](#disclosing-a-security-issue)
- [Vulnerability management](#vulnerability-management)
- [Supply-chain controls](#supply-chain-controls)
- [Vulnerability allowlist](#vulnerability-allowlist)
- [Suggesting changes](#suggesting-changes)

## Disclosing a security issue

The `skill-scanner` maintainers take all security issues in the project seriously. Thank you for improving the security of `skill-scanner`. We appreciate your dedication to responsible disclosure and will make every effort to acknowledge your contributions.

`skill-scanner` leverages GitHub's private vulnerability reporting.

To learn more about this feature and how to submit a vulnerability report,
review [GitHub's documentation on private reporting](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability).

Here are some helpful details to include in your report:

- a detailed description of the issue
- the steps required to reproduce the issue
- versions of the project that may be affected by the issue
- if known, any mitigations for the issue

A maintainer will acknowledge the report and follow up with next steps.

If you've been unable to successfully draft a vulnerability report via GitHub
or have not received a timely response, please reach out via the
[Cisco Open security contact email](mailto:oss-security@cisco.com).

After the initial reply to your report, the maintainers will endeavor to keep
you informed of the progress towards a fix and full announcement, and may ask
for additional information or guidance.

## Vulnerability management

When the maintainers receive a disclosure report, they will assign it to a
primary handler.

This person will coordinate the fix and release process, which involves the
following steps:

- confirming the issue
- determining affected versions of the project
- auditing code to find any potential similar problems
- preparing fixes for all releases under maintenance

## Supply-chain controls

`cisco-ai-skill-scanner` ships the following supply-chain protections:

- **Hash-verified lockfile.** `uv.lock` is committed to the repository and
  contains SHA-256 hashes for every direct and transitive dependency. CI installs
  with `uv sync --frozen`, which fails the build if the lockfile is stale or
  tampered with.
- **Vulnerability scanning on every commit.** `pip-audit` runs against the
  locked tree in CI and fails the build on any new CVE. See the
  [Vulnerability allowlist](#vulnerability-allowlist) section for the temporary
  exception process.
- **Hash-pinned `requirements.txt` for `pip` users.** Each GitHub release
  includes a `requirements.txt` exported via `uv export --frozen` so consumers
  who install with `pip` can reproduce the exact same dependency tree we ship
  and tested against, with hash verification.
- **PyPI Trusted Publishers.** Releases are uploaded to PyPI via OIDC; no
  long-lived API tokens are stored in the repository or in CI secrets.
- **Loose abstract constraints in `pyproject.toml`.** Library consumers can
  resolve transitive security patches forward without forced cascades. See
  [`CONTRIBUTING.md` § Dependency Policy](/CONTRIBUTING.md#dependency-policy)
  for details.

## Vulnerability allowlist

The `pip-audit` CI step is fail-closed by default. If a transitive CVE has no
available fix within our allowed dependency ranges, or is verifiably
not-applicable to how `skill-scanner` uses the affected package, a maintainer
may temporarily ignore it by appending `--ignore-vuln <ID>` to the
`pip-audit` invocation in `.github/workflows/python-tests.yml`.

Every allowlist entry MUST include:

1. The vulnerability ID (GHSA or CVE).
2. A link to the upstream advisory.
3. A short justification (e.g., "code path not reached", "fix expected in
   upstream X.Y", "tracking issue #NNN").
4. A target removal date or condition (e.g., "remove when upstream releases
   patched version").

Entries should be reviewed every release. If a fix becomes available, remove the
allowlist entry as part of the dependency bump.

## Suggesting changes

If you have suggestions on how this process could be improved please submit an
issue or pull request.
