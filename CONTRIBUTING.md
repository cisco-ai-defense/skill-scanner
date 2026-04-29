# How to Contribute

Thanks for your interest in contributing to `skill-scanner`! Here are a few
general guidelines on contributing and reporting bugs that we ask you to review.
Following these guidelines helps to communicate that you respect the time of the
contributors managing and developing this open source project. In return, they
should reciprocate that respect in addressing your issue, assessing changes, and
helping you finalize your pull requests. In that spirit of mutual respect, we
endeavor to review incoming issues and pull requests within 10 days, and will
close any lingering issues or pull requests after 60 days of inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](/CODE_OF_CONDUCT.md). This includes creation of issues or pull
requests, commenting on issues or pull requests, and extends to all interactions
in any real-time space e.g., Slack, Discord, etc.

## Development Setup

See [docs/developing.md](/docs/developing.md) for complete environment setup instructions, including:

- Installing prerequisites (Python 3.10+, uv)
- Cloning and configuring the repository
- Installing dependencies and pre-commit hooks
- Running tests and linting

## Dependency Policy

`cisco-ai-skill-scanner` is published as a library on PyPI, so its dependency
strategy distinguishes between **abstract** and **concrete** constraints:

| Layer | File | Style | Audience |
|---|---|---|---|
| Abstract constraints | `pyproject.toml` | Compatible-release ranges (`>=X.Y,<X+1`) | Downstream consumers' resolvers |
| Concrete tree | `uv.lock` | Exact versions + SHA-256 hashes | Our CI, Docker builds, dev environments |
| Pip-user reproducibility | `requirements.txt` (attached to GitHub releases) | Exact versions + hashes | Plain `pip install` users |

### Rules of thumb

1. **Do NOT use `==` in `[project] dependencies` or `[project.optional-dependencies]`.**
   Hard pins force downstream consumers into full dependency-tree rewires every
   time a transitive dep ships a security patch (see issue #93). Use
   `>=floor,<next_major` instead, with the floor at the lowest version we
   actually test.
2. **Floor pins for known-bad versions are encouraged.** If a specific upstream
   release was yanked, compromised, or has a CVE with no fix below it, raise the
   floor and add an inline comment explaining why (see `litellm` for an example).
3. **`[dependency-groups] dev` may use `==`.** These never propagate to library
   consumers, and exact pins keep contributor environments deterministic.
4. **Reproducibility comes from `uv.lock`, not `pyproject.toml`.** CI uses
   `uv sync --frozen` so any drift between `pyproject.toml` and `uv.lock` fails
   the build.
5. **Re-run `uv lock` after every `pyproject.toml` edit.** Pre-commit will not do
   this for you; commit the lockfile change with the constraint change.

### When upgrading dependencies

```bash
uv lock --upgrade        # bump the entire tree to latest within ranges
uv sync --all-extras --frozen
uv run pytest tests/
uv run pip-audit         # must report 0 vulnerabilities
```

If `pip-audit` flags a transitive CVE that has no fix available in our allowed
range, see [SECURITY.md](/SECURITY.md#vulnerability-allowlist) for the
documented allowlist process.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our [issues
list](https://github.com/cisco-ai-defense/skill-scanner/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case.

**If you discover a security bug, please do not report it through GitHub.
Instead, please see security procedures in [SECURITY.md](/SECURITY.md).**

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and, as
we follow semantic versioning, we may reserve breaking changes until the next
major version release.

### Pull Request Checklist

- [ ] All pre-commit hooks pass (`uv run pre-commit run --all-files`)
- [ ] All unit tests pass (`uv run pytest tests/`)
- [ ] All benchmarks pass without significant regressions (`uv run python evals/runners/benchmark_runner.py`)
- [ ] Tests added/updated for changes (see [TESTING.md](/TESTING.md))
- [ ] Documentation updated if needed
- [ ] Commit messages follow conventional format (e.g., `feat:`, `fix:`, `docs:`)

## Other Ways to Contribute

We welcome anyone that wants to contribute to `skill-scanner` to triage and
reply to open issues to help troubleshoot and fix existing bugs. Here is what
you can do:

- Help ensure that existing issues follows the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review and update the existing content of our
  [Wiki](https://deepwiki.com/cisco-ai-defense/skill-scanner) with up-to-date
  instructions and code samples.
- Review existing pull requests, and testing patches against real existing
  applications that use `skill-scanner`.
- Write a test, or add a missing test case to an existing test.

Thanks again for your interest on contributing to `skill-scanner`!

:heart:
