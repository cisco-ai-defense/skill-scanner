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
- [ ] All benchmarks pass without significant regressions (`uv run python evals/benchmark_runner.py`)
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
  [Wiki](https://github.com/cisco-ai-defense/skill-scanner/wiki) with up-to-date
  instructions and code samples.
- Review existing pull requests, and testing patches against real existing
  applications that use `skill-scanner`.
- Write a test, or add a missing test case to an existing test.

Thanks again for your interest on contributing to `skill-scanner`!

:heart:
