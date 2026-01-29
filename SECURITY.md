# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.2.x   | :white_check_mark: |
| 0.1.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in the Skill Scanner, please report it responsibly.

### How to Report

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please email: oss-security@cisco.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity
  - Critical: 1-7 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: Best effort

### Disclosure Policy

- We follow coordinated disclosure
- We will credit researchers (unless they prefer anonymity)
- We will publish security advisories for confirmed vulnerabilities
- We request 90 days before public disclosure

## Security Features

### Built-in Protections

1. **Prompt Injection Protection**
   - Random delimiter system prevents analyzer manipulation
   - Validates delimiter integrity before LLM analysis

2. **Input Validation**
   - File path validation
   - Size limits on uploaded files
   - Sanitization of user inputs

3. **Sandboxed Execution**
   - Behavioral analyzer runs in Docker (optional)
   - Read-only file system by default
   - Network isolation available

4. **No Credential Exposure**
   - No hardcoded credentials
   - API keys from environment only
   - Secrets never logged

### Security Best Practices

When using the analyzer:

1. **Run in isolated environment** for untrusted skills
2. **Use Docker sandbox** for behavioral analysis
3. **Review findings manually** before taking action
4. **Keep dependencies updated** (`pip install --upgrade cisco-ai-skill-scanner`)
5. **Use environment variables** for API keys (never hardcode)

## Known Limitations

1. **Behavioral Analyzer**: Executes skill code - only use on skills you're analyzing
2. **LLM Analyzer**: Sends skill content to LLM provider (use Bedrock for compliance)
3. **Static Analysis**: Pattern-based, may miss sophisticated obfuscation

## Security Scanning

This tool scans agent skills for security threats. It is not a substitute for:
- Manual security review
- Penetration testing
- Compliance audits
- Legal review

Always perform comprehensive security assessment before deploying skills in production.

## Dependencies

We regularly update dependencies to address security vulnerabilities. Run:

```bash
pip install --upgrade cisco-ai-skill-scanner
```

To check for dependency vulnerabilities:

```bash
uv run pip-audit
```

## Contact

For security concerns: oss-security@cisco.com
For general issues: https://github.com/cisco-ai-defense/skill-scanner/issues
