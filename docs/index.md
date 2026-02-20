---
layout: home

hero:
  name: Cisco Skill Scanner
  text: Security scanning for AI agent skills
  tagline: "Detect prompt injection, data exfiltration, and malicious code patterns with multi-engine analysis -- static, behavioral, LLM semantic, and cloud-based."
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/quick-start
    - theme: alt
      text: View on GitHub
      link: https://github.com/cisco-ai-defense/skill-scanner

features:
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>'
    title: Multi-Engine Detection
    details: "Static signatures, YARA rules, behavioral dataflow, LLM-as-a-judge, and cloud analyzers -- layered to catch what any single engine misses."
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg>'
    title: Policy-Driven Tuning
    details: "Preset postures (strict, balanced, permissive) or fully custom YAML policies. Disable rules, override severities, and scope by analyzer -- no code changes."
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="8" y1="13" x2="8" y2="17"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="16" y1="15" x2="16" y2="17"/></svg>'
    title: CI/CD and Reporting
    details: "SARIF for GitHub Code Scanning, JSON for automation, Markdown and HTML for review. Exit codes and --fail-on-findings for build gates."
  - icon: '<svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><path d="M14 17.5h7"/><path d="M17.5 14v7"/></svg>'
    title: Extensible Rule Packs
    details: "Author custom YAML signatures, YARA rules, and Python checks. Bundle them into rule packs that distribute and version independently."
---

<ClientOnly>
<div class="hero-badges">
  <a href="https://pypi.org/project/cisco-ai-skill-scanner/" target="_blank" rel="noopener noreferrer"><img src="https://img.shields.io/pypi/v/cisco-ai-skill-scanner.svg" alt="PyPI version"></a>
  <a href="https://www.python.org/downloads/" target="_blank" rel="noopener noreferrer"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"></a>
  <a href="https://opensource.org/licenses/Apache-2.0" target="_blank" rel="noopener noreferrer"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="https://github.com/cisco-ai-defense/skill-scanner/actions/workflows/python-tests.yml" target="_blank" rel="noopener noreferrer"><img src="https://github.com/cisco-ai-defense/skill-scanner/actions/workflows/python-tests.yml/badge.svg" alt="CI"></a>
</div>
</ClientOnly>

<div class="install-demo">
  <div class="install-panels">
    <div class="install-panel">
      <div class="install-panel-header">
        <span class="install-dot"></span>
        <span class="install-label">Install</span>
      </div>
      <div class="install-cmd"><span class="install-prompt">$</span> <span class="cmd-bin">pip</span> install <span class="cmd-arg">cisco-ai-skill-scanner</span></div>
    </div>
    <div class="install-panel">
      <div class="install-panel-header">
        <span class="install-dot"></span>
        <span class="install-label">Try it</span>
      </div>
      <div class="install-cmd"><span class="install-prompt">$</span> <span class="cmd-bin">skill-scanner</span> scan <span class="cmd-arg">/path/to/skill</span></div>
    </div>
  </div>
</div>

<div class="terminal-demo">
<div class="terminal-header">
<span class="terminal-dot red"></span>
<span class="terminal-dot yellow"></span>
<span class="terminal-dot green"></span>
<span class="terminal-title">Terminal</span>
</div>
</div>

```txt
$ skill-scanner scan evals/skills/behavioral-analysis/multi-file-exfiltration --use-behavioral
============================================================
Skill: config-analyzer
============================================================
Status: [FAIL] ISSUES FOUND
Max Severity: CRITICAL
Total Findings: 11
Scan Duration: 0.37s

Findings Summary:
  CRITICAL: 3
      HIGH: 3
    MEDIUM: 4
       LOW: 1
      INFO: 0
```

<div class="explore-docs">
  <div class="explore-heading">Explore the Docs</div>
  <div class="explore-grid">
    <a class="explore-card" href="./getting-started/quick-start">
      <div class="explore-card-icon"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div>
      <div class="explore-card-title">Quick Start</div>
      <div class="explore-card-desc">Install, configure, and run your first scan.</div>
    </a>
    <a class="explore-card" href="./architecture/">
      <div class="explore-card-icon"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="8" height="8" rx="1"/><rect x="14" y="2" width="8" height="8" rx="1"/><rect x="8" y="14" width="8" height="8" rx="1"/><path d="M6 10v2a2 2 0 0 0 2 2h0"/><path d="M18 10v2a2 2 0 0 1-2 2h0"/></svg></div>
      <div class="explore-card-title">Architecture</div>
      <div class="explore-card-desc">How the analyzers, pipeline, and risk model work.</div>
    </a>
    <a class="explore-card" href="./user-guide/">
      <div class="explore-card-icon"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
      <div class="explore-card-title">User Guide</div>
      <div class="explore-card-desc">CLI, Python SDK, API server, policies, and configuration.</div>
    </a>
    <a class="explore-card" href="./reference/">
      <div class="explore-card-icon"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/><line x1="9" y1="8" x2="17" y2="8"/><line x1="9" y1="12" x2="15" y2="12"/></svg></div>
      <div class="explore-card-title">Reference</div>
      <div class="explore-card-desc">CLI commands, API endpoints, config, and output formats.</div>
    </a>
  </div>
</div>

<div class="home-notes">
Cisco Skill Scanner is a best-effort detection tool. It should be used as one layer in a defense-in-depth program -- a clean scan does not guarantee safety.
</div>
