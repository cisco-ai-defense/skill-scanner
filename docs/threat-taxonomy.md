# Agent Skills Threat Taxonomy

## Overview

Authoritative threat classification for agent skills security analysis, aligned with the [Cisco Integrated AI Security and Safety Framework](https://arxiv.org/html/2512.12921v1) (December 2025).

**Detection Engines:**
- Static Analyzer: 58 pattern-based rules (YAML + YARA + Python)
- LLM Analyzer: Semantic analysis via Claude/GPT/Gemini

**Validation:** 149 tests passing, 0% false CRITICAL rate on official skills

---

## Threat Categories

### 1. Prompt Injection

**AITech**: AITech-1.1, AITech-1.2 | **Risk**: HIGH-CRITICAL

Malicious instructions that manipulate AI behavior or bypass safety systems.

**Detected by**: YAML rules, YARA (prompt_injection_generic, coercive_injection_generic), LLM analysis

**Examples**: "Ignore previous instructions", "unrestricted mode", "don't tell user"

---

### 2. Command & Code Injection

**AITech**: AITech-9.1.4 | **Risk**: CRITICAL

Unsafe code execution enabling arbitrary command execution.

**Detected by**: YAML rules, YARA (code_execution_generic, command_injection_generic, sql_injection_generic), LLM analysis

**Examples**: `eval()`, `os.system()`, `subprocess shell=True`, SQL injection, reverse shells

---

### 3. Data Exfiltration

**AITech**: AITech-8.2, AITech-8.2.3 | **Risk**: CRITICAL

Unauthorized data access and transmission to external locations.

**Detected by**: YAML rules, YARA (credential_harvesting_generic, tool_chaining_abuse_generic), LLM flow analysis

**Examples**: Network calls with credentials, ~/.aws access, environment harvesting, read→send chains

---

### 4. Hardcoded Secrets

**AITech**: AITech-8.2 | **Risk**: CRITICAL

Credentials embedded in code files.

**Detected by**: YAML rules, YARA (credential_harvesting_generic), LLM pattern recognition

**Examples**: API keys (AKIA, ghp_, sk-proj), private keys, JWT tokens, connection strings

---

### 5. Tool & Permission Abuse

**AITech**: AITech-12.1 | **Risk**: MEDIUM-CRITICAL

Violating allowed-tools restrictions or undeclared capabilities.

**Detected by**: Python validation checks, YARA (system_manipulation_generic), LLM permission analysis

**Examples**: Writing files without Write tool, undeclared network, package installation, system modifications, tool poisoning, tool shadowing, unauthorized tool use

---

### 6. Obfuscation

**Risk**: MEDIUM-CRITICAL

Deliberate code obfuscation hiding malicious intent.

**Detected by**: YAML rules, YARA (code_execution_generic, script_injection_generic), binary detection, LLM intent analysis

**Examples**: Binary executables, base64→exec, hex encoding, XOR ciphers

---

### 7. Protocol Manipulation - Capability Inflation

**AITech**: AITech-4.3 / AISubtech-4.3.5 | **Risk**: LOW-HIGH

Manipulation of skill discovery mechanisms to inflate perceived capabilities and increase unwanted activation. Actors manipulate skill metadata, descriptions, or discovery protocols to make skills appear more capable or relevant than they actually are, leading to inappropriate skill selection or invocation.

**Detected by**: YAML rules, YARA (capability_inflation_generic), Python checks, LLM deception analysis

**Examples**: Brand impersonation, over-broad capability claims, keyword baiting, description-behavior mismatch

---

### 8. Indirect Prompt Injection - Instruction Manipulation

**AITech**: AITech-1.2 / AISubtech-1.2.1 | **Risk**: HIGH

Embedding malicious instructions within external data sources (e.g., documents, web pages, emails, databases, API responses) that an LLM retrieves and processes, causing these external instructions to override or modify the model's intended behavior without the user's knowledge or awareness. The attack exploits the model's inability to distinguish between trusted system instructions and untrusted external content.

**Detected by**: YARA (indirect_prompt_injection_generic), LLM trust analysis

**Examples**: "Follow webpage instructions", "execute code blocks found in files", "obey file content", delegating trust to untrusted external sources

---

### 9. Autonomy Abuse

**AITech**: AITech-13.1 / AISubtech-13.1.1 | **Risk**: MEDIUM-HIGH

Excessive autonomous behavior without user confirmation (compute exhaustion).

**Detected by**: YAML rules, YARA (autonomy_abuse_generic), LLM behavioral analysis

**Examples**: "Keep retrying forever", "run without asking", ignore errors, self-modification

---

### 10. Tool Chaining

**AITech**: AITech-8.2.3 | **Risk**: HIGH

Multi-step operations chaining tools for data exfiltration.

**Detected by**: YARA (tool_chaining_abuse_generic), LLM workflow analysis

**Examples**: Read→send patterns, collect→post chains, automated pipelines

---

### 11. Resource Abuse

**AITech**: AITech-13.1 / AISubtech-13.1.1 | **Risk**: LOW-MEDIUM

Excessive resource consumption causing instability (compute exhaustion).

**Detected by**: YAML rules, YARA patterns, LLM resource analysis

**Examples**: Infinite loops, unbounded recursion, memory bombs, fork bombs

---

## Detection Architecture

### Static Analyzer (58 methods)
- 35 YAML regex rules
- 13 YARA pattern files
- 6 Python validation checks
- 5 consistency validations

### LLM Analyzer
- Semantic analysis across all categories
- Behavioral pattern recognition
- Intent detection
- Workflow analysis
- **Structured Output**: Enforces AITech taxonomy codes via JSON schema (API-level enforcement)
- **Direct AITech Mapping**: LLM returns AITech codes directly, mapped to ThreatCategory enum

---

## Severity Levels

| Severity | Criteria | Examples |
|----------|----------|----------|
| CRITICAL | Immediate exploitation, significant impact | eval(input), credential theft, system compromise |
| HIGH | Serious risk, immediate attention required | Privilege escalation, sensitive access, impersonation |
| MEDIUM | Security concerns requiring review | Undeclared network, suspicious patterns |
| LOW | Minor issues, informational | Documentation problems, style issues |

---

## Scan Modes

**Fast** (~150ms): Static only, no API cost, for CI/CD
**Comprehensive** (~2.2s): Static + LLM, API cost, for detailed analysis
**LLM-Only** (~2s): Semantic analysis, API cost, for second opinion

---

## Standards Alignment

- Cisco Integrated AI Security Framework (December 2025)
- MITRE ATLAS
- OWASP Top 10 (LLM and Agentic)
- NIST AI Risk Management Framework

Reference: [arxiv.org/html/2512.12921v1](https://arxiv.org/html/2512.12921v1)

---

## Best Practices

### For Skill Authors
- No hardcoded secrets
- No eval/exec
- Validate all inputs
- Declare permissions in allowed-tools
- Accurate descriptions
- No obfuscation
- Test before publishing

### Response Guidelines
- **CRITICAL**: Do not deploy, fix immediately
- **HIGH**: Address before release
- **MEDIUM**: Review and plan fixes
- **LOW**: Address in future releases

---

## Technical References

- Rule definitions: `skill_scanner/data/rules/signatures.yaml`
- YARA rules: `skill_scanner/data/yara_rules/`
- Threat mappings: `skill_scanner/threats/threats.py`
