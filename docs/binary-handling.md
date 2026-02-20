# Binary File Handling in Agent Skills

## Current Behavior

### Detection

When the scanner finds binary files in a skill package:

**Detected as binary:**
- `.exe`, `.so`, `.dylib`, `.dll`, `.bin` extensions
- Files that fail UTF-8 decoding

**Action taken:**
- Flagged as CRITICAL threat
- Severity: CRITICAL
- Category: OBFUSCATION
- Title: "Binary executable in skill package"
- Remediation: "Remove binary files. Use Python or Bash scripts only"

### Why Binary Files Are Dangerous

**Security risks:**
1. **Unauditable** - Can't read/inspect the code
2. **Platform-specific malware** - Could be trojans, keyloggers, ransomware
3. **Obfuscation** - Hides malicious behavior
4. **Execution risk** - Could be run by user or agent
5. **Supply chain attack** - Common malware delivery method

**Example threat:**
```
skill-package/
├── SKILL.md (claims: "helpful utilities")
└── assets/
    └── helper.exe  # Actually: keylogger or backdoor
```

## What We Currently Do

### Static Analyzer

**From `static.py` lines 264-280:**

```python
def _check_binary_files(self, skill: Skill) -> List[Finding]:
    """Check for binary executables in skill package."""
    for skill_file in skill.files:
        if skill_file.file_type == 'binary':
            # CRITICAL finding
            findings.append(Finding(
                severity=Severity.CRITICAL,
                category=ThreatCategory.OBFUSCATION,
                title="Binary executable in skill package",
                description=f"Binary file detected: {skill_file.relative_path}",
                remediation="Remove binary files. Use Python or Bash scripts only"
            ))
```

**Result**: Binary files are detected and reported at INFO level (informational only).

## Potential Improvements

### 1. Hash-Based Analysis (Add to Behavioral Analyzer)

**What we could do:**
```python
def analyze_binary(self, binary_path: Path) -> Finding:
    """Analyze binary file with hash checking."""

    # Calculate SHA-256
    sha256 = hashlib.sha256(binary_path.read_bytes()).hexdigest()

    # Check against known malware databases
    # - VirusTotal API
    # - NIST NVD
    # - Local malware hash database

    if sha256 in KNOWN_MALWARE_HASHES:
        return Finding(
            severity=Severity.CRITICAL,
            title="Known malware detected",
            description=f"Binary matches known malware: {sha256}"
        )
```

**Benefits:**
- Detect known malware instantly
- No false positives on legitimate binaries
- Fast hash lookup

**Implementation needed:**
- Add VirusTotal API integration
- Maintain local malware hash database
- Add to behavioral analyzer

### 2. Metadata Extraction

**What we could do:**
```python
# For Windows .exe files
import pefile

pe = pefile.PE(binary_path)
metadata = {
    "company": pe.FileInfo[0].StringTable[0].entries[b'CompanyName'],
    "description": pe.FileInfo[0].StringTable[0].entries[b'FileDescription'],
    "version": pe.FileInfo[0].StringTable[0].entries[b'FileVersion'],
}

# Check for suspicious metadata
if "attacker" in metadata['company'].lower():
    return Finding(severity=Severity.CRITICAL, ...)
```

**Benefits:**
- Extract file version, company, description
- Detect suspicious metadata
- Identify unsigned binaries

**Implementation needed:**
- Add `pefile` for Windows executables
- Add `pyelftools` for Linux binaries
- Add `macholib` for macOS binaries

### 3. Sandboxed Execution Analysis

**What we could do:**
```python
# Run in isolated Docker container
def analyze_binary_behavior(self, binary_path: Path) -> List[Finding]:
    """Execute binary in sandbox and monitor behavior."""

    # Run in restricted Docker container
    result = docker.run(
        image="alpine",
        command=[str(binary_path)],
        network="none",
        read_only=True,
        timeout=30
    )

    # Monitor: network attempts, file access, syscalls
    if "network" in result.attempted_operations:
        return Finding(severity=Severity.CRITICAL,
                      title="Binary attempted network access")
```

**Benefits:**
- See what binary actually does
- Detect runtime behavior
- Catch sophisticated malware

**Implementation needed:**
- Docker integration
- System call monitoring (strace, eBPF)
- Behavioral analysis framework

## Recommendation for Now

**Current behavior is CORRECT:**
- [OK] **Flag all binaries as CRITICAL** (safe default)
- [OK] **Recommend removal** (best practice)
- [OK] **No false negatives** (catch everything)

**Legitimate use case**: Some skills might bundle:
- Compiled data processing tools
- Platform-specific utilities
- Signed system utilities

**For these, users can:**
1. **Whitelist specific binaries** (future feature)
2. **Provide hash verification** (future feature)
3. **Replace with Python/Bash** (recommended now)

## Future Enhancements Priority

1. **High Priority**: Hash-based malware detection (quick win)
2. **Medium Priority**: Metadata extraction for Windows/Linux/macOS
3. **Low Priority**: Sandboxed execution (complex, resource-intensive)

## Current Behavior (v0.2.0)

**Binary files are detected and highlighted:**
- Severity: INFO (informational, doesn't block)
- Purpose: Make user aware of binary files
- Recommendation: Use auditable Python/Bash scripts when possible
- Not blocked: Users can decide if binary is legitimate

**For v0.3.0:**
- Add hash-based malware detection
- Add binary metadata extraction
- Add whitelist configuration option

---

*Current status: All binaries flagged as CRITICAL threat*
*Improvement potential: Hash checking, metadata extraction, sandbox execution*
*Recommendation: Current behavior is secure - improvements are enhancements, not fixes*
