# Unified Analyzer Response Schema

## Standard Security Finding Response Format

All analyzers (API, YARA, LLM) will return security findings with this unified structure:

```json
{
  "severity": "HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "summary": "Brief human-readable description of the threat",
  "threat_category": "Standardized threat type",
  "analyzer": "API|YARA|LLM",
  "details": {
    "skill_name": "Name of the analyzed skill",
    "threat_type": "Specific threat identified",
    "evidence": "Evidence or explanation of the finding",
    "source_rule": "Rule/model that detected this (optional)",
    "confidence_score": "Numeric confidence if available",
    "raw_response": "Original analyzer response (for debugging)"
  }
}
```

## Standardized Fields

### 1. **severity** (Required)
- **HIGH**: Critical security threats requiring immediate attention
- **MEDIUM**: Moderate security concerns that should be reviewed
- **LOW**: Minor issues or potential concerns

### 2. **confidence** (Required)
- **HIGH**: Very confident in the finding (>80% certainty)
- **MEDIUM**: Moderately confident (50-80% certainty)
- **LOW**: Low confidence, potential false positive (<50% certainty)

### 3. **threat_category** (Required)
Standardized threat categories across all analyzers:
- **PROMPT_INJECTION**: Malicious prompt manipulation
- **DATA_EXFILTRATION**: Unauthorized data access/transmission
- **CREDENTIAL_HARVESTING**: Attempts to collect sensitive credentials
- **SOCIAL_ENGINEERING**: Deceptive user manipulation
- **CODE_EXECUTION**: Arbitrary code execution risks
- **FILE_ACCESS**: Unauthorized file system access
- **NETWORK_ACCESS**: Suspicious network activity
- **PRIVILEGE_ESCALATION**: Attempts to gain elevated permissions
- **POLICY_VIOLATION**: Violation of security policies
- **MALICIOUS_BEHAVIOR**: General malicious activity

### 4. **details** Object Structure
- **skill_name**: Name of the analyzed Claude Skill
- **threat_type**: Specific sub-type of the threat_category
- **evidence**: Explanation of why this is flagged as a threat
- **source_rule**: Name of YARA rule, API classification, or LLM analysis type
- **confidence_score**: Numeric confidence (0-100) if available
- **raw_response**: Original response from the analyzer (for debugging)

## Analyzer-Specific Mappings

### API Analyzer Mapping
```
SECURITY_VIOLATION -> HIGH severity, POLICY_VIOLATION category
PROMPT_INJECTION -> HIGH severity, PROMPT_INJECTION category
HARASSMENT -> MEDIUM severity, SOCIAL_ENGINEERING category
HATE_SPEECH -> MEDIUM severity, SOCIAL_ENGINEERING category
TOXIC_CONTENT -> MEDIUM severity, SOCIAL_ENGINEERING category
VIOLENCE -> HIGH severity, MALICIOUS_BEHAVIOR category
CODE_DETECTION -> MEDIUM severity, CODE_EXECUTION category
```

### YARA Analyzer Mapping
```
Rule matches -> Severity based on rule metadata
Threat types mapped to standardized categories
Confidence HIGH for exact matches
```

### LLM Analyzer Mapping
```
CRITICAL -> HIGH severity
HIGH -> HIGH severity
MEDIUM -> MEDIUM severity
LOW -> LOW severity

Risk levels mapped to confidence:
>80% certainty -> HIGH confidence
50-80% certainty -> MEDIUM confidence
<50% certainty -> LOW confidence
```

## Benefits of Unified Schema

1. **Consistency**: All analyzers return the same field structure
2. **Clarity**: Standardized severity and confidence levels
3. **Compatibility**: Easy to process and display results
4. **Extensibility**: New analyzers can easily adopt this format
5. **User Experience**: No confusion about different field names or values
