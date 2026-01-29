#!/bin/bash
# Skill Scanner Pre-commit Hook
#
# This script scans agent skills for security vulnerabilities before commit.
# It blocks commits containing HIGH or CRITICAL severity findings.
#
# Installation:
#   1. Copy to .git/hooks/pre-commit
#   2. Or symlink: ln -s ../../scripts/pre-commit-hook.sh .git/hooks/pre-commit
#   3. Or run: skill-scanner-pre-commit install
#
# Configuration:
#   Create .skill_scannerrc in your repo root:
#   {
#     "severity_threshold": "high",
#     "skills_path": ".claude/skills",
#     "fail_fast": true
#   }
#
# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Configuration defaults
SEVERITY_THRESHOLD="${SKILL_ANALYZER_THRESHOLD:-high}"
SKILLS_PATH="${SKILL_ANALYZER_SKILLS_PATH:-.claude/skills}"

echo "🔍 Skill Scanner Pre-commit Hook"
echo "================================"

# Check if skill-scanner is installed
if ! command -v skill-scanner &> /dev/null; then
    echo -e "${YELLOW}Warning: skill-scanner not found in PATH${NC}"
    echo "Install with: pip install skill-scanner"
    echo "Skipping security scan..."
    exit 0
fi

# Check if Python hook is available (preferred)
if command -v skill-scanner-pre-commit &> /dev/null; then
    exec skill-scanner-pre-commit "$@"
fi

# Fallback: Manual skill scanning
echo "Looking for changed skills in: ${SKILLS_PATH}"

# Normalize skills path (remove trailing slash)
SKILLS_BASE="${SKILLS_PATH%/}"

# Get list of staged files in skills directory
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACMR | grep "^${SKILLS_BASE}/" || true)

if [ -z "$STAGED_FILES" ]; then
    echo -e "${GREEN}✅ No skill files staged for commit${NC}"
    exit 0
fi

# Extract unique skill directories regardless of depth
SKILL_DIRS=$(
    echo "$STAGED_FILES" | while read -r file; do
        [ -z "$file" ] && continue

        case "$file" in
            "${SKILLS_BASE}/"*)
                relative="${file#${SKILLS_BASE}/}"
                [ -z "$relative" ] && continue

                skill="${relative%%/*}"
                echo "${SKILLS_BASE}/${skill}"
                ;;
        esac
    done | sort -u
)
BLOCKED=0
TOTAL_FINDINGS=0

for SKILL_DIR in $SKILL_DIRS; do
    if [ -f "${SKILL_DIR}/SKILL.md" ]; then
        echo ""
        echo "📦 Scanning: ${SKILL_DIR}"

        # Run skill-scanner and capture output
        OUTPUT=$(skill-scanner scan "${SKILL_DIR}" --format json 2>/dev/null || echo '{"error": true}')

        # Check for critical/high findings using grep
        CRITICAL=$(echo "$OUTPUT" | grep -o '"severity": "critical"' | wc -l || echo "0")
        HIGH=$(echo "$OUTPUT" | grep -o '"severity": "high"' | wc -l || echo "0")
        MEDIUM=$(echo "$OUTPUT" | grep -o '"severity": "medium"' | wc -l || echo "0")
        LOW=$(echo "$OUTPUT" | grep -o '"severity": "low"' | wc -l || echo "0")

        TOTAL=$((CRITICAL + HIGH + MEDIUM + LOW))
        TOTAL_FINDINGS=$((TOTAL_FINDINGS + TOTAL))

        if [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ]; then
            echo -e "   ${RED}🚫 BLOCKED: ${CRITICAL} critical, ${HIGH} high findings${NC}"
            BLOCKED=1
        elif [ "$TOTAL" -gt 0 ]; then
            echo -e "   ${YELLOW}⚠️  ${TOTAL} finding(s) (below threshold)${NC}"
        else
            echo -e "   ${GREEN}✅ No issues found${NC}"
        fi
    fi
done

echo ""
echo "================================"

if [ "$BLOCKED" -eq 1 ]; then
    echo -e "${RED}❌ Commit BLOCKED${NC}"
    echo "   Fix HIGH/CRITICAL security issues before committing."
    echo "   Run: skill-scanner scan <skill-dir> --detailed"
    echo ""
    echo "   To bypass (not recommended): git commit --no-verify"
    exit 1
elif [ "$TOTAL_FINDINGS" -gt 0 ]; then
    echo -e "${YELLOW}⚠️  ${TOTAL_FINDINGS} total finding(s) detected${NC}"
    echo "   Consider reviewing with: skill-scanner scan <skill-dir>"
fi

echo -e "${GREEN}✅ Pre-commit checks passed${NC}"
exit 0
