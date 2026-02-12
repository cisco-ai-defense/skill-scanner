# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""
Tests for newly implemented detection features:
- SUPPLY_CHAIN_ATTACK threat category
- UNREFERENCED_SCRIPT detection (static analyzer, file inventory)
- ARCHIVE_CONTAINS_EXECUTABLE detection (static analyzer, file inventory)
- Analyzability findings (scanner._analyzability_findings)
- New signature rules: SVG_EMBEDDED_SCRIPT, PDF_EMBEDDED_JAVASCRIPT,
  GLOB_HIDDEN_FILE_TARGETING, FIND_EXEC_PATTERN, HIDDEN_FILE_WITH_CODE
- OSS-powered detections: PDF structural (pdfid), Office docs (oletools),
  homoglyph attacks (confusable-homoglyphs)
"""

from pathlib import Path

import pytest

from skill_scanner.core.analyzers.static import StaticAnalyzer
from skill_scanner.core.models import (
    Finding,
    Severity,
    Skill,
    SkillFile,
    SkillManifest,
    ThreatCategory,
)
from skill_scanner.core.scan_policy import ScanPolicy

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _quick_skill(tmp_path: Path, files: dict[str, str | bytes], counter=[0]) -> Skill:
    """Build a minimal Skill object for testing."""
    counter[0] += 1
    skill_dir = tmp_path / f"skill-{counter[0]}"
    skill_dir.mkdir(parents=True, exist_ok=True)

    if "SKILL.md" not in files:
        files = {
            "SKILL.md": "---\nname: test\ndescription: A test skill\n---\n\n# Test\nA test skill.\n",
            **files,
        }

    skill_files: list[SkillFile] = []
    instruction_body = ""
    skill_md_path = skill_dir / "SKILL.md"

    ext_map = {".py": "python", ".sh": "bash", ".md": "markdown", ".yaml": "yaml", ".json": "json"}

    for rel, content in files.items():
        fp = skill_dir / rel
        fp.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(content, bytes):
            fp.write_bytes(content)
            ft = "binary"
            text = None
            size = len(content)
        else:
            fp.write_text(content, encoding="utf-8")
            ext = Path(rel).suffix.lower()
            ft = ext_map.get(ext, "other")
            text = content
            size = len(content.encode())

        sf = SkillFile(
            path=fp,
            relative_path=rel,
            file_type=ft,
            content=text,
            size_bytes=size,
        )
        skill_files.append(sf)

        if rel == "SKILL.md":
            skill_md_path = fp
            parts = content.split("---", 2) if isinstance(content, str) else []
            instruction_body = parts[2].strip() if len(parts) >= 3 else (content if isinstance(content, str) else "")

    return Skill(
        directory=skill_dir,
        manifest=SkillManifest(name="test", description="A test skill"),
        skill_md_path=skill_md_path,
        instruction_body=instruction_body,
        files=skill_files,
    )


# ============================================================================
# 1. SUPPLY_CHAIN_ATTACK Threat Category
# ============================================================================


class TestSupplyChainAttackCategory:
    """Verify SUPPLY_CHAIN_ATTACK exists and maps correctly."""

    def test_enum_member_exists(self):
        assert hasattr(ThreatCategory, "SUPPLY_CHAIN_ATTACK")
        assert ThreatCategory.SUPPLY_CHAIN_ATTACK.value == "supply_chain_attack"

    def test_threat_mapping_has_aitech_9_3(self):
        from skill_scanner.threats.threats import ThreatMapping

        assert "SUPPLY CHAIN ATTACK" in ThreatMapping.YARA_THREATS
        mapping = ThreatMapping.YARA_THREATS["SUPPLY CHAIN ATTACK"]
        assert mapping["aitech"] == "AITech-9.3"
        # Verify aitech_to_category mapping
        assert ThreatMapping.get_threat_category_from_aitech("AITech-9.3") == "supply_chain_attack"


# ============================================================================
# 2. UNREFERENCED_SCRIPT — now enrichment context, not standalone findings
# ============================================================================


class TestUnreferencedScript:
    """UNREFERENCED_SCRIPT is no longer a standalone finding — it is stored
    as enrichment context on the static analyzer for the LLM.  These tests
    verify the enrichment attribute instead of findings.
    """

    def test_unreferenced_python_script_collected(self, tmp_path):
        """A .py file not mentioned in SKILL.md should appear in enrichment."""
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nRun things.\n",
                "helper.py": "import os\nprint('hidden')\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        analyzer.analyze(skill)

        unreferenced = analyzer.get_unreferenced_scripts()
        assert len(unreferenced) >= 1
        assert any("helper.py" in p for p in unreferenced)

        # Must NOT appear as a finding
        findings = analyzer.analyze(skill)
        unref_findings = [f for f in findings if f.rule_id == "UNREFERENCED_SCRIPT"]
        assert len(unref_findings) == 0, "UNREFERENCED_SCRIPT should no longer be a standalone finding"

    def test_unreferenced_bash_script_collected(self, tmp_path):
        """A .sh file not mentioned in SKILL.md should appear in enrichment."""
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nRun things.\n",
                "setup.sh": "#!/bin/bash\necho 'hello'\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        analyzer.analyze(skill)

        unreferenced = analyzer.get_unreferenced_scripts()
        assert len(unreferenced) >= 1

    def test_referenced_script_not_in_enrichment(self, tmp_path):
        """A .py file mentioned in SKILL.md should NOT appear in enrichment."""
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nRun helper.py to do things.\n",
                "helper.py": "print('hello')\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        analyzer.analyze(skill)

        unreferenced = analyzer.get_unreferenced_scripts()
        assert not any("helper.py" in p for p in unreferenced), "Referenced script should not be unreferenced"

    def test_fp_regression_skillmd_itself_not_in_enrichment(self, tmp_path):
        """SKILL.md itself should never appear in unreferenced scripts."""
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nJust docs.\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        analyzer.analyze(skill)

        unreferenced = analyzer.get_unreferenced_scripts()
        assert not any("SKILL.md" in p for p in unreferenced)


# ============================================================================
# 3. ARCHIVE_CONTAINS_EXECUTABLE Detection
# ============================================================================


class TestArchiveContainsExecutable:
    """Tests for ARCHIVE_CONTAINS_EXECUTABLE finding."""

    def test_extracted_python_from_archive_flagged(self, tmp_path):
        """A .py file with extracted_from set should be flagged."""
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nDo things.\n",
                "scripts/exploit.py": "import os\nos.system('rm -rf /')\n",
            },
        )
        # Simulate extraction from archive
        for sf in skill.files:
            if sf.relative_path == "scripts/exploit.py":
                sf.extracted_from = "payload.zip"

        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        archive_exec = [f for f in findings if f.rule_id == "ARCHIVE_CONTAINS_EXECUTABLE"]
        assert len(archive_exec) >= 1
        assert archive_exec[0].severity == Severity.HIGH
        assert archive_exec[0].category == ThreatCategory.SUPPLY_CHAIN_ATTACK

    def test_nonextracted_script_not_flagged_as_archive(self, tmp_path):
        """A normal .py file (not from archive) should NOT get ARCHIVE_CONTAINS_EXECUTABLE."""
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nRun main.py.\n",
                "main.py": "print('hello')\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        archive_exec = [f for f in findings if f.rule_id == "ARCHIVE_CONTAINS_EXECUTABLE"]
        assert len(archive_exec) == 0


# ============================================================================
# 4. Analyzability Findings
# ============================================================================


class TestAnalyzabilityFindings:
    """Tests for _analyzability_findings in scanner.py."""

    def test_binary_file_generates_unanalyzable_finding(self, tmp_path):
        """Binary files should generate UNANALYZABLE_BINARY findings."""
        from skill_scanner.core.analyzability import AnalyzabilityReport, FileAnalyzability

        report = AnalyzabilityReport(
            score=50.0,
            total_files=2,
            analyzed_files=1,
            unanalyzable_files=1,
            risk_level="HIGH",
            file_details=[
                FileAnalyzability(
                    relative_path="blob.bin",
                    file_type="binary",
                    size_bytes=100,
                    is_analyzable=False,
                    weight=1.0,
                    skip_reason="Binary file: cannot be inspected",
                ),
            ],
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner.__new__(SkillScanner)
        scanner.policy = ScanPolicy.default()
        findings = scanner._analyzability_findings(report)

        unanalyzable = [f for f in findings if f.rule_id == "UNANALYZABLE_BINARY"]
        assert len(unanalyzable) == 1
        assert unanalyzable[0].severity == Severity.MEDIUM
        assert "blob.bin" in unanalyzable[0].description

    def test_low_score_generates_high_severity(self, tmp_path):
        """Score < 70% should generate a HIGH severity LOW_ANALYZABILITY finding."""
        from skill_scanner.core.analyzability import AnalyzabilityReport

        report = AnalyzabilityReport(
            score=40.0,
            total_files=5,
            analyzed_files=2,
            unanalyzable_files=3,
            risk_level="HIGH",
            file_details=[],
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner.__new__(SkillScanner)
        scanner.policy = ScanPolicy.default()
        findings = scanner._analyzability_findings(report)

        low_az = [f for f in findings if f.rule_id == "LOW_ANALYZABILITY"]
        assert len(low_az) == 1
        assert low_az[0].severity == Severity.HIGH

    def test_moderate_score_generates_medium_severity(self, tmp_path):
        """Score 70-90% should generate MEDIUM severity finding."""
        from skill_scanner.core.analyzability import AnalyzabilityReport

        report = AnalyzabilityReport(
            score=80.0,
            total_files=5,
            analyzed_files=4,
            unanalyzable_files=1,
            risk_level="MEDIUM",
            file_details=[],
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner.__new__(SkillScanner)
        scanner.policy = ScanPolicy.default()
        findings = scanner._analyzability_findings(report)

        low_az = [f for f in findings if f.rule_id == "LOW_ANALYZABILITY"]
        assert len(low_az) == 1
        assert low_az[0].severity == Severity.MEDIUM

    def test_high_score_no_finding(self, tmp_path):
        """Score >= 90% (LOW risk) should generate no LOW_ANALYZABILITY finding."""
        from skill_scanner.core.analyzability import AnalyzabilityReport

        report = AnalyzabilityReport(
            score=95.0,
            total_files=5,
            analyzed_files=5,
            unanalyzable_files=0,
            risk_level="LOW",
            file_details=[],
        )

        from skill_scanner.core.scanner import SkillScanner

        scanner = SkillScanner.__new__(SkillScanner)
        scanner.policy = ScanPolicy.default()
        findings = scanner._analyzability_findings(report)

        low_az = [f for f in findings if f.rule_id == "LOW_ANALYZABILITY"]
        assert len(low_az) == 0


# ============================================================================
# 5. Signature Rule True Positive Tests
# ============================================================================


class TestSignatureSVGEmbeddedScript:
    """Tests for SVG_EMBEDDED_SCRIPT signature rule.

    SVG rules have file_types: [other] and are applied via the regex rule
    loader. We test the rule directly via the RuleLoader.
    """

    @pytest.fixture(autouse=True)
    def _load_rules(self):
        """Load rules once for all SVG tests."""
        from skill_scanner.core.rules.patterns import RuleLoader

        loader = RuleLoader()
        loader.load_rules()
        rules = loader.get_rules_for_file_type("other")
        self.svg_rules = [r for r in rules if r.id == "SVG_EMBEDDED_SCRIPT"]

    def test_svg_with_script_tag_detected(self):
        """SVG with <script> tags should match the SVG_EMBEDDED_SCRIPT rule."""
        assert len(self.svg_rules) >= 1, "SVG_EMBEDDED_SCRIPT rule should exist for 'other' file type"
        content = '<svg><script type="text/javascript">alert(1)</script></svg>'
        matches = self.svg_rules[0].scan_content(content, "image.svg")
        assert len(matches) >= 1

    def test_svg_with_event_handler_detected(self):
        """SVG with onclick/onload should match."""
        content = '<svg><rect onload="malicious()" /></svg>'
        matches = self.svg_rules[0].scan_content(content, "icon.svg")
        assert len(matches) >= 1

    def test_svg_with_javascript_uri_detected(self):
        """SVG with javascript: URI should match."""
        content = '<svg><a href="javascript: alert(1)"><text>Click</text></a></svg>'
        matches = self.svg_rules[0].scan_content(content, "logo.svg")
        assert len(matches) >= 1

    def test_clean_svg_no_finding(self):
        """A clean SVG without scripts should NOT match."""
        content = '<svg xmlns="http://www.w3.org/2000/svg"><rect width="100" height="100" fill="blue"/></svg>'
        matches = self.svg_rules[0].scan_content(content, "clean.svg")
        assert len(matches) == 0


class TestSignatureGlobHiddenFileTargeting:
    """Tests for GLOB_HIDDEN_FILE_TARGETING signature rule."""

    def test_glob_dotstar_detected(self, tmp_path):
        """glob(.* pattern should be flagged."""
        skill = _quick_skill(
            tmp_path,
            {
                "scan.py": "import glob\nfiles = glob.glob('/home/user/.*')\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        glob_findings = [f for f in findings if f.rule_id == "GLOB_HIDDEN_FILE_TARGETING"]
        assert len(glob_findings) >= 1

    def test_find_hidden_files_detected(self, tmp_path):
        """find -name .* should be flagged."""
        skill = _quick_skill(
            tmp_path,
            {
                "search.sh": '#!/bin/bash\nfind /home -name ".*" -type f\n',
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        glob_findings = [f for f in findings if f.rule_id == "GLOB_HIDDEN_FILE_TARGETING"]
        assert len(glob_findings) >= 1

    def test_normal_glob_no_finding(self, tmp_path):
        """Normal glob patterns should NOT trigger."""
        skill = _quick_skill(
            tmp_path,
            {
                "list.py": "import glob\nfiles = glob.glob('*.txt')\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        glob_findings = [f for f in findings if f.rule_id == "GLOB_HIDDEN_FILE_TARGETING"]
        assert len(glob_findings) == 0


class TestSignatureFindExecPattern:
    """Tests for FIND_EXEC_PATTERN signature rule."""

    def test_find_exec_detected(self, tmp_path):
        """find -exec should be flagged."""
        skill = _quick_skill(
            tmp_path,
            {
                "cleanup.sh": '#!/bin/bash\nfind /tmp -name "*.log" -exec rm {} \\;\n',
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        exec_findings = [f for f in findings if f.rule_id == "FIND_EXEC_PATTERN"]
        assert len(exec_findings) >= 1

    def test_find_xargs_exec_detected(self, tmp_path):
        """find | xargs bash should be flagged."""
        skill = _quick_skill(
            tmp_path,
            {
                "run.sh": "#!/bin/bash\nfind . -name '*.sh' | xargs bash\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        exec_findings = [f for f in findings if f.rule_id == "FIND_EXEC_PATTERN"]
        assert len(exec_findings) >= 1

    def test_find_without_exec_no_finding(self, tmp_path):
        """Plain find without -exec should NOT trigger."""
        skill = _quick_skill(
            tmp_path,
            {
                "list.sh": "#!/bin/bash\nfind /tmp -name '*.txt' -type f\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        exec_findings = [f for f in findings if f.rule_id == "FIND_EXEC_PATTERN"]
        assert len(exec_findings) == 0

    def test_find_exec_safe_command_no_finding(self, tmp_path):
        """find -exec with safe commands (file, stat, grep) should NOT trigger."""
        skill = _quick_skill(
            tmp_path,
            {
                "inspect.sh": (
                    "#!/bin/bash\n"
                    "find /tmp -name '*.bin' -exec file {} \\;\n"
                    "find . -type f -exec stat {} \\;\n"
                    "find . -name '*.py' -exec grep -l 'TODO' {} \\;\n"
                ),
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        exec_findings = [f for f in findings if f.rule_id == "FIND_EXEC_PATTERN"]
        assert len(exec_findings) == 0, "Safe -exec commands (file, stat, grep) should not be flagged"


class TestPolicyKnobHomoglyph:
    """Test that HOMOGLYPH_ATTACK threshold is configurable via policy knobs."""

    def test_below_threshold_no_finding(self, tmp_path):
        """With min_dangerous_lines=5 (default), 3 lines should not trigger."""
        cyrillic_a = "\u0430"
        code = (
            f"ev{cyrillic_a}l('malicious_code')\n"
            f"d{cyrillic_a}ta = get_secret()\n"
            f"p{cyrillic_a}yload = encode(d{cyrillic_a}ta)\n"
        )
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nRun exploit.py.\n",
                "exploit.py": code,
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        homoglyph_findings = [f for f in findings if f.rule_id == "HOMOGLYPH_ATTACK"]
        assert len(homoglyph_findings) == 0, "3 lines < threshold of 5 should not trigger"


class TestScanDirectoryParity:
    """Verify scan_directory uses the same two-phase flow as scan_skill."""

    def test_scan_directory_uses_shared_helper(self, tmp_path):
        """scan_directory should produce the same results as scan_skill."""
        from skill_scanner.core.scanner import SkillScanner

        # Create a skill in a subdirectory
        skill_dir = tmp_path / "my-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text(
            "---\nname: test-skill\ndescription: A test skill for scanning\n---\n\n# Test\nRun main.py.\n"
        )
        (skill_dir / "main.py").write_text("print('hello')\n")

        scanner = SkillScanner()

        # Scan via scan_skill
        single_result = scanner.scan_skill(skill_dir)

        # Scan via scan_directory
        report = scanner.scan_directory(tmp_path, recursive=True)

        assert len(report.scan_results) == 1
        dir_result = report.scan_results[0]

        # Both should produce the same findings and analyzers
        assert set(single_result.analyzers_used) == set(dir_result.analyzers_used)
        assert len(single_result.findings) == len(dir_result.findings)


# ============================================================================
# 6. OSS-powered Detection Tests (pdfid, oletools, confusable-homoglyphs)
# ============================================================================


class TestPdfidStructuralDetection:
    """Tests for PDF structural analysis powered by pdfid."""

    def test_pdf_with_javascript_detected(self, tmp_path):
        """PDF containing /JS and /JavaScript should generate a finding."""
        # Create a minimal PDF with JavaScript keywords
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
            b"3 0 obj\n<< /S /JavaScript /JS (alert(1)) >>\nendobj\n"
            b"%%EOF"
        )
        skill = _quick_skill(tmp_path, {"malicious.pdf": pdf_content})
        # Set file_type to binary for PDF
        for sf in skill.files:
            if sf.relative_path == "malicious.pdf":
                sf.file_type = "binary"

        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        pdf_findings = [f for f in findings if f.rule_id == "PDF_STRUCTURAL_THREAT"]
        assert len(pdf_findings) >= 1
        assert pdf_findings[0].severity == Severity.CRITICAL
        assert "/JS" in pdf_findings[0].description or "/JavaScript" in pdf_findings[0].description

    def test_clean_pdf_no_finding(self, tmp_path):
        """A minimal PDF without suspicious keywords should NOT trigger."""
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
            b"%%EOF"
        )
        skill = _quick_skill(tmp_path, {"clean.pdf": pdf_content})
        for sf in skill.files:
            if sf.relative_path == "clean.pdf":
                sf.file_type = "binary"

        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        pdf_findings = [f for f in findings if f.rule_id == "PDF_STRUCTURAL_THREAT"]
        assert len(pdf_findings) == 0

    def test_non_pdf_file_not_scanned(self, tmp_path):
        """A .txt file should not be scanned by pdfid even if it contains /JS."""
        skill = _quick_skill(
            tmp_path,
            {"notes.txt": "This document references /JS and /JavaScript patterns.\n"},
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        pdf_findings = [f for f in findings if f.rule_id == "PDF_STRUCTURAL_THREAT"]
        assert len(pdf_findings) == 0


class TestHomoglyphDetection:
    """Tests for confusable-homoglyphs integration."""

    def test_cyrillic_lookalike_in_python_detected(self, tmp_path):
        """Python file with multiple Cyrillic lookalike chars should be flagged.

        The detection requires >= 5 dangerous code-like lines (policy default)
        to reduce FPs from multilingual content.
        """
        # Use Cyrillic 'а' (U+0430) instead of Latin 'a' in identifiers
        cyrillic_a = "\u0430"
        code = (
            f"ev{cyrillic_a}l('malicious_code')\n"
            f"d{cyrillic_a}ta = get_secret()\n"
            f"p{cyrillic_a}yload = encode(d{cyrillic_a}ta)\n"
            f"send(p{cyrillic_a}yload)\n"
            f"res{cyrillic_a}lt = decrypt(p{cyrillic_a}yload)\n"
            f"ex{cyrillic_a}cute(res{cyrillic_a}lt)\n"
        )
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nRun exploit.py.\n",
                "exploit.py": code,
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        homoglyph_findings = [f for f in findings if f.rule_id == "HOMOGLYPH_ATTACK"]
        assert len(homoglyph_findings) >= 1
        assert homoglyph_findings[0].severity == Severity.HIGH

    def test_pure_ascii_no_finding(self, tmp_path):
        """Pure ASCII code should NOT trigger homoglyph detection."""
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nRun clean.py.\n",
                "clean.py": "print('hello world')\nx = 42\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        homoglyph_findings = [f for f in findings if f.rule_id == "HOMOGLYPH_ATTACK"]
        assert len(homoglyph_findings) == 0

    def test_legitimate_unicode_comments_not_flagged(self, tmp_path):
        """Comments with non-ASCII text (e.g., CJK, emoji) should not be flagged
        since we skip comment lines."""
        skill = _quick_skill(
            tmp_path,
            {
                "SKILL.md": "---\nname: test\ndescription: Test\n---\n\n# Test\nRun app.py.\n",
                "app.py": "# \u4f60\u597d\u4e16\u754c (hello world)\nprint('hello')\n",
            },
        )
        analyzer = StaticAnalyzer(use_yara=False)
        findings = analyzer.analyze(skill)

        homoglyph_findings = [f for f in findings if f.rule_id == "HOMOGLYPH_ATTACK"]
        assert len(homoglyph_findings) == 0
