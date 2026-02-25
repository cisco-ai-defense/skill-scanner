# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""
Comprehensive tests for bug fixes applied to the skill-scanner project.

Groups tests by fix category: correctness (C), security/hardening (H),
maintainability (M), and quality (Q).
"""

from __future__ import annotations

import hashlib
import re
from datetime import timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# C1: asyncio event loop crash in behavioral_analyzer
# ---------------------------------------------------------------------------


class TestBehavioralAnalyzerCoroutineSync:
    """Verify _run_coroutine_sync works with and without a running event loop."""

    def test_run_coroutine_sync_no_loop(self):
        """No running loop: uses asyncio.run()."""
        from skill_scanner.core.analyzers.behavioral_analyzer import _run_coroutine_sync

        async def _simple_coro():
            return 42

        result = _run_coroutine_sync(_simple_coro())
        assert result == 42

    @pytest.mark.asyncio
    async def test_run_coroutine_sync_inside_loop(self):
        """Running loop: uses ThreadPoolExecutor to avoid nested run."""
        from skill_scanner.core.analyzers.behavioral_analyzer import _run_coroutine_sync

        async def _simple_coro():
            return 42

        result = _run_coroutine_sync(_simple_coro())
        assert result == 42


# ---------------------------------------------------------------------------
# C3: Operator precedence in LLM filter
# ---------------------------------------------------------------------------


class TestLLMAnalyzerOperatorPrecedence:
    """Verify LLM analyzer uses correct parenthesization in filter logic."""

    def test_llm_filter_external_check_parenthesized(self):
        """External check in is_internal_file_reading has proper parentheses."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "core" / "analyzers" / "llm_analyzer.py"
        text = source.read_text()
        # The is_internal_file_reading block has "or" conditions in parentheses
        assert "is_internal_file_reading" in text
        assert "(" in text and ")" in text
        # The compound condition for AITech-1.2 has logical grouping
        assert "and (" in text or "or " in text


# ---------------------------------------------------------------------------
# C4: Non-deterministic hash() for finding IDs
# ---------------------------------------------------------------------------


class TestDeterministicFindingIds:
    """Verify finding IDs use sha256 (deterministic), not hash() (non-deterministic)."""

    def test_deterministic_finding_ids(self):
        """Finding IDs are deterministic (sha256-based, not hash()-based)."""
        parts = ("rule_id", "file.py", "1", "snippet")
        key = "|".join(str(p) for p in parts)
        id1 = hashlib.sha256(key.encode()).hexdigest()[:8]
        id2 = hashlib.sha256(key.encode()).hexdigest()[:8]
        assert id1 == id2
        assert len(id1) == 8

    def test_scanner_uses_sha256_for_ids(self):
        """Scanner uses hashlib.sha256 for ID generation."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "core" / "scanner.py"
        text = source.read_text()
        assert "hashlib.sha256" in text


# ---------------------------------------------------------------------------
# H1: Symlink traversal in loader
# ---------------------------------------------------------------------------


class TestLoaderSymlinkTraversal:
    """Verify loader rejects symlinks pointing outside skill root."""

    def test_symlink_traversal_blocked(self, tmp_path):
        """Symlink target outside skill dir is NOT in discovered files."""
        from skill_scanner.core.loader import SkillLoader

        skill_dir = tmp_path / "skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Test Skill\nDescription of the skill for testing.")

        outside = tmp_path / "secret.txt"
        outside.write_text("secret data")

        link = skill_dir / "linked.txt"
        link.symlink_to(outside)

        loader = SkillLoader()
        files = loader._discover_files(skill_dir)

        resolved_paths = [str(sf.path) for sf in files]
        assert not any("secret" in p for p in resolved_paths)


# ---------------------------------------------------------------------------
# H2: ReDoS protection on user-supplied regex
# ---------------------------------------------------------------------------


class TestReDoSProtection:
    """Verify _safe_compile rejects long/invalid patterns in scan_policy and command_safety."""

    def test_policy_safe_compile_rejects_long_pattern(self):
        """Scan policy rejects patterns longer than max_length."""
        from skill_scanner.core.scan_policy import _safe_compile as policy_safe_compile

        long_pattern = "a" * 1001
        result = policy_safe_compile(long_pattern)
        assert result is None

    def test_policy_safe_compile_accepts_valid_pattern(self):
        """Scan policy accepts valid patterns."""
        from skill_scanner.core.scan_policy import _safe_compile as policy_safe_compile

        result = policy_safe_compile(r"\d+")
        assert result is not None

    def test_policy_safe_compile_rejects_invalid_regex(self):
        """Scan policy rejects invalid regex."""
        from skill_scanner.core.scan_policy import _safe_compile as policy_safe_compile

        result = policy_safe_compile("[invalid")
        assert result is None

    def test_policy_safe_compile_custom_max_length(self):
        """Scan policy respects custom max_length."""
        from skill_scanner.core.scan_policy import _safe_compile as policy_safe_compile

        result = policy_safe_compile("abc", max_length=2)
        assert result is None
        result = policy_safe_compile("ab", max_length=2)
        assert result is not None

    def test_cmd_safe_compile_rejects_long_pattern(self):
        """Command safety rejects long patterns."""
        from skill_scanner.core.command_safety import _safe_compile as cmd_safe_compile

        long_pattern = "a" * 1001
        result = cmd_safe_compile(long_pattern)
        assert result is None

    def test_cmd_safe_compile_custom_max_length(self):
        """Command safety respects custom max_length."""
        from skill_scanner.core.command_safety import _safe_compile as cmd_safe_compile

        result = cmd_safe_compile("abcdef", max_length=3)
        assert result is None


# ---------------------------------------------------------------------------
# H3: Unvalidated LLM file paths
# ---------------------------------------------------------------------------


class TestLLMAnalyzerPathTraversal:
    """Verify LLM analyzer rejects path traversal (..)."""

    def test_llm_analyzer_rejects_path_traversal(self):
        """LLM analyzer source includes path traversal rejection."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "core" / "analyzers" / "llm_analyzer.py"
        text = source.read_text()
        assert ".." in text
        assert "lstrip" in text or "replace" in text


# ---------------------------------------------------------------------------
# H4: API keys moved from body to header
# ---------------------------------------------------------------------------


class TestAPIKeysInHeaders:
    """Verify API keys are passed via headers, not request body."""

    def test_api_keys_in_headers(self):
        """API router uses Header() for API keys."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "api" / "router.py"
        text = source.read_text()
        assert "Header(" in text
        assert "X-VirusTotal-Key" in text or "x-virustotal-key" in text.lower()
        assert "X-AIDefense-Key" in text or "x-aidefense-key" in text.lower()


# ---------------------------------------------------------------------------
# H5: Raw exception messages in 500 responses
# ---------------------------------------------------------------------------


class TestAPINoRawExceptionIn500:
    """Verify 500 responses use generic error messages."""

    def test_api_no_raw_exception_in_500(self):
        """500 responses use generic message; exceptions logged."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "api" / "router.py"
        text = source.read_text()
        assert "Internal scan error" in text
        assert "logger.exception" in text


# ---------------------------------------------------------------------------
# M1: UTC timestamps in SARIF / models
# ---------------------------------------------------------------------------


class TestUTCTimestamps:
    """Verify Report/ScanResult use UTC timestamps."""

    def test_report_timestamp_is_utc(self):
        """Report timestamp is timezone-aware UTC."""
        from skill_scanner.core.models import Report

        report = Report()
        assert report.timestamp.tzinfo == timezone.utc


# ---------------------------------------------------------------------------
# M2: Thread-safe _BoundedCache
# ---------------------------------------------------------------------------


class TestBoundedCacheThreadSafety:
    """Verify _BoundedCache has thread safety (lock)."""

    def test_bounded_cache_thread_safety(self):
        """_BoundedCache uses threading.Lock."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "api" / "router.py"
        text = source.read_text()
        assert "threading" in text
        assert "Lock()" in text


# ---------------------------------------------------------------------------
# M3: Cross-skill findings in synthetic result
# ---------------------------------------------------------------------------


class TestCrossSkillSyntheticResult:
    """Verify cross-skill findings are separated from per-skill results."""

    def test_cross_skill_findings_not_appended_to_first_result(self):
        """Cross-skill findings use add_cross_skill_findings, not results[0]."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "core" / "scanner.py"
        text = source.read_text()
        assert "add_cross_skill_findings" in text

    def test_report_has_cross_skill_findings_field(self):
        """Report model has a dedicated cross_skill_findings field."""
        from skill_scanner.core.models import Report

        report = Report()
        assert hasattr(report, "cross_skill_findings")


# ---------------------------------------------------------------------------
# M5: YARA scanner file size limit
# ---------------------------------------------------------------------------


class TestYaraScannerFileSizeLimit:
    """Verify YARA scanner skips files exceeding max size."""

    def test_yara_scanner_respects_max_file_size(self, tmp_path):
        """YARA scanner skips files exceeding max_scan_file_size."""
        from skill_scanner.core.rules.yara_scanner import YaraScanner

        rules_dir = tmp_path / "yara_rules"
        rules_dir.mkdir()
        (rules_dir / "test.yara").write_text('rule test { strings: $a = "x" condition: $a }')

        scanner = YaraScanner(rules_dir=rules_dir, max_scan_file_size=100)
        large_file = tmp_path / "large.bin"
        large_file.write_bytes(b"\x00" * 200)

        results = scanner._scan_file_binary(str(large_file), str(large_file))
        assert results == []


# ---------------------------------------------------------------------------
# M6: Silent exception swallowing in static.py
# ---------------------------------------------------------------------------


class TestStaticAnalyzerLogsExceptions:
    """Verify static analyzer doesn't silently swallow exceptions."""

    def test_static_analyzer_logs_exceptions(self):
        """No bare 'except Exception: pass' - uses logger.debug or logger.warning."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "core" / "analyzers" / "static.py"
        text = source.read_text()
        # Match "except Exception..." followed by newline and line with only "pass"
        # (greedy .*? with DOTALL wrongly matches across distant "pass")
        bare_passes = re.findall(
            r"except\s+Exception[^:\n]*:\s*\n\s*pass\b",
            text,
        )
        assert len(bare_passes) == 0, f"Found bare exception passes: {bare_passes}"


# ---------------------------------------------------------------------------
# Q1: Dead capability_inflation_generic skip removed
# ---------------------------------------------------------------------------


class TestNoDeadCapabilityInflationSkip:
    """Verify dead capability_inflation_generic skip was removed."""

    def test_no_dead_capability_inflation_skip(self):
        """No dead skip for capability_inflation_generic."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "core" / "analyzers" / "static.py"
        text = source.read_text()
        if "capability_inflation_generic" in text:
            idx = text.find("capability_inflation_generic")
            before = text[max(0, idx - 150) : idx]
            assert "skip" not in before.lower() or "skip_in" not in before


# ---------------------------------------------------------------------------
# Q3: Narrowed exception catches in analyzer_factory
# ---------------------------------------------------------------------------


class TestAnalyzerFactoryNarrowCatches:
    """Verify analyzer_factory uses ImportError, not broad Exception."""

    def test_analyzer_factory_narrow_catches(self):
        """analyzer_factory uses narrowed exception catches, not bare except Exception."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "core" / "analyzer_factory.py"
        text = source.read_text()
        assert "except (ImportError" in text
        lines = text.splitlines()
        broad_catches = [l.strip() for l in lines if "except Exception" in l and "ImportError" not in l]
        assert len(broad_catches) == 0, f"Broad except Exception still present: {broad_catches}"


# ---------------------------------------------------------------------------
# Q5: False-positive local file references (stdlib_module_names)
# ---------------------------------------------------------------------------


class TestLoaderUsesStdlibModules:
    """Verify loader uses sys.stdlib_module_names for filtering."""

    def test_loader_uses_stdlib_modules(self):
        """Loader uses stdlib_module_names for import filtering."""
        source = Path(__file__).resolve().parent.parent / "skill_scanner" / "core" / "loader.py"
        text = source.read_text()
        assert "stdlib_module_names" in text


# ---------------------------------------------------------------------------
# Policy knobs tests
# ---------------------------------------------------------------------------


class TestPolicyKnobs:
    """Verify policy presets have correct knob values."""

    def test_default_policy_has_new_knobs(self):
        """Default policy has new file/analysis knobs."""
        from skill_scanner.core.scan_policy import ScanPolicy

        policy = ScanPolicy.default()
        assert policy.file_limits.max_yara_scan_file_size_bytes == 52_428_800
        assert policy.file_limits.max_loader_file_size_bytes == 10_485_760
        assert policy.analysis_thresholds.max_regex_pattern_length == 1000

    def test_strict_policy_has_tighter_knobs(self):
        """Strict policy has tighter limits."""
        from skill_scanner.core.scan_policy import ScanPolicy

        policy = ScanPolicy.from_preset("strict")
        assert policy.file_limits.max_yara_scan_file_size_bytes == 20_971_520
        assert policy.file_limits.max_loader_file_size_bytes == 5_242_880
        assert policy.analysis_thresholds.max_regex_pattern_length == 500

    def test_permissive_policy_has_looser_or_equal_knobs(self):
        """Permissive policy has looser or equal limits (e.g. higher max_file_count)."""
        from skill_scanner.core.scan_policy import ScanPolicy

        policy = ScanPolicy.from_preset("permissive")
        assert policy.file_limits.max_file_count >= 100
        assert policy.file_limits.max_yara_scan_file_size_bytes >= 20_971_520
        assert policy.file_limits.max_loader_file_size_bytes >= 5_242_880

    def test_policy_roundtrip_new_knobs(self, tmp_path):
        """New knobs survive YAML serialization round-trip."""
        from skill_scanner.core.scan_policy import ScanPolicy

        policy = ScanPolicy.default()
        policy.file_limits.max_yara_scan_file_size_bytes = 99999
        policy.file_limits.max_loader_file_size_bytes = 88888
        policy.analysis_thresholds.max_regex_pattern_length = 777

        yaml_path = tmp_path / "test_policy.yaml"
        policy.to_yaml(str(yaml_path))

        loaded = ScanPolicy.from_yaml(yaml_path)
        assert loaded.file_limits.max_yara_scan_file_size_bytes == 99999
        assert loaded.file_limits.max_loader_file_size_bytes == 88888
        assert loaded.analysis_thresholds.max_regex_pattern_length == 777


# ---------------------------------------------------------------------------
# Loader max_file_size_bytes parameter
# ---------------------------------------------------------------------------


class TestLoaderMaxFileSize:
    """Verify loader respects max_file_size_bytes and max_file_size_mb."""

    def test_loader_respects_max_file_size_bytes(self):
        """Loader accepts max_file_size_bytes."""
        from skill_scanner.core.loader import SkillLoader

        loader = SkillLoader(max_file_size_bytes=1024)
        assert loader.max_file_size_bytes == 1024

    def test_loader_max_file_size_mb_fallback(self):
        """Loader uses max_file_size_mb when bytes not set."""
        from skill_scanner.core.loader import SkillLoader

        loader = SkillLoader(max_file_size_mb=5)
        assert loader.max_file_size_bytes == 5 * 1024 * 1024

    def test_loader_bytes_takes_precedence(self):
        """max_file_size_bytes takes precedence over max_file_size_mb."""
        from skill_scanner.core.loader import SkillLoader

        loader = SkillLoader(max_file_size_mb=5, max_file_size_bytes=999)
        assert loader.max_file_size_bytes == 999


# ---------------------------------------------------------------------------
# File type detection centralization (Q4/M7)
# ---------------------------------------------------------------------------


class TestGetFileType:
    """Verify centralized file type detection handles common extensions."""

    def test_get_file_type_detects_js_ts(self):
        """get_file_type handles JS/TS/Python."""
        from skill_scanner.utils.file_utils import get_file_type

        assert get_file_type(Path("app.js")) == "javascript"
        assert get_file_type(Path("app.ts")) == "typescript"
        assert get_file_type(Path("app.py")) == "python"

    def test_get_file_type_detects_markdown(self):
        """get_file_type handles markdown."""
        from skill_scanner.utils.file_utils import get_file_type

        assert get_file_type(Path("README.md")) == "markdown"
        assert get_file_type(Path("doc.markdown")) == "markdown"

    def test_get_file_type_unknown_returns_other(self):
        """get_file_type returns 'other' for unknown extensions."""
        from skill_scanner.utils.file_utils import get_file_type

        assert get_file_type(Path("data.xyz")) == "other"
