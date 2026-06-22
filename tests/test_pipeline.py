"""Tests for the MPC Pipeline Orchestrator."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from mpc.jadx import JadxClient
from mpc.mobsf import MobSFClient
from mpc.pipeline import Orchestrator


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_apk(tmp_path: Path) -> str:
    """Create a minimal fake APK and return its path."""
    apk = tmp_path / "test.apk"
    apk.write_text("fake apk content")
    return str(apk)


@pytest.fixture
def mock_mobsf_client() -> MagicMock:
    """Return a pre-configured mock MobSFClient."""
    client = MagicMock(spec=MobSFClient)
    client.upload.return_value = {"hash": "abc123", "file_name": "test.apk", "scan_type": "apk"}
    client.scan.return_value = {"hash": "abc123", "scan_type": "apk", "file_name": "test.apk"}
    client.report_json.return_value = {
        "hash": "abc123",
        "static_analysis": {"permissions": ["INTERNET"]},
        "code_analysis": {"findings": {}, "rules_count": 10},
        "malware_analysis": {},
    }
    client.get_sast_summary.return_value = {
        "static_analysis": {"permissions": ["INTERNET"]},
        "code_analysis": {"findings": {}, "rules_count": 10},
        "malware_analysis": {},
    }
    return client


@pytest.fixture
def mock_jadx_client() -> MagicMock:
    """Return a pre-configured mock JadxClient."""
    client = MagicMock(spec=JadxClient)
    client.decompile_with_report.return_value = {
        "success": True,
        "output_path": "/tmp/jadx_out",
        "total_files": 42,
        "bad_code_entries": [],
        "error": None,
    }
    client.search_code.return_value = []
    client.get_decompiled_files.return_value = [
        "/tmp/jadx_out/sources/com/example/MainActivity.java",
    ]
    return client


@pytest.fixture
def orchestrator(
    mock_mobsf_client: MagicMock,
    mock_jadx_client: MagicMock,
) -> Orchestrator:
    """Return an Orchestrator with mocked clients."""
    return Orchestrator(
        mobsf_client=mock_mobsf_client,
        jadx_client=mock_jadx_client,
    )


# ── Init ────────────────────────────────────────────────────────────────────────


class TestInit:
    def test_creates_default_clients_when_none_given(self) -> None:
        """Orchestrator creates default clients when none are provided."""
        # Patch the concrete clients so we do not need real services.
        with patch("mpc.pipeline.MobSFClient"), \
             patch("mpc.pipeline.JadxClient"), \
             patch("mpc.pipeline.GhidraClient"):
            orch = Orchestrator()
            assert orch.mobsf is not None
            assert orch.jadx is not None
            assert orch.ghidra is not None

    def test_accepts_pre_configured_clients(
        self,
        mock_mobsf_client: MagicMock,
        mock_jadx_client: MagicMock,
    ) -> None:
        """Pre-configured clients are used instead of creating defaults."""
        orch = Orchestrator(
            mobsf_client=mock_mobsf_client,
            jadx_client=mock_jadx_client,
        )
        assert orch.mobsf is mock_mobsf_client
        assert orch.jadx is mock_jadx_client

    def test_config_is_loaded(self) -> None:
        """MPCConfig is loaded during initialisation."""
        with patch("mpc.pipeline.MobSFClient"), \
             patch("mpc.pipeline.JadxClient"), \
             patch("mpc.pipeline.GhidraClient"):
            orch = Orchestrator()
            assert orch.config is not None


# ── analyze_apk (sequential) ────────────────────────────────────────────────────


class TestAnalyzeApk:
    def test_missing_apk_returns_early(self, orchestrator: Orchestrator) -> None:
        """A missing APK returns an error without calling any tools."""
        result = orchestrator.analyze_apk("/nonexistent.apk")
        assert result["errors"] != []
        assert "not found" in result["errors"][0].lower()
        # No tool methods should have been called
        orchestrator.mobsf.upload.assert_not_called()
        orchestrator.jadx.decompile_with_report.assert_not_called()

    def test_runs_mobsf_and_jadx_by_default(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """Both MobSF and JADX are executed in a default sequential run."""
        result = orchestrator.analyze_apk(fake_apk)

        orchestrator.mobsf.upload.assert_called_once_with(fake_apk)
        orchestrator.jadx.decompile_with_report.assert_called_once_with(fake_apk)

        assert result["mobsf"] is not None
        assert result["jadx"] is not None
        assert result["ghidra"] is None

    def test_skips_mobsf_when_disabled(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """MobSF is skipped when run_mobsf=False."""
        result = orchestrator.analyze_apk(fake_apk, run_mobsf=False)
        orchestrator.mobsf.upload.assert_not_called()
        assert result["mobsf"] is None
        assert result["jadx"] is not None

    def test_skips_jadx_when_disabled(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """JADX is skipped when run_jadx=False."""
        result = orchestrator.analyze_apk(fake_apk, run_jadx=False)
        orchestrator.jadx.decompile_with_report.assert_not_called()
        assert result["mobsf"] is not None
        assert result["jadx"] is None

    @patch("mpc.pipeline.GhidraClient")
    def test_runs_ghidra_when_enabled(
        self,
        mock_ghidra_cls: MagicMock,
        fake_apk: str,
    ) -> None:
        """Ghidra is executed when run_ghidra=True."""
        mock_ghidra = MagicMock()
        mock_ghidra.analyze_apk.return_value = {"success": True}
        mock_ghidra_cls.return_value = mock_ghidra

        orch = Orchestrator(
            mobsf_client=MagicMock(spec=MobSFClient),
            jadx_client=MagicMock(spec=JadxClient),
            ghidra_client=mock_ghidra,
        )
        result = orch.analyze_apk(fake_apk, run_ghidra=True)
        assert result["ghidra"] is not None
        assert result["ghidra"]["success"] is True

    def test_error_in_mobsf_does_not_block_jadx(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """A MobSF failure is captured as an error; JADX still runs."""
        orchestrator.mobsf.upload.side_effect = RuntimeError("MobSF down")

        result = orchestrator.analyze_apk(fake_apk)
        assert any("MobSF" in err for err in result["errors"])
        assert result["mobsf"] is None
        # JADX should still have been called
        orchestrator.jadx.decompile_with_report.assert_called_once()


# ── analyze_apk_parallel ────────────────────────────────────────────────────────


class TestAnalyzeApkParallel:
    def test_parallel_execution(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """MobSF and JADX are both executed in parallel mode."""
        result = orchestrator.analyze_apk_parallel(fake_apk)

        orchestrator.mobsf.upload.assert_called_once_with(fake_apk)
        orchestrator.jadx.decompile_with_report.assert_called_once_with(fake_apk)

        assert result["mobsf"] is not None
        assert result["jadx"] is not None

    def test_parallel_missing_apk(self, orchestrator: Orchestrator) -> None:
        """Missing APK returns early without calling any tools."""
        result = orchestrator.analyze_apk_parallel("/missing.apk")
        assert result["errors"] != []
        orchestrator.mobsf.upload.assert_not_called()
        orchestrator.jadx.decompile_with_report.assert_not_called()

    def test_parallel_error_handling(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """Errors in one parallel branch do not crash the other."""
        orchestrator.mobsf.upload.side_effect = RuntimeError("crash")
        result = orchestrator.analyze_apk_parallel(fake_apk)

        assert any("mobsf" in err.lower() for err in result["errors"])
        assert result["mobsf"] is None
        # JADX should still have completed
        assert result["jadx"] is not None


# ── mobsf_pipeline ──────────────────────────────────────────────────────────────


class TestMobsfPipeline:
    def test_full_mobsf_workflow(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """mobsf_pipeline calls upload → scan → report → SAST."""
        result = orchestrator.mobsf_pipeline(fake_apk)

        orchestrator.mobsf.upload.assert_called_once_with(fake_apk)
        orchestrator.mobsf.scan.assert_called_once_with("abc123")
        orchestrator.mobsf.report_json.assert_called_once_with("abc123")
        orchestrator.mobsf.get_sast_summary.assert_called_once_with("abc123")

        assert result["upload"] is not None
        assert result["scan"] is not None
        assert result["report"] is not None
        assert result["sast_summary"] is not None


# ── jadx_pipeline ───────────────────────────────────────────────────────────────


class TestJadxPipeline:
    def test_full_jadx_workflow(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """jadx_pipeline calls decompile_with_report and vulnerability search."""
        result = orchestrator.jadx_pipeline(fake_apk)

        orchestrator.jadx.decompile_with_report.assert_called_once_with(fake_apk)
        orchestrator.jadx.search_code.assert_called()

        assert result["decompile"] is not None
        assert result["decompile_report"] is not None
        assert result["vulnerability_search"] is not None

    def test_vulnerability_search_skipped_on_failure(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """Vulnerability search is not run when decompilation fails."""
        orchestrator.jadx.decompile_with_report.return_value = {
            "success": False,
            "output_path": None,
            "total_files": 0,
            "bad_code_entries": [],
            "error": "JADX failed",
        }

        result = orchestrator.jadx_pipeline(fake_apk)

        # search_code should not have been called
        orchestrator.jadx.search_code.assert_not_called()
        assert result["vulnerability_search"] == {}


# ── search_vulnerabilities ──────────────────────────────────────────────────────


class TestSearchVulnerabilities:
    def test_uses_default_patterns_when_none_given(
        self,
        orchestrator: Orchestrator,
        tmp_path: Path,
    ) -> None:
        """When patterns is None, _default_vuln_patterns is used."""
        # Create a fake dir so search_code doesn't error
        out_dir = str(tmp_path / "jadx_out")
        Path(out_dir).mkdir(parents=True)

        # Make search_code return something for one category
        def search_code_side_effect(_dir: str, pattern: str) -> list:
            if "hardcoded" in pattern:
                return [{"file": "Test.java", "line": 10, "content": "sk_live_abc"}]
            return []

        orchestrator.jadx.search_code.side_effect = search_code_side_effect

        defaults = orchestrator._default_vuln_patterns()
        result = orchestrator.search_vulnerabilities(out_dir)

        assert "_summary" in result
        assert isinstance(result["_summary"]["total_findings"], int)

    def test_custom_patterns_override_defaults(
        self,
        orchestrator: Orchestrator,
        tmp_path: Path,
    ) -> None:
        """Explicit patterns dict is used instead of defaults."""
        out_dir = str(tmp_path / "custom_out")
        Path(out_dir).mkdir(parents=True)

        custom_patterns = {"custom_vuln": r"TODO|FIXME"}
        result = orchestrator.search_vulnerabilities(out_dir, patterns=custom_patterns)

        assert "custom_vuln" in result
        assert "_summary" in result
        # Default patterns should NOT be present
        assert "hardcoded_api_key" not in result
        assert "insecure_webview" not in result

    def test_summary_counts_are_correct(
        self,
        orchestrator: Orchestrator,
        tmp_path: Path,
    ) -> None:
        """The _summary section has accurate total_findings."""
        out_dir = str(tmp_path / "summary_test")
        Path(out_dir).mkdir(parents=True)

        def search_side(_dir: str, pattern: str) -> list:
            return [{"file": "a.java", "line": 1, "content": "x"}]

        orchestrator.jadx.search_code.side_effect = search_side

        patterns = {"cat_a": r"a", "cat_b": r"b", "cat_c": r"c"}
        result = orchestrator.search_vulnerabilities(out_dir, patterns=patterns)

        assert result["_summary"]["total_findings"] == 3  # one match per category
        assert len(result["_summary"]["categories_with_matches"]) == 3

    def test_empty_results_when_no_matches(
        self,
        orchestrator: Orchestrator,
        tmp_path: Path,
    ) -> None:
        """When no patterns match, results contain empty lists and zero count."""
        out_dir = str(tmp_path / "empty")
        Path(out_dir).mkdir(parents=True)

        orchestrator.jadx.search_code.return_value = []

        patterns = {"nothing": r"ZXjK__NEVER__MATCH"}
        result = orchestrator.search_vulnerabilities(out_dir, patterns=patterns)

        assert result["nothing"] == []
        assert result["_summary"]["total_findings"] == 0
        assert result["_summary"]["categories_with_matches"] == []

    def test_nonexistent_directory_returns_empty(
        self,
        orchestrator: Orchestrator,
    ) -> None:
        """A non-existent directory is handled gracefully."""
        # search_code will find no files in a non-existent dir
        orchestrator.jadx.search_code.return_value = []
        result = orchestrator.search_vulnerabilities("/no/such/dir")
        assert "_summary" in result


# ── _default_vuln_patterns ──────────────────────────────────────────────────────


class TestDefaultVulnPatterns:
    def test_returns_dict(self, orchestrator: Orchestrator) -> None:
        """Returns a non-empty dictionary of patterns."""
        patterns = orchestrator._default_vuln_patterns()
        assert isinstance(patterns, dict)
        assert len(patterns) > 0

    def test_all_values_are_strings(self, orchestrator: Orchestrator) -> None:
        """Every value in the dict is a non-empty string (regex)."""
        patterns = orchestrator._default_vuln_patterns()
        for name, regex in patterns.items():
            assert isinstance(regex, str), f"Pattern '{name}' is not a string"
            assert len(regex) > 0, f"Pattern '{name}' is empty"

    def test_all_patterns_are_valid_regex(self, orchestrator: Orchestrator) -> None:
        """Every pattern compiles without error."""
        patterns = orchestrator._default_vuln_patterns()
        for name, regex in patterns.items():
            try:
                re.compile(regex)
            except re.error as exc:
                pytest.fail(f"Pattern '{name}' failed to compile: {exc}")

    def test_contains_expected_categories(self, orchestrator: Orchestrator) -> None:
        """All expected vulnerability categories are present."""
        patterns = orchestrator._default_vuln_patterns()
        expected = {
            "hardcoded_api_key",
            "insecure_webview",
            "weak_hash",
            "sql_injection",
            "logging_sensitive",
            "pending_intent_flags",
            "deeplink_schemes",
            "insecure_random",
            "ssl_pinning_bypass",
            "world_writable_file",
        }
        assert expected.issubset(patterns.keys()), (
            f"Missing categories: {expected - set(patterns.keys())}"
        )

    def test_hardcoded_api_key_matches_stripe_key(self, orchestrator: Orchestrator) -> None:
        """The hardcoded_api_key pattern matches a real-looking Stripe key."""
        pattern = orchestrator._default_vuln_patterns()["hardcoded_api_key"]
        compiled = re.compile(pattern)
        assert compiled.search('"sk_live_abc123def456"')
        assert compiled.search("pk_live_xxxxxxxxxxxx")
        assert compiled.search("AIzaSyD-abc123def456abc123def456abc123def456")
        assert compiled.search("AKIAIOSFODNN7EXAMPLE")

    def test_insecure_webview_detects_js_enabled(self, orchestrator: Orchestrator) -> None:
        """The insecure_webview pattern detects setJavaScriptEnabled(true)."""
        pattern = orchestrator._default_vuln_patterns()["insecure_webview"]
        compiled = re.compile(pattern)
        assert compiled.search("setJavaScriptEnabled(true)")
        assert compiled.search("setAllowFileAccess(true)")

    def test_weak_hash_detects_md5(self, orchestrator: Orchestrator) -> None:
        """The weak_hash pattern detects MD5 usage."""
        pattern = orchestrator._default_vuln_patterns()["weak_hash"]
        compiled = re.compile(pattern)
        assert compiled.search('MessageDigest.getInstance("MD5")')

    def test_logging_sensitive_detects_password_log(self, orchestrator: Orchestrator) -> None:
        """The logging_sensitive pattern detects password in log calls."""
        pattern = orchestrator._default_vuln_patterns()["logging_sensitive"]
        compiled = re.compile(pattern)
        assert compiled.search('Log.d(TAG, "password: " + pwd)')
        assert compiled.search('Log.e("Auth", "token expired: " + token)')


# ── generate_report ─────────────────────────────────────────────────────────────


class TestGenerateReport:
    def test_returns_report_directory_path(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
        tmp_path: Path,
    ) -> None:
        """generate_report returns the path to the reports directory."""
        report_dir = str(tmp_path / "reports")

        result_path = orchestrator.generate_report(
            fake_apk, output_dir=report_dir,
        )

        assert result_path == str(Path(report_dir).resolve())
        assert Path(report_dir).is_dir()

    def test_writes_report_files(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
        tmp_path: Path,
    ) -> None:
        """JSON, Markdown, and HTML files are written to the output dir."""
        report_dir = str(tmp_path / "output_reports")

        result_path = orchestrator.generate_report(
            fake_apk, output_dir=report_dir,
        )

        report_path = Path(result_path)
        stem = Path(fake_apk).stem
        assert (report_path / f"{stem}_report.json").exists()
        assert (report_path / f"{stem}_report.md").exists()
        assert (report_path / f"{stem}_report.html").exists()

    def test_default_output_dir_uses_config(
        self,
        orchestrator: Orchestrator,
        fake_apk: str,
    ) -> None:
        """Uses the configured report_dir when no output_dir is given."""
        result_path = orchestrator.generate_report(fake_apk)
        expected = Path(orchestrator.config.report_dir).resolve()
        assert Path(result_path).resolve() == expected
