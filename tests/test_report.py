"""Tests for the MPC Report Generator."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

from mpc.report import Finding, ReportGenerator


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def sample_finding() -> Finding:
    """Return a basic Finding for reuse in tests."""
    return Finding(
        tool="jadx",
        severity="high",
        category="insecure_webview",
        title="Insecure WebView",
        description="WebView allows JavaScript execution.",
        location="com/example/MainActivity.java:42",
        recommendation="Disable JavaScript unless required.",
    )


@pytest.fixture
def mobsf_pipeline_result() -> Dict[str, Any]:
    """Simulate a MobSF pipeline result with findings."""
    return {
        "upload": {"hash": "abc", "file_name": "test.apk", "scan_type": "apk"},
        "scan": {"hash": "abc", "scan_type": "apk", "file_name": "test.apk"},
        "report": {
            "hash": "abc",
            "static_analysis": {
                "permissions": [
                    "INTERNET",
                    "READ_EXTERNAL_STORAGE",
                    "CAMERA",
                    "ACCESS_FINE_LOCATION",
                ],
            },
            "code_analysis": {
                "findings": {
                    "rule_001": [
                        {
                            "severity": "high",
                            "title": "Insecure WebView",
                            "description": "WebView with JS enabled",
                            "file": "res/layout/activity_main.xml",
                        },
                        {
                            "severity": "warning",
                            "title": "Weak Cipher",
                            "description": "Uses RC4",
                            "file": "com/example/Crypto.java",
                        },
                    ],
                    "rule_002": [
                        {
                            "severity": "info",
                            "title": "Backup Enabled",
                            "description": "android:allowBackup=true",
                            "file": "AndroidManifest.xml",
                        },
                    ],
                },
                "rules_count": 2,
            },
            "malware_analysis": {},
        },
        "sast_summary": {
            "static_analysis": {
                "permissions": [
                    "INTERNET",
                    "READ_EXTERNAL_STORAGE",
                    "CAMERA",
                    "ACCESS_FINE_LOCATION",
                ],
            },
            "code_analysis": {
                "findings": {
                    "rule_001": [
                        {
                            "severity": "high",
                            "title": "Insecure WebView",
                            "description": "WebView with JS enabled",
                            "file": "res/layout/activity_main.xml",
                        },
                        {
                            "severity": "warning",
                            "title": "Weak Cipher",
                            "description": "Uses RC4",
                            "file": "com/example/Crypto.java",
                        },
                    ],
                    "rule_002": [
                        {
                            "severity": "info",
                            "title": "Backup Enabled",
                            "description": "android:allowBackup=true",
                            "file": "AndroidManifest.xml",
                        },
                    ],
                },
                "rules_count": 2,
            },
            "malware_analysis": {},
        },
    }


@pytest.fixture
def jadx_pipeline_result() -> Dict[str, Any]:
    """Simulate a JADX pipeline result with vulnerability search hits."""
    return {
        "decompile": {
            "success": True,
            "output_path": "/tmp/jadx_out",
            "total_files": 50,
            "bad_code_entries": ["WARNING: bad code at Foo.java"],
            "error": None,
        },
        "decompile_report": {
            "success": True,
            "output_path": "/tmp/jadx_out",
            "total_files": 50,
            "bad_code_entries": ["WARNING: bad code at Foo.java"],
        },
        "vulnerability_search": {
            "hardcoded_api_key": [
                {"file": "com/example/Config.java", "line": 15, "content": 'String key = "sk_live_xxxx";'},
                {"file": "com/example/Config.java", "line": 22, "content": 'String pk = "pk_live_yyyy";'},
            ],
            "insecure_webview": [
                {"file": "com/example/WebActivity.java", "line": 33, "content": "webView.getSettings().setJavaScriptEnabled(true);"},
            ],
            "weak_hash": [],
            "_summary": {
                "total_findings": 3,
                "categories_with_matches": ["hardcoded_api_key", "insecure_webview"],
            },
        },
    }


@pytest.fixture
def full_pipeline_results(
    mobsf_pipeline_result: Dict[str, Any],
    jadx_pipeline_result: Dict[str, Any],
) -> Dict[str, Any]:
    """Simulate the full output of Orchestrator.analyze_apk()."""
    return {
        "apk_path": "/tmp/test.apk",
        "mobsf": mobsf_pipeline_result,
        "jadx": jadx_pipeline_result,
        "ghidra": None,
        "errors": [],
    }


# ── Finding dataclass ──────────────────────────────────────────────────────────


class TestFinding:
    def test_create_finding(self, sample_finding: Finding) -> None:
        """A Finding can be created with all fields."""
        assert sample_finding.tool == "jadx"
        assert sample_finding.severity == "high"
        assert sample_finding.category == "insecure_webview"
        assert sample_finding.title == "Insecure WebView"

    def test_finding_default_location_empty(self) -> None:
        """Location defaults to empty string."""
        f = Finding(tool="mobsf", severity="info", category="test", title="Test", description="Desc")
        assert f.location == ""

    def test_finding_default_recommendation_empty(self) -> None:
        """Recommendation defaults to empty string."""
        f = Finding(tool="mobsf", severity="info", category="test", title="Test", description="Desc")
        assert f.recommendation == ""


# ── _extract_findings_from_mobsf ───────────────────────────────────────────────


class TestExtractFindingsFromMobsf:
    def test_extracts_code_analysis_findings(
        self,
        mobsf_pipeline_result: Dict[str, Any],
    ) -> None:
        """Code analysis findings are extracted from the MobSF result."""
        findings = ReportGenerator._extract_findings_from_mobsf(mobsf_pipeline_result)
        code_findings = [f for f in findings if f.category == "code_analysis"]
        assert len(code_findings) >= 3  # 2 from rule_001 + 1 from rule_002

    def test_extracts_dangerous_permissions(
        self,
        mobsf_pipeline_result: Dict[str, Any],
    ) -> None:
        """Dangerous permissions produce a finding."""
        findings = ReportGenerator._extract_findings_from_mobsf(mobsf_pipeline_result)
        perm_findings = [f for f in findings if f.category == "dangerous_permissions"]
        assert len(perm_findings) == 1
        assert "CAMERA" in perm_findings[0].description
        assert "ACCESS_FINE_LOCATION" in perm_findings[0].description
        assert perm_findings[0].severity == "medium"

    def test_no_permissions_finding_when_none_dangerous(self) -> None:
        """When no dangerous permissions exist, no permission finding is created."""
        safe_result = {
            "report": {},
            "sast_summary": {
                "static_analysis": {
                    "permissions": ["INTERNET", "NFC"],
                },
                "code_analysis": {"findings": {}},
                "malware_analysis": {},
            },
        }
        findings = ReportGenerator._extract_findings_from_mobsf(safe_result)
        perm_findings = [f for f in findings if f.category == "dangerous_permissions"]
        assert perm_findings == []

    def test_empty_result_returns_empty_list(self) -> None:
        """An empty MobSF result returns no findings."""
        findings = ReportGenerator._extract_findings_from_mobsf({})
        assert findings == []

    def test_severity_mapping(self, mobsf_pipeline_result: Dict[str, Any]) -> None:
        """MobSF severities are mapped to canonical levels."""
        findings = ReportGenerator._extract_findings_from_mobsf(mobsf_pipeline_result)
        for f in findings:
            assert f.severity in ("critical", "high", "medium", "low", "info")


# ── _extract_findings_from_jadx ────────────────────────────────────────────────


class TestExtractFindingsFromJadx:
    def test_extracts_vulnerability_search_hits(
        self,
        jadx_pipeline_result: Dict[str, Any],
    ) -> None:
        """Vulnerability search results are converted to Findings."""
        search = jadx_pipeline_result.get("vulnerability_search", {})
        findings = ReportGenerator._extract_findings_from_jadx(
            jadx_pipeline_result, search,
        )

        # 2 hardcoded_api_key + 1 insecure_webview + 1 bad code entry
        assert len(findings) >= 3

        hardcoded = [f for f in findings if f.category == "hardcoded_api_key"]
        assert len(hardcoded) == 2
        assert hardcoded[0].severity == "critical"
        assert "Config.java" in hardcoded[0].location

    def test_includes_decompilation_issues(
        self,
        jadx_pipeline_result: Dict[str, Any],
    ) -> None:
        """Bad-code entries from JADX produce info-level findings."""
        search = jadx_pipeline_result.get("vulnerability_search", {})
        findings = ReportGenerator._extract_findings_from_jadx(
            jadx_pipeline_result, search,
        )
        quality = [f for f in findings if f.category == "decompilation_quality"]
        assert len(quality) == 1
        assert quality[0].severity == "info"

    def test_empty_search_returns_decompilation_only(self) -> None:
        """With no search hits, only decompilation quality findings remain."""
        result = {
            "decompile": {
                "success": True,
                "output_path": "/out",
                "total_files": 10,
                "bad_code_entries": [],
                "error": None,
            },
            "decompile_report": {
                "success": True,
                "output_path": "/out",
                "total_files": 10,
                "bad_code_entries": [],
            },
        }
        findings = ReportGenerator._extract_findings_from_jadx(result, {})
        # No bad code entries, so only potential decompilation issue
        # (but none since bad_code_entries is empty)
        quality = [f for f in findings if f.category == "decompilation_quality"]
        assert quality == []

    def test_severity_per_category(
        self,
        jadx_pipeline_result: Dict[str, Any],
    ) -> None:
        """Each vulnerability category has the correct severity."""
        search = jadx_pipeline_result.get("vulnerability_search", {})
        findings = ReportGenerator._extract_findings_from_jadx(
            jadx_pipeline_result, search,
        )

        severity_map = {
            "hardcoded_api_key": "critical",
            "insecure_webview": "high",
        }
        for f in findings:
            if f.category in severity_map:
                assert f.severity == severity_map[f.category], (
                    f"Expected {severity_map[f.category]} for {f.category}, "
                    f"got {f.severity}"
                )


# ── generate_json ──────────────────────────────────────────────────────────────


class TestGenerateJson:
    def test_contains_metadata(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """JSON report contains metadata section."""
        report = ReportGenerator.generate_json("/tmp/test.apk", full_pipeline_results)
        assert "metadata" in report
        assert report["metadata"]["apk_name"] == "test.apk"

    def test_contains_summary(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """JSON report contains summary with counts."""
        report = ReportGenerator.generate_json("/tmp/test.apk", full_pipeline_results)
        assert "summary" in report
        assert "total_findings" in report["summary"]
        assert "by_severity" in report["summary"]
        assert "by_tool" in report["summary"]

    def test_contains_findings_list(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """JSON report contains a findings list."""
        report = ReportGenerator.generate_json("/tmp/test.apk", full_pipeline_results)
        assert "findings" in report
        assert isinstance(report["findings"], list)
        assert len(report["findings"]) > 0

    def test_contains_errors(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """JSON report contains the errors list."""
        report = ReportGenerator.generate_json("/tmp/test.apk", full_pipeline_results)
        assert "errors" in report

    def test_findings_sorted_by_severity(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """Findings are sorted with critical first."""
        report = ReportGenerator.generate_json("/tmp/test.apk", full_pipeline_results)
        severities = [f["severity"] for f in report["findings"]]
        # Check that critical comes before high, etc.
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        order_values = [sev_order[s] for s in severities]
        assert order_values == sorted(order_values)

    def test_json_serializable(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """The report can be serialised to JSON without error."""
        report = ReportGenerator.generate_json("/tmp/test.apk", full_pipeline_results)
        json_str = json.dumps(report, indent=2, default=str)
        assert isinstance(json_str, str)
        # Verify round-trip
        parsed = json.loads(json_str)
        assert parsed["metadata"]["apk_name"] == "test.apk"


# ── generate_markdown ──────────────────────────────────────────────────────────


class TestGenerateMarkdown:
    def test_contains_expected_sections(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """Markdown report contains all major sections."""
        md = ReportGenerator.generate_markdown("/tmp/test.apk", full_pipeline_results)
        assert "# MPC Analysis Report: test.apk" in md
        assert "## Summary" in md
        assert "## Findings" in md
        assert "### By Severity" in md
        assert "### By Tool" in md

    def test_contains_findings(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """Each finding is rendered in the markdown."""
        md = ReportGenerator.generate_markdown("/tmp/test.apk", full_pipeline_results)
        assert "[HIGH]" in md
        assert "[CRITICAL]" in md
        assert "Hardcoded API Key" in md
        assert "Insecure WebView" in md

    def test_errors_section_included_when_present(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """Errors section is included when there are errors."""
        results_with_errors = dict(full_pipeline_results)
        results_with_errors["errors"] = ["MobSF connection failed"]
        md = ReportGenerator.generate_markdown("/tmp/test.apk", results_with_errors)
        assert "## Errors" in md
        assert "MobSF connection failed" in md

    def test_no_findings_message(self) -> None:
        """When no findings exist, the markdown says so."""
        empty_results: Dict[str, Any] = {
            "apk_path": "/tmp/clean.apk",
            "mobsf": {},
            "jadx": {"vulnerability_search": {}, "decompile": {"bad_code_entries": []}},
            "ghidra": None,
            "errors": [],
        }
        md = ReportGenerator.generate_markdown("/tmp/clean.apk", empty_results)
        assert "_No findings were identified._" in md

    def test_errors_section_omitted_when_empty(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """Errors section is omitted when there are no errors."""
        md = ReportGenerator.generate_markdown("/tmp/test.apk", full_pipeline_results)
        assert "## Errors" not in md


# ── generate_html ──────────────────────────────────────────────────────────────


class TestGenerateHtml:
    def test_contains_required_html_structure(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """HTML report has proper HTML document structure."""
        html = ReportGenerator.generate_html("/tmp/test.apk", full_pipeline_results)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_contains_severity_classes(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """HTML report contains severity CSS classes."""
        html = ReportGenerator.generate_html("/tmp/test.apk", full_pipeline_results)
        assert "severity-critical" in html or "critical" in html.lower()
        assert "severity-high" in html or "high" in html.lower()

    def test_contains_app_name(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """HTML title contains the APK name."""
        html = ReportGenerator.generate_html("/tmp/test.apk", full_pipeline_results)
        assert "test.apk" in html
        assert "MPC Analysis Report" in html

    def test_summary_cards(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """HTML report includes summary cards with counts."""
        html = ReportGenerator.generate_html("/tmp/test.apk", full_pipeline_results)
        assert "summary-grid" in html
        assert "summary-card" in html
        assert "Total Findings" in html

    def test_errors_included_when_present(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """Errors are displayed in the HTML when present."""
        results_with_errors = dict(full_pipeline_results)
        results_with_errors["errors"] = ["Something went wrong"]
        html = ReportGenerator.generate_html("/tmp/test.apk", results_with_errors)
        assert "Errors" in html
        assert "Something went wrong" in html

    def test_no_findings_message(self) -> None:
        """When no findings, HTML displays an appropriate message."""
        empty_results: Dict[str, Any] = {
            "apk_path": "/tmp/clean.apk",
            "mobsf": {},
            "jadx": {"decompile": {}, "vulnerability_search": {}},
            "ghidra": None,
            "errors": [],
        }
        html = ReportGenerator.generate_html("/tmp/clean.apk", empty_results)
        assert "No findings were identified" in html


# ── _extract_all_findings (integration) ────────────────────────────────────────


class TestExtractAllFindings:
    def test_aggregates_from_all_tools(
        self,
        full_pipeline_results: Dict[str, Any],
    ) -> None:
        """All findings from MobSF and JADX are aggregated."""
        findings = ReportGenerator._extract_all_findings(full_pipeline_results)
        assert len(findings) > 0

        mobsf_findings = [f for f in findings if f.tool == "mobsf"]
        jadx_findings = [f for f in findings if f.tool == "jadx"]
        assert len(mobsf_findings) > 0
        assert len(jadx_findings) > 0

    def test_empty_pipeline_returns_empty_list(self) -> None:
        """An empty pipeline result yields no findings."""
        findings = ReportGenerator._extract_all_findings({})
        assert findings == []
