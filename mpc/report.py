"""Report generation for MPC analysis pipelines.

Transforms raw pipeline results into structured JSON, Markdown, and
HTML report formats, extracting and categorising findings from each
analysis tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Finding:
    """A single security finding identified during analysis.

    Attributes
    ----------
    tool:
        The tool that identified the finding (``"mobsf"``, ``"jadx"``,
        or ``"ghidra"``).
    severity:
        Severity level: ``"critical"``, ``"high"``, ``"medium"``,
        ``"low"``, or ``"info"``.
    category:
        Categorisation of the finding (e.g. ``"hardcoded_secret"``,
        ``"insecure_webview"``).
    title:
        Short human-readable title.
    description:
        Detailed description of the issue.
    location:
        File path, class name, or other location indicator (optional).
    recommendation:
        Remediation advice or next steps (optional).
    """

    tool: str
    severity: str
    category: str
    title: str
    description: str
    location: str = ""
    recommendation: str = ""


# Severity ordering for sorting
_SEVERITY_ORDER: Dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _severity_sort_key(finding: Finding) -> int:
    return _SEVERITY_ORDER.get(finding.severity, 99)


# ── Report Generator ────────────────────────────────────────────────────────────


class ReportGenerator:
    """Generates structured and human-readable reports from pipeline results."""

    @staticmethod
    def generate_json(
        apk_path: str,
        pipeline_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build a structured JSON-serialisable report.

        Parameters
        ----------
        apk_path:
            Path to the analysed APK.
        pipeline_results:
            The output from :meth:`Orchestrator.analyze_apk`.

        Returns
        -------
        dict
            A JSON-compatible report dict with metadata, findings, and
            per-tool sections.
        """
        findings = ReportGenerator._extract_all_findings(pipeline_results)

        report: Dict[str, Any] = {
            "metadata": {
                "apk_path": str(Path(apk_path).resolve()),
                "apk_name": Path(apk_path).name,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tools_used": [
                    name for name in ("mobsf", "jadx", "ghidra")
                    if pipeline_results.get(name) is not None
                ],
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": {
                    "critical": sum(1 for f in findings if f.severity == "critical"),
                    "high": sum(1 for f in findings if f.severity == "high"),
                    "medium": sum(1 for f in findings if f.severity == "medium"),
                    "low": sum(1 for f in findings if f.severity == "low"),
                    "info": sum(1 for f in findings if f.severity == "info"),
                },
                "by_tool": {
                    "mobsf": sum(1 for f in findings if f.tool == "mobsf"),
                    "jadx": sum(1 for f in findings if f.tool == "jadx"),
                    "ghidra": sum(1 for f in findings if f.tool == "ghidra"),
                },
            },
            "findings": [
                {
                    "tool": f.tool,
                    "severity": f.severity,
                    "category": f.category,
                    "title": f.title,
                    "description": f.description,
                    "location": f.location,
                    "recommendation": f.recommendation,
                }
                for f in sorted(findings, key=_severity_sort_key)
            ],
            "errors": pipeline_results.get("errors", []),
        }

        return report

    @staticmethod
    def generate_markdown(
        apk_path: str,
        pipeline_results: Dict[str, Any],
    ) -> str:
        """Generate a Markdown report from pipeline results.

        Parameters
        ----------
        apk_path:
            Path to the analysed APK.
        pipeline_results:
            The output from :meth:`Orchestrator.analyze_apk`.

        Returns
        -------
        str
            Markdown-formatted report.
        """
        findings = ReportGenerator._extract_all_findings(pipeline_results)
        apk_name = Path(apk_path).name
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines: List[str] = [
            f"# MPC Analysis Report: {apk_name}",
            "",
            f"**Generated:** {now}",
            f"**APK Path:** `{Path(apk_path).resolve()}`",
            "",
            "---",
            "",
            "## Summary",
            "",
            f"- **Total Findings:** {len(findings)}",
            "",
            "### By Severity",
            "",
            f"| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in ("critical", "high", "medium", "low", "info"):
            count = sum(1 for f in findings if f.severity == sev)
            lines.append(f"| {sev.capitalize()} | {count} |")

        lines += [
            "",
            "### By Tool",
            "",
            "| Tool | Count |",
            "|------|-------|",
        ]
        for tool in ("mobsf", "jadx", "ghidra"):
            count = sum(1 for f in findings if f.tool == tool)
            lines.append(f"| {tool.capitalize()} | {count} |")

        lines += [
            "",
            "---",
            "",
            "## Findings",
            "",
        ]

        if not findings:
            lines.append("_No findings were identified._")
        else:
            for idx, finding in enumerate(sorted(findings, key=_severity_sort_key), start=1):
                lines += [
                    f"### {idx}. [{finding.severity.upper()}] {finding.title}",
                    "",
                    f"**Tool:** {finding.tool.capitalize()}",
                    f"**Category:** `{finding.category}`",
                    f"**Severity:** {finding.severity.capitalize()}",
                    "",
                ]
                if finding.location:
                    lines.append(f"**Location:** `{finding.location}`")
                    lines.append("")
                lines.append(f"{finding.description}")
                lines.append("")
                if finding.recommendation:
                    lines.append(f"> **Recommendation:** {finding.recommendation}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        # Errors section
        errors = pipeline_results.get("errors", [])
        if errors:
            lines += [
                "## Errors",
                "",
            ]
            for err in errors:
                lines.append(f"- {err}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def generate_html(
        apk_path: str,
        pipeline_results: Dict[str, Any],
    ) -> str:
        """Generate a minimal HTML report with severity-coloured findings.

        Parameters
        ----------
        apk_path:
            Path to the analysed APK.
        pipeline_results:
            The output from :meth:`Orchestrator.analyze_apk`.

        Returns
        -------
        str
            HTML document as a string.
        """
        findings = ReportGenerator._extract_all_findings(pipeline_results)
        apk_name = Path(apk_path).name
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        severity_colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }

        summary_counts = {
            sev: sum(1 for f in findings if f.severity == sev)
            for sev in ("critical", "high", "medium", "low", "info")
        }

        # Build findings HTML rows
        findings_rows: List[str] = []
        for idx, finding in enumerate(
            sorted(findings, key=_severity_sort_key), start=1
        ):
            color = severity_colors.get(finding.severity, "#6c757d")
            location_html = (
                f"<br><small><em>Location:</em> <code>{finding.location}</code></small>"
                if finding.location
                else ""
            )
            recommendation_html = (
                f"<blockquote><strong>Recommendation:</strong> {finding.recommendation}</blockquote>"
                if finding.recommendation
                else ""
            )
            findings_rows.append(
                f"""          <tr>
            <td>{idx}</td>
            <td style="color:{color};font-weight:bold">{finding.severity.upper()}</td>
            <td>{finding.tool.capitalize()}</td>
            <td><code>{finding.category}</code></td>
            <td>
              <strong>{finding.title}</strong><br>
              {finding.description}
              {location_html}
              {recommendation_html}
            </td>
          </tr>"""
            )

        errors_html = ""
        errors = pipeline_results.get("errors", [])
        if errors:
            errors_list = "\n".join(
                f"            <li>{err}</li>" for err in errors
            )
            errors_html = f"""
        <h2>Errors</h2>
        <ul class="errors">
          {errors_list}
        </ul>"""

        if findings_rows:
            findings_table = f"""      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Severity</th>
            <th>Tool</th>
            <th>Category</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
{chr(10).join(findings_rows)}
        </tbody>
      </table>"""
        else:
            findings_table = "      <p><em>No findings were identified.</em></p>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MPC Report: {apk_name}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 2rem; color: #333; }}
    h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
    h2 {{ margin-top: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
    th, td {{ border: 1px solid #dee2e6; padding: 0.75rem; text-align: left; vertical-align: top; }}
    th {{ background-color: #f8f9fa; font-weight: 600; }}
    tr:nth-child(even) {{ background-color: #f8f9fa; }}
    .severity-critical {{ color: #dc3545; }}
    .severity-high {{ color: #fd7e14; }}
    .severity-medium {{ color: #ffc107; }}
    .severity-low {{ color: #28a745; }}
    .severity-info {{ color: #17a2b8; }}
    code {{ background-color: #e9ecef; padding: 0.15rem 0.3rem; border-radius: 3px; font-size: 0.9em; }}
    blockquote {{ border-left: 4px solid #6c757d; margin: 0.5rem 0; padding: 0.5rem 1rem; background: #f8f9fa; }}
    ul.errors {{ color: #dc3545; }}
    .summary-grid {{ display: flex; gap: 1rem; flex-wrap: wrap; margin: 1rem 0; }}
    .summary-card {{ border: 1px solid #dee2e6; border-radius: 6px; padding: 1rem; min-width: 120px; text-align: center; }}
    .summary-card .count {{ font-size: 2rem; font-weight: bold; }}
    .summary-card .label {{ font-size: 0.85rem; color: #6c757d; text-transform: uppercase; }}
    .metadata {{ background: #f8f9fa; padding: 1rem; border-radius: 6px; margin: 1rem 0; }}
  </style>
</head>
<body>
  <h1>MPC Analysis Report: {apk_name}</h1>
  <div class="metadata">
    <strong>Generated:</strong> {now}<br>
    <strong>APK Path:</strong> <code>{Path(apk_path).resolve()}</code>
  </div>

  <h2>Summary</h2>
  <div class="summary-grid">
    <div class="summary-card">
      <div class="count">{len(findings)}</div>
      <div class="label">Total Findings</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color:{severity_colors['critical']}">{summary_counts['critical']}</div>
      <div class="label">Critical</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color:{severity_colors['high']}">{summary_counts['high']}</div>
      <div class="label">High</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color:{severity_colors['medium']}">{summary_counts['medium']}</div>
      <div class="label">Medium</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color:{severity_colors['low']}">{summary_counts['low']}</div>
      <div class="label">Low</div>
    </div>
    <div class="summary-card">
      <div class="count" style="color:{severity_colors['info']}">{summary_counts['info']}</div>
      <div class="label">Info</div>
    </div>
  </div>

  <h2>Findings</h2>
  {findings_table}
  {errors_html}
</body>
</html>"""

        return html

    # ------------------------------------------------------------------
    # Internal: finding extraction helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_all_findings(
        pipeline_results: Dict[str, Any],
    ) -> List[Finding]:
        """Collect findings from every tool present in the pipeline results."""
        findings: List[Finding] = []

        mobsf_result = pipeline_results.get("mobsf")
        if mobsf_result:
            findings.extend(
                ReportGenerator._extract_findings_from_mobsf(mobsf_result)
            )

        jadx_result = pipeline_results.get("jadx")
        if jadx_result:
            jadx_search = jadx_result.get("vulnerability_search", {})
            findings.extend(
                ReportGenerator._extract_findings_from_jadx(
                    jadx_result, jadx_search,
                )
            )

        # Ghidra findings are not yet extracted, but the hook is here.
        # ghidra_result = pipeline_results.get("ghidra")

        return findings

    @staticmethod
    def _extract_findings_from_mobsf(
        mobsf_result: Dict[str, Any],
    ) -> List[Finding]:
        """Extract findings from a MobSF pipeline result.

        Scans the ``report`` and ``sast_summary`` sections for known
        issue categories.
        """
        findings: List[Finding] = []
        report = mobsf_result.get("report", {})
        sast = mobsf_result.get("sast_summary", {})

        # --- Code analysis findings ---
        code_analysis = sast.get("code_analysis", {}) or report.get("code_analysis", {})

        # MobSF returns findings as a dict of rule_id -> list of match dicts
        # under the ``"findings"`` key.
        raw_findings = code_analysis.get("findings", {})
        if isinstance(raw_findings, dict):
            for rule_id, matches in raw_findings.items():
                if isinstance(matches, list):
                    for match in matches:
                        severity = (
                            match.get("severity", "").lower()
                            if isinstance(match, dict)
                            else "info"
                        )
                        # Map MobSF severity to our normalised levels
                        severity = _normalise_severity(severity)
                        title = match.get("title", match.get("name", str(rule_id))) if isinstance(match, dict) else str(rule_id)
                        desc = match.get("description", match.get("detail", "")) if isinstance(match, dict) else str(match)

                        findings.append(
                            Finding(
                                tool="mobsf",
                                severity=severity,
                                category="code_analysis",
                                title=str(title),
                                description=str(desc),
                                location=match.get("file", match.get("location", "")) if isinstance(match, dict) else "",
                            )
                        )

        # --- Static analysis permissions ---
        static_analysis = sast.get("static_analysis", {}) or report.get("static_analysis", {})
        permissions = static_analysis.get("permissions", [])
        if isinstance(permissions, list):
            dangerous_perms = [
                p for p in permissions
                if isinstance(p, str) and (
                    "READ_EXTERNAL_STORAGE" in p
                    or "WRITE_EXTERNAL_STORAGE" in p
                    or "RECORD_AUDIO" in p
                    or "CAMERA" in p
                    or "ACCESS_FINE_LOCATION" in p
                    or "ACCESS_COARSE_LOCATION" in p
                    or "READ_SMS" in p
                    or "SEND_SMS" in p
                    or "READ_CONTACTS" in p
                )
            ]
            if dangerous_perms:
                findings.append(
                    Finding(
                        tool="mobsf",
                        severity="medium",
                        category="dangerous_permissions",
                        title="Dangerous permissions requested",
                        description=f"The APK requests {len(dangerous_perms)} dangerous permission(s): "
                                    f"{', '.join(dangerous_perms)}.",
                        location="AndroidManifest.xml",
                        recommendation="Review whether each dangerous permission is strictly "
                                        "required and remove any that are unnecessary.",
                    )
                )

        # --- Malware analysis ---
        malware_analysis = sast.get("malware_analysis", {}) or report.get("malware_analysis", {})
        malware_families = malware_analysis.get("malware_families", [])
        if malware_families:
            findings.append(
                Finding(
                    tool="mobsf",
                    severity="critical",
                    category="malware",
                    title="Potential malware matches detected",
                    description=f"MobSF flagged {len(malware_families)} potential malware "
                                f"family/families: {', '.join(str(m) for m in malware_families)}.",
                    recommendation="Investigate the flagged APK thoroughly in a sandboxed environment.",
                )
            )

        return findings

    @staticmethod
    def _extract_findings_from_jadx(
        jadx_result: Dict[str, Any],
        search_results: Dict[str, Any],
    ) -> List[Finding]:
        """Extract findings from JADX decompilation and vulnerability search results.

        Parameters
        ----------
        jadx_result:
            The ``"jadx"`` section of pipeline results.
        search_results:
            The ``"vulnerability_search"`` dict from the JADX pipeline.

        Returns
        -------
        list[Finding]
            Synthesised findings from decompilation and regex searches.
        """
        findings: List[Finding] = []
        severity_map: Dict[str, str] = {
            "hardcoded_api_key": "critical",
            "insecure_webview": "high",
            "weak_hash": "high",
            "sql_injection": "critical",
            "logging_sensitive": "low",
            "pending_intent_flags": "medium",
            "deeplink_schemes": "info",
            "insecure_random": "medium",
            "ssl_pinning_bypass": "high",
            "world_writable_file": "medium",
        }
        category_titles: Dict[str, str] = {
            "hardcoded_api_key": "Hardcoded API Key / Secret",
            "insecure_webview": "Insecure WebView Configuration",
            "weak_hash": "Weak Hashing Algorithm",
            "sql_injection": "Potential SQL Injection",
            "logging_sensitive": "Sensitive Data in Logs",
            "pending_intent_flags": "PendingIntent Flag Concerns",
            "deeplink_schemes": "Custom Deeplink Schemes",
            "insecure_random": "Insecure Random Number Generator",
            "ssl_pinning_bypass": "SSL Pinning Bypass / Weak TrustManager",
            "world_writable_file": "World-Writable File Permissions",
        }
        category_descriptions: Dict[str, str] = {
            "hardcoded_api_key": "The application contains what appears to be a hardcoded API key, "
                                  "secret token, or private key embedded in the source code.",
            "insecure_webview": "A WebView component is configured with settings that could allow "
                                "arbitrary code execution or file access.",
            "weak_hash": "A weak or deprecated hashing algorithm (MD5 or SHA-1) is being used. "
                         "These are considered cryptographically broken.",
            "sql_injection": "Raw SQL queries appear to be constructed with string concatenation, "
                             "potentially enabling SQL injection attacks.",
            "logging_sensitive": "Sensitive data such as passwords, tokens, or credentials may be "
                                 "written to the Android system log (Logcat).",
            "pending_intent_flags": "PendingIntent is used with flags that may introduce security "
                                    "vulnerabilities (FLAG_UPDATE_CURRENT, FLAG_MUTABLE).",
            "deeplink_schemes": "Custom URI schemes are declared in the manifest. Verify that "
                                "deeplink handling does not expose functionality to malicious apps.",
            "insecure_random": "java.util.Random is used instead of SecureRandom for security-"
                               "sensitive operations.",
            "ssl_pinning_bypass": "A custom TrustManager implementation may be bypassing SSL/TLS "
                                  "certificate validation, leaving communications vulnerable to MITM.",
            "world_writable_file": "Files or preferences are created with world-readable or world-"
                                   "writable permissions, exposing data to other applications.",
        }
        category_recommendations: Dict[str, str] = {
            "hardcoded_api_key": "Store secrets in environment variables, a secrets manager, or "
                                 "encrypted storage — never in source code.",
            "insecure_webview": "Disable JavaScript unless strictly needed, and set "
                                "``setAllowFileAccess`` to ``false``.",
            "weak_hash": "Use a strong, modern hash function such as SHA-256 or SHA-3.",
            "sql_injection": "Use parameterised queries (``?`` placeholders) or an ORM instead of "
                             "string concatenation.",
            "logging_sensitive": "Remove sensitive data from log statements or guard them behind "
                                 "``BuildConfig.DEBUG`` checks.",
            "pending_intent_flags": "Use ``FLAG_IMMUTABLE`` for PendingIntents where the fill-in "
                                    "parameters do not need to change.",
            "deeplink_schemes": "Validate all incoming URIs and do not assume the caller is "
                                "trustworthy.",
            "insecure_random": "Replace ``java.util.Random`` with ``java.security.SecureRandom`` "
                               "for security-sensitive contexts.",
            "ssl_pinning_bypass": "Ensure the TrustManager performs proper certificate "
                                  "validation and does not blindly trust all certificates.",
            "world_writable_file": "Use ``MODE_PRIVATE`` for file creation and avoid "
                                   "``MODE_WORLD_READABLE`` / ``MODE_WORLD_WRITEABLE``.",
        }

        # Findings from vulnerability search results
        if "hardcoded_api_key" in search_results:  # compatibility with _summary
            for category, matches in search_results.items():
                if category == "_summary":
                    continue
                if not isinstance(matches, list) or not matches:
                    continue

                severity = severity_map.get(category, "info")
                title = category_titles.get(category, category.replace("_", " ").title())
                description = category_descriptions.get(
                    category,
                    f"Potential issue found in category: {category}",
                )
                recommendation = category_recommendations.get(category, "")

                for match in matches[:10]:  # cap per category to keep report concise
                    location = ""
                    if isinstance(match, dict):
                        location = match.get("file", match.get("location", ""))
                        if match.get("line"):
                            location = f"{location}:{match['line']}"
                    elif isinstance(match, str):
                        location = match

                    findings.append(
                        Finding(
                            tool="jadx",
                            severity=severity,
                            category=category,
                            title=title,
                            description=description,
                            location=location,
                            recommendation=recommendation,
                        )
                    )

        # Decompilation quality indicators
        decompile = jadx_result.get("decompile", {}) or jadx_result.get("decompile_report", {})
        bad_code = decompile.get("bad_code_entries", [])
        if bad_code:
            findings.append(
                Finding(
                    tool="jadx",
                    severity="info",
                    category="decompilation_quality",
                    title=f"JADX flagged {len(bad_code)} bad-code entries",
                    description="JADX encountered code that could not be fully decompiled. "
                                "Some source files may contain synthetic or unresolvable references.",
                    location="",
                    recommendation="Review the bad-code entries in the JADX output and manually "
                                   "inspect the affected classes.",
                )
            )

        return findings


# ── Internal helpers ───────────────────────────────────────────────────────────


def _normalise_severity(raw: str) -> str:
    """Map MobSF and other tool severity strings to our canonical levels."""
    raw_lower = raw.strip().lower()
    mapping = {
        "critical": "critical",
        "high": "high",
        "warning": "medium",
        "medium": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "good": "info",
        "secure": "info",
        "pass": "info",
    }
    return mapping.get(raw_lower, "info")
