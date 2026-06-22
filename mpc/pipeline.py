"""Pipeline orchestrator for MPC.

Coordinates multi-tool analysis across MobSF, JADX, and Ghidra,
providing unified entry points for sequential and parallel analysis.
"""

from __future__ import annotations

import concurrent.futures
import logging
import os
import re
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

from mpc.config import MPCConfig
from mpc.ghidra import GhidraClient
from mpc.jadx import JadxClient
from mpc.mobsf import MobSFClient

logger = logging.getLogger(__name__)


class Orchestrator:
    """Coordinates analysis across MobSF, JADX, and Ghidra.

    Usage::

        orch = Orchestrator()
        results = orch.analyze_apk("target.apk")
        report_path = orch.generate_report("target.apk")
    """

    def __init__(
        self,
        mobsf_client: Optional[MobSFClient] = None,
        jadx_client: Optional[JadxClient] = None,
        ghidra_client: Optional[GhidraClient] = None,
    ) -> None:
        """Initialise the orchestrator.

        Accepts pre-configured clients or creates default instances.
        """
        self.config = MPCConfig.load()

        self.mobsf: MobSFClient = mobsf_client or MobSFClient()
        self.jadx: JadxClient = jadx_client or JadxClient()
        self.ghidra: GhidraClient = ghidra_client or GhidraClient(
            config=self.config,
        )

    # ------------------------------------------------------------------
    # Full-pipeline entry points
    # ------------------------------------------------------------------

    def analyze_apk(
        self,
        apk_path: str,
        *,
        run_mobsf: bool = True,
        run_jadx: bool = True,
        run_ghidra: bool = False,
    ) -> Dict[str, Any]:
        """Run a full APK analysis pipeline.

        Each enabled tool is executed **sequentially**.  The result dict
        contains a top-level key per tool (``"mobsf"``, ``"jadx"``,
        ``"ghidra"``) with that tool's output, plus an ``"errors"`` list
        and a ``"apk_path"`` field.

        Parameters
        ----------
        apk_path:
            Path to the APK file on disk.
        run_mobsf:
            Whether to run MobSF analysis (default ``True``).
        run_jadx:
            Whether to run JADX decompilation (default ``True``).
        run_ghidra:
            Whether to run Ghidra analysis (default ``False``).

        Returns
        -------
        dict
            Consolidated results from every requested tool.
        """
        apk_path = os.path.abspath(apk_path)
        result: Dict[str, Any] = {
            "apk_path": apk_path,
            "mobsf": None,
            "jadx": None,
            "ghidra": None,
            "errors": [],
        }

        if not os.path.isfile(apk_path):
            result["errors"].append(f"APK not found: {apk_path}")
            return result

        if run_mobsf:
            try:
                result["mobsf"] = self.mobsf_pipeline(apk_path)
            except Exception as exc:
                msg = f"MobSF pipeline failed: {exc}"
                logger.exception(msg)
                result["errors"].append(msg)

        if run_jadx:
            try:
                result["jadx"] = self.jadx_pipeline(apk_path)
            except Exception as exc:
                msg = f"JADX pipeline failed: {exc}"
                logger.exception(msg)
                result["errors"].append(msg)

        if run_ghidra:
            try:
                result["ghidra"] = self.ghidra.analyze_apk(apk_path)
            except Exception as exc:
                msg = f"Ghidra analysis failed: {exc}"
                logger.exception(msg)
                result["errors"].append(msg)

        return result

    def analyze_apk_parallel(self, apk_path: str) -> Dict[str, Any]:
        """Run MobSF and JADX analysis **in parallel**.

        Ghidra is excluded from parallel execution by default because it is
        typically the slowest tool and is rarely needed for quick triage.

        Parameters
        ----------
        apk_path:
            Path to the APK file on disk.

        Returns
        -------
        dict
            Consolidated results (same schema as :meth:`analyze_apk`).
        """
        apk_path = os.path.abspath(apk_path)
        result: Dict[str, Any] = {
            "apk_path": apk_path,
            "mobsf": None,
            "jadx": None,
            "ghidra": None,
            "errors": [],
        }

        if not os.path.isfile(apk_path):
            result["errors"].append(f"APK not found: {apk_path}")
            return result

        with ThreadPoolExecutor(max_workers=2) as pool:
            mobsf_future: Future = pool.submit(self.mobsf_pipeline, apk_path)
            jadx_future: Future = pool.submit(self.jadx_pipeline, apk_path)

            for name, future in [("mobsf", mobsf_future), ("jadx", jadx_future)]:
                try:
                    result[name] = future.result()
                except Exception as exc:
                    msg = f"{name} pipeline failed (parallel): {exc}"
                    logger.exception(msg)
                    result["errors"].append(msg)

        return result

    # ------------------------------------------------------------------
    # Single-tool pipelines
    # ------------------------------------------------------------------

    def mobsf_pipeline(self, apk_path: str) -> Dict[str, Any]:
        """Complete MobSF workflow: upload → scan → report → SAST summary.

        Parameters
        ----------
        apk_path:
            Path to the APK file on disk.

        Returns
        -------
        dict
            Contains ``"upload"``, ``"scan"``, ``"report"``, and
            ``"sast_summary"`` sub-dicts.
        """
        apk_path = os.path.abspath(apk_path)
        result: Dict[str, Any] = {
            "upload": None,
            "scan": None,
            "report": None,
            "sast_summary": None,
        }

        upload = self.mobsf.upload(apk_path)
        result["upload"] = upload

        file_hash: str = upload["hash"]
        scan = self.mobsf.scan(file_hash)
        result["scan"] = scan

        report = self.mobsf.report_json(file_hash)
        result["report"] = report

        sast = self.mobsf.get_sast_summary(file_hash)
        result["sast_summary"] = sast

        return result

    def jadx_pipeline(self, apk_path: str) -> Dict[str, Any]:
        """Complete JADX workflow: decompile → search for vulnerabilities.

        Parameters
        ----------
        apk_path:
            Path to the APK file on disk.

        Returns
        -------
        dict
            Contains ``"decompile"`` (raw decompile result),
            ``"decompile_report"`` (rich summary), and
            ``"vulnerability_search"`` (results from
            :meth:`search_vulnerabilities`).
        """
        apk_path = os.path.abspath(apk_path)
        result: Dict[str, Any] = {
            "decompile": None,
            "decompile_report": None,
            "vulnerability_search": None,
        }

        decompile = self.jadx.decompile_with_report(apk_path)
        result["decompile"] = decompile
        result["decompile_report"] = {
            "success": decompile.get("success"),
            "output_path": decompile.get("output_path"),
            "total_files": decompile.get("total_files", 0),
            "bad_code_entries": decompile.get("bad_code_entries", []),
        }

        output_path = decompile.get("output_path")
        if decompile.get("success") and output_path:
            vuln_search = self.search_vulnerabilities(output_path)
            result["vulnerability_search"] = vuln_search
        else:
            result["vulnerability_search"] = {}

        return result

    # ------------------------------------------------------------------
    # Vulnerability search
    # ------------------------------------------------------------------

    def search_vulnerabilities(
        self,
        jadx_output_dir: str,
        patterns: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Search decompiled Java sources for vulnerability patterns.

        Parameters
        ----------
        jadx_output_dir:
            Root directory of the JADX decompiled output.
        patterns:
            A dict mapping category names to regex patterns.
            When ``None``, :meth:`_default_vuln_patterns` is used.

        Returns
        -------
        dict
            Maps each category to a list of match dicts (each with
            ``"file"``, ``"line"``, ``"content"`` keys).  A top-level
            ``"_summary"`` key provides counts per category.
        """
        if patterns is None:
            patterns = self._default_vuln_patterns()

        results: Dict[str, Any] = {}
        total_findings = 0

        for category, regex in patterns.items():
            try:
                matches = self.jadx.search_code(jadx_output_dir, regex)
            except re.error as exc:
                logger.warning("Invalid regex for category '%s': %s", category, exc)
                matches = []

            results[category] = matches
            total_findings += len(matches)

        results["_summary"] = {
            "total_findings": total_findings,
            "categories_with_matches": [
                cat for cat, matches in results.items()
                if cat != "_summary" and matches
            ],
        }

        return results

    def _default_vuln_patterns(self) -> Dict[str, str]:
        """Return default regex patterns for common Android vulnerabilities.

        Returns
        -------
        dict
            Maps category names to compiled regex patterns.
        """
        return {
            "hardcoded_api_key": (
                r"(?i)(?:sk_live_|pk_live_|AIza[0-9A-Za-z_-]{35}|"
                r"AKIA[0-9A-Z]{16}|"
                r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)"
            ),
            "insecure_webview": (
                r"\bsetJavaScriptEnabled\s*\(\s*true\s*\)|"
                r"\bsetAllowFileAccess\s*\(\s*true\s*\)|"
                r"\bsetAllowFileAccessFromFileURLs\s*\(\s*true\s*\)|"
                r"\bsetAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)"
            ),
            "weak_hash": (
                r"MessageDigest\.getInstance\s*\(\s*\"MD5\"\s*\)|"
                r"MessageDigest\.getInstance\s*\(\s*\"SHA-1\"\s*\)|"
                r"MessageDigest\.getInstance\s*\(\s*\"SHA1\"\s*\)"
            ),
            "sql_injection": (
                r"(?i)(?:rawQuery\s*\(\s*[^)]*\"\s*\+\s*|"
                r"execSQL\s*\(\s*[^)]*\"\s*\+\s*|"
                r"compileStatement\s*\(\s*[^)]*\"\s*\+\s*)"
            ),
            "logging_sensitive": (
                r"(?i)Log\.\w+\s*\(\s*[^)]*(?:password|secret|token|"
                r"api_key|apiKey|auth|credential|jwt|session)\s*[^)]*\)"
            ),
            "pending_intent_flags": (
                r"PendingIntent\.\w+\s*\([^)]*"
                r"FLAG_UPDATE_CURRENT[^)]*"
                r"|PendingIntent\.\w+\s*\([^)]*"
                r"FLAG_MUTABLE[^)]*"
            ),
            "deeplink_schemes": (
                r"android:scheme\s*=\s*\"(?!https?|ftp)\w+://\""
            ),
            "insecure_random": (
                r"new\s+java\.util\.Random\s*\(|"
                r"new\s+Random\s*\("
            ),
            "ssl_pinning_bypass": (
                r"X509TrustManager|"
                r"checkClientTrusted\s*\([^)]*\)\s*\{\s*\}|"
                r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}"
            ),
            "world_writable_file": (
                r"(?i)MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE"
            ),
        }

    # ------------------------------------------------------------------
    # Report generation convenience
    # ------------------------------------------------------------------

    def generate_report(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
        *,
        run_mobsf: bool = True,
        run_jadx: bool = True,
        run_ghidra: bool = False,
    ) -> str:
        """Run the full analysis pipeline and generate report files.

        This is a convenience method that runs :meth:`analyze_apk` and
        then writes JSON, Markdown, and HTML reports to *output_dir*
        (defaults to ``./reports``).  Returns the path to the report
        directory.

        Parameters
        ----------
        apk_path:
            Path to the APK file on disk.
        output_dir:
            Directory where reports are saved.  Defaults to the
            configured ``report_dir`` (``./reports``).
        run_mobsf:
            Passed through to :meth:`analyze_apk`.
        run_jadx:
            Passed through to :meth:`analyze_apk`.
        run_ghidra:
            Passed through to :meth:`analyze_apk`.

        Returns
        -------
        str
            Absolute path to the generated report directory.
        """
        # Lazy import to avoid circular dependency at module level.
        from mpc.report import ReportGenerator  # noqa: PLC0415

        if output_dir is None:
            output_dir = self.config.report_dir

        out_path = Path(output_dir).resolve()
        out_path.mkdir(parents=True, exist_ok=True)

        pipeline_results = self.analyze_apk(
            apk_path,
            run_mobsf=run_mobsf,
            run_jadx=run_jadx,
            run_ghidra=run_ghidra,
        )

        rgen = ReportGenerator()

        # JSON
        json_report = rgen.generate_json(apk_path, pipeline_results)
        json_path = out_path / f"{Path(apk_path).stem}_report.json"
        json_path.write_text(
            __import__("json").dumps(json_report, indent=2, default=str),
            encoding="utf-8",
        )
        logger.info("JSON report written to %s", json_path)

        # Markdown
        md_report = rgen.generate_markdown(apk_path, pipeline_results)
        md_path = out_path / f"{Path(apk_path).stem}_report.md"
        md_path.write_text(md_report, encoding="utf-8")
        logger.info("Markdown report written to %s", md_path)

        # HTML
        html_report = rgen.generate_html(apk_path, pipeline_results)
        html_path = out_path / f"{Path(apk_path).stem}_report.html"
        html_path.write_text(html_report, encoding="utf-8")
        logger.info("HTML report written to %s", html_path)

        return str(out_path)
