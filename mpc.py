#!/usr/bin/env python3

# Standard library imports
import argparse
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional

# Third-party imports
import cmd2
import click
import requests

# Local imports
from mpc import MobSFClient, JadxClient, GhidraClient, Orchestrator, ReportGenerator
from mpc.config import MPCConfig
from mpc.mobsf import MobSFConnectionError, MobSFAuthError

# ── ANSI color constants (matching medusa.py style) ────────────────────────
RED = "\033[1;31m"
BLUE = "\033[1;34m"
CYAN = "\033[1;36m"
WHITE = "\033[1;37m"
YELLOW = "\033[1;33m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD = "\033[;1m"
REVERSE = "\033[;7m"

FLUX_LOGO = """
    ___________  __  _   ______
   / ____/ ___/ / / / | / / _/
  / /_   \\__ \\ / / /  |/ / /
 / __/  ___/ // /_/ /|  / /___
/_/    /____/ \\____/ |_/_____/
  Mobile Security Analysis Forge
"""


# ── CLI Application ────────────────────────────────────────────────────────


class FluxCLI(cmd2.Cmd):
    """FLUX - Mobile Security Analysis Forge interactive shell."""

    prompt = CYAN + "flux>" + RESET

    def __init__(self) -> None:
        super().__init__(allow_cli_args=False)

        # Load configuration and initialise clients lazily
        self._config: MPCConfig = MPCConfig.load()
        self._mobsf: Optional[MobSFClient] = None
        self._jadx: Optional[JadxClient] = None
        self._ghidra: Optional[GhidraClient] = None
        self._orchestrator: Optional[Orchestrator] = None

    # ── Properties for lazy initialisation ─────────────────────────────

    @property
    def config(self) -> MPCConfig:
        return self._config

    @property
    def mobsf(self) -> MobSFClient:
        if self._mobsf is None:
            self._mobsf = MobSFClient()
        return self._mobsf

    @property
    def jadx(self) -> JadxClient:
        if self._jadx is None:
            self._jadx = JadxClient()
        return self._jadx

    @property
    def ghidra(self) -> GhidraClient:
        if self._ghidra is None:
            self._ghidra = GhidraClient(config=self._config)
        return self._ghidra

    @property
    def orchestrator(self) -> Orchestrator:
        if self._orchestrator is None:
            self._orchestrator = Orchestrator(
                mobsf_client=self._mobsf,
                jadx_client=self._jadx,
                ghidra_client=self._ghidra,
            )
        return self._orchestrator

    # ── Startup ────────────────────────────────────────────────────────

    def preloop(self) -> None:
        """Display the banner at shell start."""
        randomized_fg = lambda: tuple(random.randint(0, 255) for _ in range(3))
        import random
        click.secho(FLUX_LOGO, fg=randomized_fg(), bold=True)
        click.secho(
            " 🧪 Type help for options 🧪\n",
            fg="green",
            bold=True,
        )

    # ── Core commands ──────────────────────────────────────────────────

    def do_analyze(self, line: str) -> None:
        """
        Run the APK analysis pipeline.

        Usage:
            analyze <apk_path> [--mobsf] [--jadx] [--ghidra]

        By default all three tools are enabled.  Use flags to select only
        specific tools (e.g. ``--mobsf --jadx``).
        """
        args = line.split()
        if not args:
            click.secho("[!] Usage: analyze <apk_path> [--mobsf] [--jadx] [--ghidra]", fg="red")
            return

        apk_path = args[0]
        flags = set(args[1:])

        # Determine which tools to run
        has_flags = bool(flags & {"--mobsf", "--jadx", "--ghidra"})
        run_mobsf = "--mobsf" in flags if has_flags else True
        run_jadx = "--jadx" in flags if has_flags else True
        run_ghidra = "--ghidra" in flags if has_flags else False

        if not os.path.isfile(apk_path):
            click.secho(f"[!] APK not found: {apk_path}", fg="red")
            return

        click.secho(f"[*] Analysing: {apk_path}", fg="cyan")
        click.secho(f"    MobSF={run_mobsf}  JADX={run_jadx}  Ghidra={run_ghidra}", fg="cyan")

        try:
            result = self.orchestrator.analyze_apk(
                apk_path,
                run_mobsf=run_mobsf,
                run_jadx=run_jadx,
                run_ghidra=run_ghidra,
            )
        except Exception as exc:
            click.secho(f"[!] Analysis pipeline failed: {exc}", fg="red")
            traceback.print_exc()
            return

        self._print_pipeline_result(result)

    def do_analyze_parallel(self, line: str) -> None:
        """
        Run MobSF + JADX analysis in parallel.

        Usage:
            analyze-parallel <apk_path>
        """
        apk_path = line.strip()
        if not apk_path:
            click.secho("[!] Usage: analyze-parallel <apk_path>", fg="red")
            return

        if not os.path.isfile(apk_path):
            click.secho(f"[!] APK not found: {apk_path}", fg="red")
            return

        click.secho(f"[*] Parallel analysis of {apk_path} ...", fg="cyan")

        try:
            result = self.orchestrator.analyze_apk_parallel(apk_path)
        except Exception as exc:
            click.secho(f"[!] Parallel analysis failed: {exc}", fg="red")
            traceback.print_exc()
            return

        self._print_pipeline_result(result)

    def do_report(self, line: str) -> None:
        """
        Run the full analysis pipeline and generate reports (JSON, Markdown, HTML).

        Usage:
            report <apk_path> [--output-dir <dir>]
        """
        parts = line.split()
        if not parts:
            click.secho("[!] Usage: report <apk_path> [--output-dir <dir>]", fg="red")
            return

        apk_path = parts[0]
        output_dir: Optional[str] = None

        if "--output-dir" in parts:
            idx = parts.index("--output-dir")
            if idx + 1 < len(parts):
                output_dir = parts[idx + 1]
            else:
                click.secho("[!] --output-dir requires a path argument", fg="red")
                return

        if not os.path.isfile(apk_path):
            click.secho(f"[!] APK not found: {apk_path}", fg="red")
            return

        click.secho(f"[*] Generating report for: {apk_path}", fg="cyan")

        try:
            report_dir = self.orchestrator.generate_report(
                apk_path,
                output_dir=output_dir or None,
            )
        except Exception as exc:
            click.secho(f"[!] Report generation failed: {exc}", fg="red")
            traceback.print_exc()
            return

        click.secho(f"[+] Reports written to: {report_dir}", fg="green")

        # Print a quick summary
        report_path = Path(report_dir)
        for ext in ("json", "md", "html"):
            f = report_path / f"{Path(apk_path).stem}_report.{ext}"
            if f.exists():
                click.secho(f"    - {f}", fg="green")

    def do_config(self, line: str) -> None:
        """
        View or set MPC configuration.

        Usage:
            config               — show all configuration
            config <key>         — show a specific key
            config <key> <value> — set a specific key (in-memory only)

        Available keys:
            mobsf_url, mobsf_api_key, jadx_bin, jadx_mcp_url,
            ghidra_mcp_url, report_dir, tool_timeout, ghidra_timeout
        """
        parts = line.split()

        if not parts:
            # Show all config
            click.secho("\n  MPC Configuration", fg="cyan", bold=True)
            click.secho("  " + "-" * 40, fg="cyan")
            click.secho(f"    mobsf_url       : {self._config.mobsf_url}", fg="white")
            click.secho(f"    mobsf_api_key   : {'***set***' if self._config.mobsf_api_key else '(not set)'}", fg="white")
            click.secho(f"    jadx_bin        : {self._config.jadx_bin}", fg="white")
            click.secho(f"    jadx_mcp_url    : {self._config.jadx_mcp_url}", fg="white")
            click.secho(f"    ghidra_mcp_url  : {self._config.ghidra_mcp_url}", fg="white")
            click.secho(f"    report_dir      : {self._config.report_dir}", fg="white")
            click.secho(f"    tool_timeout    : {self._config.tool_timeout}", fg="white")
            click.secho(f"    ghidra_timeout  : {self._config.ghidra_timeout}", fg="white")
            click.secho("")
            return

        key = parts[0].lower()
        valid_keys = {
            "mobsf_url", "mobsf_api_key", "jadx_bin", "jadx_mcp_url",
            "ghidra_mcp_url", "report_dir", "tool_timeout", "ghidra_timeout",
        }

        if key not in valid_keys:
            click.secho(f"[!] Unknown config key: {key}", fg="red")
            click.secho(f"    Valid keys: {', '.join(sorted(valid_keys))}", fg="yellow")
            return

        if len(parts) == 1:
            # Show single key
            value = getattr(self._config, key, "(unknown)")
            click.secho(f"    {key} = {value}", fg="white")
            return

        # Set a key (in-memory only)
        new_value: Any = parts[1]
        if key in ("tool_timeout", "ghidra_timeout", "mcp_port"):
            try:
                new_value = int(new_value)
            except ValueError:
                click.secho(f"[!] {key} must be an integer", fg="red")
                return

        setattr(self._config, key, new_value)
        click.secho(f"[+] {key} set to {new_value} (in-memory)", fg="green")
        click.secho("    Note: Changes are not persisted. Set environment variables for permanent config.", fg="yellow")

    # ── MobSF commands ─────────────────────────────────────────────────

    def do_mobsf_check(self, line: str) -> None:
        """
        Check MobSF server health.

        Usage:
            mobsf-check
        """
        url = self._config.mobsf_url.rstrip("/")
        click.secho(f"[*] Checking MobSF at {url} ...", fg="cyan")

        try:
            resp = requests.get(f"{url}/api/v1/", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                version = data.get("version", data.get("message", "unknown"))
                click.secho(f"[+] MobSF is running  (version: {version})", fg="green")
            else:
                click.secho(f"[?] MobSF responded with HTTP {resp.status_code}", fg="yellow")
        except requests.ConnectionError:
            click.secho(f"[!] Could not connect to MobSF at {url}", fg="red")
        except requests.Timeout:
            click.secho(f"[!] MobSF request timed out at {url}", fg="red")
        except Exception as exc:
            click.secho(f"[!] MobSF check failed: {exc}", fg="red")

    def do_mobsf_upload(self, line: str) -> None:
        """
        Upload an APK to MobSF.

        Usage:
            mobsf-upload <apk_path>
        """
        apk_path = line.strip()
        if not apk_path:
            click.secho("[!] Usage: mobsf-upload <apk_path>", fg="red")
            return

        if not os.path.isfile(apk_path):
            click.secho(f"[!] APK not found: {apk_path}", fg="red")
            return

        click.secho(f"[*] Uploading {apk_path} to MobSF ...", fg="cyan")

        try:
            result = self.mobsf.upload(apk_path)
        except MobSFConnectionError as exc:
            click.secho(f"[!] MobSF connection error: {exc}", fg="red")
            return
        except MobSFAuthError as exc:
            click.secho(f"[!] MobSF auth error: {exc}", fg="red")
            return
        except Exception as exc:
            click.secho(f"[!] Upload failed: {exc}", fg="red")
            traceback.print_exc()
            return

        click.secho("[+] Upload successful", fg="green")
        click.secho(f"    Hash    : {result.get('hash', 'N/A')}", fg="white")
        click.secho(f"    File    : {result.get('file_name', 'N/A')}", fg="white")
        click.secho(f"    Type    : {result.get('scan_type', 'N/A')}", fg="white")

    def do_mobsf_scan(self, line: str) -> None:
        """
        Start a MobSF scan on an uploaded file.

        Usage:
            mobsf-scan <file_hash>
        """
        file_hash = line.strip()
        if not file_hash:
            click.secho("[!] Usage: mobsf-scan <file_hash>", fg="red")
            return

        click.secho(f"[*] Starting MobSF scan for hash: {file_hash} ...", fg="cyan")

        try:
            result = self.mobsf.scan(file_hash)
        except Exception as exc:
            click.secho(f"[!] Scan failed: {exc}", fg="red")
            traceback.print_exc()
            return

        click.secho("[+] Scan initiated", fg="green")
        scan_type = result.get("scan_type", "N/A")
        file_name = result.get("file_name", "N/A")
        click.secho(f"    Type: {scan_type}  File: {file_name}", fg="white")

    def do_mobsf_report(self, line: str) -> None:
        """
        Retrieve the MobSF JSON report for a scanned file.

        Usage:
            mobsf-report <file_hash>
        """
        file_hash = line.strip()
        if not file_hash:
            click.secho("[!] Usage: mobsf-report <file_hash>", fg="red")
            return

        click.secho(f"[*] Fetching MobSF report for hash: {file_hash} ...", fg="cyan")

        try:
            report = self.mobsf.report_json(file_hash)
        except Exception as exc:
            click.secho(f"[!] Report retrieval failed: {exc}", fg="red")
            traceback.print_exc()
            return

        click.secho("[+] Report received", fg="green")

        # Print a compact summary
        pkg_name = report.get("package_name", "N/A")
        app_name = report.get("app_name", "N/A")

        click.secho(f"    Package : {pkg_name}", fg="white")
        click.secho(f"    App     : {app_name}", fg="white")

        # Code analysis summary
        code_analysis = report.get("code_analysis", {}) or report.get("static_analysis", {})
        findings = code_analysis.get("findings", {})
        if isinstance(findings, dict) and findings:
            click.secho(f"    Findings: {sum(len(v) if isinstance(v, list) else 0 for v in findings.values())} issues", fg="yellow")

        # Print first 20 lines of the report as preview
        preview = json.dumps(report, indent=2, default=str)[:2000]
        click.secho("\n  --- Report preview (first 2000 chars) ---", fg="cyan")
        click.secho(preview, fg="white")

        # Optionally save to file
        save_path = Path.cwd() / f"{file_hash}_mobsf_report.json"
        save_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        click.secho(f"\n[+] Full report saved to: {save_path}", fg="green")

    # ── JADX commands ──────────────────────────────────────────────────

    def do_jadx_decompile(self, line: str) -> None:
        """
        Decompile an APK using JADX.

        Usage:
            jadx-decompile <apk_path>
        """
        apk_path = line.strip()
        if not apk_path:
            click.secho("[!] Usage: jadx-decompile <apk_path>", fg="red")
            return

        if not os.path.isfile(apk_path):
            click.secho(f"[!] APK not found: {apk_path}", fg="red")
            return

        click.secho(f"[*] Decompiling {apk_path} with JADX ...", fg="cyan")

        try:
            result = self.jadx.decompile_with_report(apk_path)
        except Exception as exc:
            click.secho(f"[!] JADX decompilation failed: {exc}", fg="red")
            traceback.print_exc()
            return

        if result.get("success"):
            click.secho("[+] Decompilation successful", fg="green")
            click.secho(f"    Output path : {result.get('output_path', 'N/A')}", fg="white")
            click.secho(f"    .java files : {result.get('total_files', 0)}", fg="white")

            bad_code = result.get("bad_code_entries", [])
            if bad_code:
                click.secho(f"    Bad-code    : {len(bad_code)} entries", fg="yellow")
                for entry in bad_code[:5]:
                    click.secho(f"      - {entry}", fg="yellow")
                if len(bad_code) > 5:
                    click.secho(f"      ... and {len(bad_code) - 5} more", fg="yellow")
        else:
            click.secho(f"[!] Decompilation failed: {result.get('error', 'Unknown error')}", fg="red")

    def do_jadx_search(self, line: str) -> None:
        """
        Search decompiled JADX output for a regex pattern.

        Usage:
            jadx-search <apk_path> <pattern>

        The output directory is derived from the APK path
        (``<apk_stem>_jadx`` in the same directory as the APK).
        """
        parts = line.split(maxsplit=1)
        if len(parts) < 2:
            click.secho("[!] Usage: jadx-search <apk_path> <pattern>", fg="red")
            return

        apk_path = parts[0]
        pattern = parts[1]

        if not os.path.isfile(apk_path):
            click.secho(f"[!] APK not found: {apk_path}", fg="red")
            return

        # Derive the default output dir the same way JadxClient does
        output_dir = str(Path(apk_path).parent / f"{Path(apk_path).stem}_jadx")

        if not os.path.isdir(output_dir):
            click.secho(f"[!] JADX output dir not found: {output_dir}", fg="red")
            click.secho("    Run 'jadx-decompile' first, or ensure the output directory exists.", fg="yellow")
            return

        click.secho(f"[*] Searching '{pattern}' in {output_dir} ...", fg="cyan")

        try:
            matches = self.jadx.search_code(output_dir, pattern)
        except Exception as exc:
            click.secho(f"[!] Search failed: {exc}", fg="red")
            traceback.print_exc()
            return

        if not matches:
            click.secho("[i] No matches found.", fg="yellow")
            return

        click.secho(f"[+] Found {len(matches)} match(es):\n", fg="green")
        for m in matches[:30]:  # cap output to 30 results
            click.secho(f"  {m['file']}:{m['line']}", fg="cyan", nl=False)
            click.secho(f"  {m['content'].strip()[:120]}", fg="white")
        if len(matches) > 30:
            click.secho(f"  ... and {len(matches) - 30} more matches (showing first 30)", fg="yellow")

    # ── Ghidra commands ────────────────────────────────────────────────

    def do_ghidra_analyze(self, line: str) -> None:
        """
        Run Ghidra headless analysis on an APK.

        Usage:
            ghidra-analyze <apk_path>
        """
        apk_path = line.strip()
        if not apk_path:
            click.secho("[!] Usage: ghidra-analyze <apk_path>", fg="red")
            return

        if not os.path.isfile(apk_path):
            click.secho(f"[!] APK not found: {apk_path}", fg="red")
            return

        click.secho(f"[*] Analysing {apk_path} with Ghidra (this may take a while) ...", fg="cyan")

        try:
            result = self.ghidra.analyze_apk(apk_path)
        except Exception as exc:
            click.secho(f"[!] Ghidra analysis failed: {exc}", fg="red")
            traceback.print_exc()
            return

        if result.get("success"):
            click.secho("[+] Ghidra analysis completed", fg="green")
            click.secho(f"    Project     : {result.get('project_name', 'N/A')}", fg="white")
            click.secho(f"    Project dir : {result.get('project_path', 'N/A')}", fg="white")
            click.secho(f"    Return code : {result.get('return_code', -1)}", fg="white")
        else:
            click.secho(f"[!] Ghidra analysis failed: {result.get('error', 'Unknown error')}", fg="red")

    # ── Shell commands ─────────────────────────────────────────────────

    def do_exit(self, line: str) -> None:
        """
        Exit the MPC shell.
        """
        click.secho("Thank you for using MPC!", fg="cyan")
        sys.exit(0)

    def do_quit(self, line: str) -> None:
        """
        Quit the MPC shell (alias for exit).
        """
        self.do_exit(line)

    # ── Internal helpers ───────────────────────────────────────────────

    @staticmethod
    def _print_pipeline_result(result: Dict[str, Any]) -> None:
        """Pretty-print a pipeline result dictionary."""
        errors = result.get("errors", [])

        click.secho("\n  --- Pipeline Results ---", fg="cyan", bold=True)
        click.secho(f"  APK: {result.get('apk_path', 'N/A')}", fg="white")

        # MobSF section
        mobsf = result.get("mobsf")
        if mobsf:
            click.secho("\n  [+] MobSF", fg="green", bold=True)
            scan = mobsf.get("scan", {})
            report = mobsf.get("report", {})
            sast = mobsf.get("sast_summary", {})

            pkg = report.get("package_name", scan.get("package_name", "N/A"))
            click.secho(f"      Package       : {pkg}", fg="white")

            code_analysis = sast.get("code_analysis", {})
            raw_findings = code_analysis.get("findings", {})
            if isinstance(raw_findings, dict):
                click.secho(f"      Code findings : {sum(len(v) if isinstance(v, list) else 0 for v in raw_findings.values())} rules", fg="white")

            static_analysis = sast.get("static_analysis", {})
            permissions = static_analysis.get("permissions", [])
            if isinstance(permissions, list):
                click.secho(f"      Permissions   : {len(permissions)} declared", fg="white")
        else:
            click.secho("\n  [ ] MobSF: skipped or failed", fg="yellow")

        # JADX section
        jadx = result.get("jadx")
        if jadx:
            click.secho("\n  [+] JADX", fg="green", bold=True)
            decompile = jadx.get("decompile_report", {})
            click.secho(f"      .java files  : {decompile.get('total_files', 0)}", fg="white")
            click.secho(f"      Output dir   : {decompile.get('output_path', 'N/A')}", fg="white")

            vuln_search = jadx.get("vulnerability_search", {})
            summary = vuln_search.get("_summary", {})
            total = summary.get("total_findings", 0)
            if total:
                click.secho(f"      Vuln findings : {total}", fg="yellow")
                cats = summary.get("categories_with_matches", [])
                for cat in cats:
                    count = len(vuln_search.get(cat, []))
                    click.secho(f"        - {cat}: {count}", fg="white")
        else:
            click.secho("\n  [ ] JADX: skipped or failed", fg="yellow")

        # Ghidra section
        ghidra = result.get("ghidra")
        if ghidra:
            click.secho("\n  [+] Ghidra", fg="green", bold=True)
            click.secho(f"      Project     : {ghidra.get('project_name', 'N/A')}", fg="white")
            click.secho(f"      Return code : {ghidra.get('return_code', -1)}", fg="white")
        else:
            click.secho("\n  [ ] Ghidra: skipped or failed", fg="yellow")

        # Errors
        if errors:
            click.secho(f"\n  [!] Errors ({len(errors)})", fg="red", bold=True)
            for err in errors:
                click.secho(f"      - {err}", fg="red")

        click.secho("")


# ── Entry point ────────────────────────────────────────────────────────────


def main() -> None:
    """MPC CLI entry point.

    If command-line arguments are provided, they are treated as a single
    MPC command and executed directly.  Otherwise the interactive shell
    is started.
    """
    app = FluxCLI()

    if len(sys.argv) > 1:
        # Run a single command and exit
        cmd_line = " ".join(sys.argv[1:])
        try:
            app.onecmd(cmd_line)
        except SystemExit:
            pass
        except Exception as exc:
            click.secho(f"[!] Command failed: {exc}", fg="red")
            traceback.print_exc()
            sys.exit(1)
    else:
        # Interactive shell
        try:
            app.cmdloop()
        except KeyboardInterrupt:
            click.secho("\n[!] Interrupted. Exiting.", fg="yellow")
            sys.exit(0)


if __name__ == "__main__":
    main()
