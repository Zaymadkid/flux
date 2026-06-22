#!/usr/bin/env python3
"""
Thin MCP adapter for FLUX - Mobile Security Analysis Forge.

Exposes MobSF, JADX, Ghidra, and pipeline analysis as MCP tools
that MCP hosts (Claude Desktop, etc.) can call directly.

Recommended dependency:
    pip install "mcp[cli]"

Recommended transport:
    streamable-http
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:
    raise SystemExit(
        'Missing MCP SDK. Install it with: pip install "mcp[cli]"'
    ) from exc

from mpc.ghidra import GhidraClient
from mpc.jadx import JadxClient
from mpc.mobsf import MobSFClient
from mpc.pipeline import Orchestrator

logger = logging.getLogger(__name__)

mcp = FastMCP(
    name="FLUX - Mobile Security Analysis Forge",
    instructions=(
        "Analyse Android APKs through MobSF, JADX, and Ghidra. "
        "Use mobsf_healthcheck first to verify MobSF connectivity. "
        "The analyze_apk and generate_report tools chain multiple "
        "tools together automatically."
    ),
)


class MpcBridge:
    """Thread-safe wrapper around the MPC Orchestrator and its clients."""

    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.orch = Orchestrator()

    # ------------------------------------------------------------------
    # MobSF tools
    # ------------------------------------------------------------------

    def mobsf_healthcheck(self) -> dict[str, Any]:
        """Check whether the MobSF server is reachable."""
        with self.lock:
            try:
                # Attempt a GET to the MobSF base URL
                import requests
                resp = requests.get(
                    self.orch.mobsf.base_url.rstrip("/api/v1") + "/api/v1",
                    timeout=10,
                )
                return {
                    "reachable": resp.status_code < 500,
                    "status_code": resp.status_code,
                    "url": self.orch.mobsf.base_url,
                }
            except Exception as exc:
                return {
                    "reachable": False,
                    "error": str(exc),
                    "url": self.orch.mobsf.base_url,
                }

    def mobsf_upload(self, apk_path: str) -> dict[str, Any]:
        """Upload an APK to MobSF for analysis."""
        with self.lock:
            try:
                result = self.orch.mobsf.upload(apk_path)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def mobsf_scan(self, file_hash: str, scan_type: str = "apk") -> dict[str, Any]:
        """Start a MobSF scan on an uploaded file."""
        with self.lock:
            try:
                result = self.orch.mobsf.scan(file_hash, scan_type=scan_type)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def mobsf_report(self, file_hash: str) -> dict[str, Any]:
        """Retrieve the full MobSF JSON report for a scanned file."""
        with self.lock:
            try:
                result = self.orch.mobsf.report_json(file_hash)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def mobsf_sast_summary(self, file_hash: str) -> dict[str, Any]:
        """Get the MobSF SAST (static analysis) summary for a scanned file."""
        with self.lock:
            try:
                result = self.orch.mobsf.get_sast_summary(file_hash)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def mobsf_pipeline(self, apk_path: str) -> dict[str, Any]:
        """Run the full MobSF pipeline: upload -> scan -> report -> SAST summary."""
        with self.lock:
            try:
                result = self.orch.mobsf_pipeline(apk_path)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # JADX tools
    # ------------------------------------------------------------------

    def jadx_decompile(
        self,
        apk_path: str,
        output_dir: str | None = None,
    ) -> dict[str, Any]:
        """Decompile an APK with JADX."""
        with self.lock:
            try:
                result = self.orch.jadx.decompile(apk_path, output_dir=output_dir)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def jadx_decompile_with_report(self, apk_path: str) -> dict[str, Any]:
        """Decompile an APK with JADX and return a summary report."""
        with self.lock:
            try:
                result = self.orch.jadx.decompile_with_report(apk_path)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def jadx_search(self, apk_path: str, pattern: str) -> dict[str, Any]:
        """Search decompiled JADX output for a regex pattern.

        Decompiles the APK first if needed, then searches the Java sources.
        """
        with self.lock:
            try:
                # Decompile first
                decompile = self.orch.jadx.decompile(apk_path)
                if not decompile.get("success"):
                    return {"success": False, "error": decompile.get("error", "JADX decompilation failed")}

                output_path = decompile.get("output_path")
                if not output_path:
                    return {"success": False, "error": "No output path from JADX decompilation"}

                matches = self.orch.jadx.search_code(output_path, pattern)
                return {
                    "success": True,
                    "data": {
                        "output_path": output_path,
                        "matches_count": len(matches),
                        "matches": matches,
                    },
                }
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def jadx_list_files(self, apk_path: str) -> dict[str, Any]:
        """List decompiled Java files from a JADX analysis.

        Decompiles the APK first if needed, then lists all Java files.
        """
        with self.lock:
            try:
                decompile = self.orch.jadx.decompile(apk_path)
                if not decompile.get("success"):
                    return {"success": False, "error": decompile.get("error", "JADX decompilation failed")}

                output_path = decompile.get("output_path")
                if not output_path:
                    return {"success": False, "error": "No output path from JADX decompilation"}

                files = self.orch.jadx.get_decompiled_files(output_path)
                return {
                    "success": True,
                    "data": {
                        "output_path": output_path,
                        "total_files": len(files),
                        "files": files,
                    },
                }
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def jadx_pipeline(self, apk_path: str) -> dict[str, Any]:
        """Run the full JADX pipeline: decompile -> vulnerability search."""
        with self.lock:
            try:
                result = self.orch.jadx_pipeline(apk_path)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # ------------------------------------------------------------------
    # Ghidra tools
    # ------------------------------------------------------------------

    def ghidra(self) -> GhidraClient:
        """Return the GhidraMCP client."""
        return self.orch.ghidra

    def ghidra_analyze(
        self,
        apk_path: str,
        script_path: str | None = None,
    ) -> dict[str, Any]:
        """Import an APK into Ghidra for analysis via GhidraMCP."""
        with self.lock:
            try:
                result = self.orch.ghidra.analyze_apk(apk_path)
                return {"success": result.get("success", False), "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def ghidra_run_script(
        self,
        project_name: str,
        script_path: str,
    ) -> dict[str, Any]:
        """Run a Ghidra script against an existing project."""
        with self.lock:
            try:
                result = self.orch.ghidra.run_script(project_name, script_path)
                return {"success": result.get("success", False), "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    # ------------------------------------------------------------------
    # Pipeline tools
    # ------------------------------------------------------------------

    def analyze_apk(
        self,
        apk_path: str,
        run_mobsf: bool = True,
        run_jadx: bool = True,
        run_ghidra: bool = False,
    ) -> dict[str, Any]:
        """Run analysis pipeline with selected tools (sequential)."""
        with self.lock:
            try:
                result = self.orch.analyze_apk(
                    apk_path,
                    run_mobsf=run_mobsf,
                    run_jadx=run_jadx,
                    run_ghidra=run_ghidra,
                )
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def analyze_apk_parallel(self, apk_path: str) -> dict[str, Any]:
        """Run MobSF + JADX analysis in parallel."""
        with self.lock:
            try:
                result = self.orch.analyze_apk_parallel(apk_path)
                return {"success": True, "data": result}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def generate_report(
        self,
        apk_path: str,
        output_dir: str | None = None,
    ) -> dict[str, Any]:
        """Run full analysis pipeline and generate report files.

        Produces JSON, Markdown, and HTML reports in the output directory.
        """
        with self.lock:
            try:
                report_path = self.orch.generate_report(
                    apk_path,
                    output_dir=output_dir,
                )
                return {
                    "success": True,
                    "data": {
                        "report_dir": report_path,
                        "apk_path": apk_path,
                    },
                }
            except Exception as exc:
                return {"success": False, "error": str(exc)}


# ------------------------------------------------------------------
# Global bridge instance
# ------------------------------------------------------------------

bridge = MpcBridge()


# ------------------------------------------------------------------
# MCP tool registrations
# ------------------------------------------------------------------


# -- MobSF tools -------------------------------------------------------


@mcp.tool()
def mobsf_healthcheck() -> dict[str, Any]:
    """Check whether the MobSF server is reachable."""
    return bridge.mobsf_healthcheck()


@mcp.tool()
def mobsf_upload(apk_path: str) -> dict[str, Any]:
    """Upload an APK to MobSF for analysis. Returns a file hash needed by other MobSF tools."""
    return bridge.mobsf_upload(apk_path)


@mcp.tool()
def mobsf_scan(file_hash: str, scan_type: str = "apk") -> dict[str, Any]:
    """Start a MobSF scan on an uploaded file. Use the hash from mobsf_upload."""
    return bridge.mobsf_scan(file_hash, scan_type=scan_type)


@mcp.tool()
def mobsf_report(file_hash: str) -> dict[str, Any]:
    """Retrieve the full MobSF JSON report for a scanned file."""
    return bridge.mobsf_report(file_hash)


@mcp.tool()
def mobsf_sast_summary(file_hash: str) -> dict[str, Any]:
    """Get the MobSF SAST (static analysis) summary for a scanned file."""
    return bridge.mobsf_sast_summary(file_hash)


# -- JADX tools --------------------------------------------------------


@mcp.tool()
def jadx_decompile(apk_path: str, output_dir: str | None = None) -> dict[str, Any]:
    """Decompile an APK with JADX. Optionally specify an output directory."""
    return bridge.jadx_decompile(apk_path, output_dir=output_dir)


@mcp.tool()
def jadx_search(apk_path: str, pattern: str) -> dict[str, Any]:
    """Search decompiled JADX Java sources for a regex pattern. Decompiles the APK first."""
    return bridge.jadx_search(apk_path, pattern)


@mcp.tool()
def jadx_list_files(apk_path: str) -> dict[str, Any]:
    """List decompiled Java files from JADX analysis. Decompiles the APK first."""
    return bridge.jadx_list_files(apk_path)


# -- Ghidra tools (powered by GhidraMCP) ---------------------------------


@mcp.tool()
def ghidra_healthcheck() -> dict[str, Any]:
    """Check whether the GhidraMCP server is reachable."""
    return {"reachable": bridge.ghidra().healthcheck()}


@mcp.tool()
def ghidra_decompile_function(name: str) -> str:
    """Decompile a function by name and return decompiled C code."""
    return bridge.ghidra().decompile_function(name)


@mcp.tool()
def ghidra_decompile_function_by_address(address: str) -> str:
    """Decompile a function at the given hex address."""
    return bridge.ghidra().decompile_function_by_address(address)


@mcp.tool()
def ghidra_disassemble_function(address: str) -> list:
    """Get assembly code (address: instruction; comment) for a function."""
    return bridge.ghidra().disassemble_function(address)


@mcp.tool()
def ghidra_list_functions() -> list:
    """List all function names in the program."""
    return bridge.ghidra().list_functions()


@mcp.tool()
def ghidra_list_methods(offset: int = 0, limit: int = 100) -> list:
    """List function names with pagination."""
    return bridge.ghidra().list_methods(offset=offset, limit=limit)


@mcp.tool()
def ghidra_list_classes(offset: int = 0, limit: int = 100) -> list:
    """List namespace/class names with pagination."""
    return bridge.ghidra().list_classes(offset=offset, limit=limit)


@mcp.tool()
def ghidra_list_segments(offset: int = 0, limit: int = 100) -> list:
    """List memory segments with pagination."""
    return bridge.ghidra().list_segments(offset=offset, limit=limit)


@mcp.tool()
def ghidra_list_imports(offset: int = 0, limit: int = 100) -> list:
    """List imported symbols with pagination."""
    return bridge.ghidra().list_imports(offset=offset, limit=limit)


@mcp.tool()
def ghidra_list_exports(offset: int = 0, limit: int = 100) -> list:
    """List exported functions/symbols with pagination."""
    return bridge.ghidra().list_exports(offset=offset, limit=limit)


@mcp.tool()
def ghidra_list_strings(offset: int = 0, limit: int = 2000, filter: str | None = None) -> list:
    """List all defined strings with their addresses."""
    return bridge.ghidra().list_strings(offset=offset, limit=limit, filter=filter)


@mcp.tool()
def ghidra_search_functions(query: str, offset: int = 0, limit: int = 100) -> list:
    """Search functions whose name contains the given substring."""
    return bridge.ghidra().search_functions_by_name(query=query, offset=offset, limit=limit)


@mcp.tool()
def ghidra_rename_function(old_name: str, new_name: str) -> str:
    """Rename a function by its current name."""
    return bridge.ghidra().rename_function(old_name, new_name)


@mcp.tool()
def ghidra_rename_data(address: str, new_name: str) -> str:
    """Rename a data label at the specified address."""
    return bridge.ghidra().rename_data(address, new_name)


@mcp.tool()
def ghidra_get_xrefs_to(address: str, offset: int = 0, limit: int = 100) -> list:
    """Get all references to the specified address (xref to)."""
    return bridge.ghidra().get_xrefs_to(address, offset=offset, limit=limit)


@mcp.tool()
def ghidra_get_xrefs_from(address: str, offset: int = 0, limit: int = 100) -> list:
    """Get all references from the specified address (xref from)."""
    return bridge.ghidra().get_xrefs_from(address, offset=offset, limit=limit)


@mcp.tool()
def ghidra_get_function_xrefs(name: str, offset: int = 0, limit: int = 100) -> list:
    """Get all references to the specified function by name."""
    return bridge.ghidra().get_function_xrefs(name, offset=offset, limit=limit)


@mcp.tool()
def ghidra_set_decompiler_comment(address: str, comment: str) -> str:
    """Set a comment for a given address in the function pseudocode."""
    return bridge.ghidra().set_decompiler_comment(address, comment)


@mcp.tool()
def ghidra_set_disassembly_comment(address: str, comment: str) -> str:
    """Set a comment for a given address in the disassembly."""
    return bridge.ghidra().set_disassembly_comment(address, comment)


@mcp.tool()
def ghidra_import_apk(apk_path: str) -> dict:
    """Import an APK into Ghidra for analysis. Ghidra must be running with GhidraMCPPlugin."""
    return bridge.ghidra().analyze_apk(apk_path)


# -- Pipeline tools ----------------------------------------------------


@mcp.tool()
def analyze_apk(
    apk_path: str,
    run_mobsf: bool = True,
    run_jadx: bool = True,
    run_ghidra: bool = False,
) -> dict[str, Any]:
    """Run a full APK analysis pipeline (sequential) with selected tools.

    By default runs MobSF and JADX. Enable Ghidra with run_ghidra=True.
    """
    return bridge.analyze_apk(
        apk_path,
        run_mobsf=run_mobsf,
        run_jadx=run_jadx,
        run_ghidra=run_ghidra,
    )


@mcp.tool()
def analyze_apk_parallel(apk_path: str) -> dict[str, Any]:
    """Run MobSF + JADX analysis in parallel for faster triage."""
    return bridge.analyze_apk_parallel(apk_path)


@mcp.tool()
def generate_report(apk_path: str, output_dir: str | None = None) -> dict[str, Any]:
    """Run full analysis pipeline and generate JSON, Markdown, and HTML reports."""
    return bridge.generate_report(apk_path, output_dir=output_dir)


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------


def _handle_termination(signum: int, _frame: Any) -> None:
    logger.info("Received signal %d, shutting down.", signum)
    sys.exit(0)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="FLUX - Mobile Security Analysis Forge MCP Server",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MPC_MCP_HOST", "0.0.0.0"),
        help="Host to bind the MCP server to (default: 0.0.0.0, env: MPC_MCP_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=os.getenv("MPC_MCP_PORT", "8000"),
        help="Port to bind the MCP server to (default: 8000, env: MPC_MCP_PORT)",
    )
    parser.add_argument(
        "--transport",
        default=os.getenv("MPC_MCP_TRANSPORT", "streamable-http"),
        choices={"stdio", "streamable-http", "sse"},
        help="MCP transport protocol (default: streamable-http, env: MPC_MCP_TRANSPORT)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    signal.signal(signal.SIGINT, _handle_termination)
    signal.signal(signal.SIGTERM, _handle_termination)

    logger.info(
        "Starting MPC MCP server on %s:%s (transport=%s)",
        args.host,
        args.port,
        args.transport,
    )

    try:
        mcp.run(transport=args.transport, host=args.host, port=args.port)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down.")
        sys.exit(0)


if __name__ == "__main__":
    main()
