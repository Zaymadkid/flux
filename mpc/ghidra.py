"""Ghidra client for FLUX powered by GhidraMCP.

Uses LaurieWired/GhidraMCP's HTTP bridge to connect to a running Ghidra
instance with the GhidraMCPPlugin loaded.  Provides decompilation, renaming,
cross-referencing, and binary analysis tools.

Requirements:
    - Ghidra running with GhidraMCPPlugin installed (File -> Install Extensions)
    - GhidraMCP HTTP server enabled (default http://127.0.0.1:8080)
    - ``requests`` library
"""

from __future__ import annotations

import logging
import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests

from mpc.config import MPCConfig

logger = logging.getLogger(__name__)

DEFAULT_GHIDRA_MCP_URL = "http://127.0.0.1:8080/"


class GhidraMCPError(Exception):
    """Raised when a GhidraMCP request fails."""


@dataclass
class GhidraResult:
    """Structured result from a Ghidra analysis run."""

    success: bool
    project_path: Optional[str] = None
    project_name: Optional[str] = None
    import_path: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    return_code: int = -1
    error: Optional[str] = None


class GhidraClient:
    """Client for Ghidra reverse engineering via GhidraMCP.

    Connects to a Ghidra instance running the GhidraMCPPlugin HTTP server.
    All 25+ Ghidra tools from GhidraMCP are available as methods.
    """

    def __init__(
        self,
        mcp_url: Optional[str] = None,
        config: Optional[MPCConfig] = None,
    ) -> None:
        self._cfg = config or MPCConfig.load()
        self._mcp_url = (
            mcp_url
            or os.getenv("GHIDRA_MCP_URL")
            or self._cfg.ghidra_mcp_url
            or DEFAULT_GHIDRA_MCP_URL
        )
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, endpoint: str, params: dict = None) -> list:
        if params is None:
            params = {}
        url = urljoin(self._mcp_url, endpoint)
        try:
            resp = self._session.get(url, params=params, timeout=10)
            resp.encoding = "utf-8"
            if resp.ok:
                return resp.text.splitlines()
            return [f"Error {resp.status_code}: {resp.text.strip()}"]
        except requests.ConnectionError as exc:
            return [f"GhidraMCP connection failed: {exc}"]
        except Exception as exc:
            return [f"Request failed: {exc}"]

    def _post(self, endpoint: str, data: dict | str) -> str:
        url = urljoin(self._mcp_url, endpoint)
        try:
            if isinstance(data, dict):
                resp = self._session.post(url, data=data, timeout=10)
            else:
                resp = self._session.post(url, data=data.encode("utf-8"), timeout=10)
            resp.encoding = "utf-8"
            if resp.ok:
                return resp.text.strip()
            return f"Error {resp.status_code}: {resp.text.strip()}"
        except requests.ConnectionError as exc:
            return f"GhidraMCP connection failed: {exc}"
        except Exception as exc:
            return f"Request failed: {exc}"

    def _get_text(self, endpoint: str, params: dict = None) -> str:
        return "\n".join(self._get(endpoint, params))

    def healthcheck(self) -> bool:
        """Check if GhidraMCP server is reachable."""
        result = self._get("")
        if not result:
            return False
        first = result[0]
        return not (first.startswith("Error") or first.startswith("GhidraMCP connection") or first.startswith("Request failed"))

    # ------------------------------------------------------------------
    # Function / Symbol listing
    # ------------------------------------------------------------------

    def list_functions(self) -> list:
        """List all function names in the program."""
        return self._get("list_functions")

    def list_methods(self, offset: int = 0, limit: int = 100) -> list:
        """List function names with pagination."""
        return self._get("methods", {"offset": offset, "limit": limit})

    def list_classes(self, offset: int = 0, limit: int = 100) -> list:
        """List namespace/class names with pagination."""
        return self._get("classes", {"offset": offset, "limit": limit})

    def list_segments(self, offset: int = 0, limit: int = 100) -> list:
        """List memory segments with pagination."""
        return self._get("segments", {"offset": offset, "limit": limit})

    def list_imports(self, offset: int = 0, limit: int = 100) -> list:
        """List imported symbols with pagination."""
        return self._get("imports", {"offset": offset, "limit": limit})

    def list_exports(self, offset: int = 0, limit: int = 100) -> list:
        """List exported functions/symbols with pagination."""
        return self._get("exports", {"offset": offset, "limit": limit})

    def list_namespaces(self, offset: int = 0, limit: int = 100) -> list:
        """List non-global namespaces with pagination."""
        return self._get("namespaces", {"offset": offset, "limit": limit})

    def list_data_items(self, offset: int = 0, limit: int = 100) -> list:
        """List defined data labels and values with pagination."""
        return self._get("data", {"offset": offset, "limit": limit})

    def list_strings(self, offset: int = 0, limit: int = 2000, filter: str = None) -> list:
        """List defined strings with addresses."""
        params = {"offset": offset, "limit": limit}
        if filter:
            params["filter"] = filter
        return self._get("strings", params)

    def search_functions_by_name(self, query: str, offset: int = 0, limit: int = 100) -> list:
        """Search functions whose name contains the given substring."""
        if not query:
            return ["Error: query string is required"]
        return self._get("searchFunctions", {"query": query, "offset": offset, "limit": limit})

    # ------------------------------------------------------------------
    # Decompilation
    # ------------------------------------------------------------------

    def decompile_function(self, name: str) -> str:
        """Decompile a function by name, return decompiled C code."""
        return self._post("decompile", name)

    def decompile_function_by_address(self, address: str) -> str:
        """Decompile a function at the given hex address."""
        return self._get_text("decompile_function", {"address": address})

    def decompile_range(self, start_addr: str, end_addr: str) -> str:
        """Decompile an address range."""
        return self._post("decompileRange", {"startAddr": start_addr, "endAddr": end_addr})

    def disassemble_function(self, address: str) -> list:
        """Get assembly (address: instruction; comment) for a function."""
        return self._get("disassemble_function", {"address": address})

    def get_function_body(self, name: str) -> str:
        """Get function addresses and bytes."""
        return self._get_text("get_function_body", {"name": name})

    def get_instructions(self, address: str, count: int = 10) -> list:
        """Get assembly instructions at an address."""
        return self._get("getInstructions", {"address": address, "count": count})

    # ------------------------------------------------------------------
    # Renaming
    # ------------------------------------------------------------------

    def rename_function(self, old_name: str, new_name: str) -> str:
        """Rename a function by its current name."""
        return self._post("renameFunction", {"oldName": old_name, "newName": new_name})

    def rename_function_by_address(self, function_address: str, new_name: str) -> str:
        """Rename a function by its address."""
        return self._post("rename_function_by_address",
                          {"function_address": function_address, "new_name": new_name})

    def rename_data(self, address: str, new_name: str) -> str:
        """Rename a data label at the specified address."""
        return self._post("renameData", {"address": address, "newName": new_name})

    def rename_variable(self, function_name: str, old_name: str, new_name: str) -> str:
        """Rename a local variable within a function."""
        return self._post("renameVariable",
                          {"functionName": function_name, "oldName": old_name, "newName": new_name})

    # ------------------------------------------------------------------
    # Comments / Prototypes
    # ------------------------------------------------------------------

    def set_decompiler_comment(self, address: str, comment: str) -> str:
        """Set a comment for an address in function pseudocode."""
        return self._post("set_decompiler_comment", {"address": address, "comment": comment})

    def set_disassembly_comment(self, address: str, comment: str) -> str:
        """Set a comment for an address in disassembly."""
        return self._post("set_disassembly_comment", {"address": address, "comment": comment})

    def set_function_prototype(self, function_address: str, prototype: str) -> str:
        """Set a function's prototype."""
        return self._post("set_function_prototype",
                          {"function_address": function_address, "prototype": prototype})

    def set_local_variable_type(self, function_address: str, variable_name: str, new_type: str) -> str:
        """Set a local variable's type."""
        return self._post("set_local_variable_type",
                          {"function_address": function_address,
                           "variable_name": variable_name,
                           "new_type": new_type})

    # ------------------------------------------------------------------
    # Cross-references
    # ------------------------------------------------------------------

    def get_xrefs_to(self, address: str, offset: int = 0, limit: int = 100) -> list:
        """Get all references to an address (xref to)."""
        return self._get("xrefs_to", {"address": address, "offset": offset, "limit": limit})

    def get_xrefs_from(self, address: str, offset: int = 0, limit: int = 100) -> list:
        """Get all references from an address (xref from)."""
        return self._get("xrefs_from", {"address": address, "offset": offset, "limit": limit})

    def get_function_xrefs(self, name: str, offset: int = 0, limit: int = 100) -> list:
        """Get all references to a function by name."""
        return self._get("function_xrefs", {"name": name, "offset": offset, "limit": limit})

    # ------------------------------------------------------------------
    # Current state
    # ------------------------------------------------------------------

    def get_current_address(self) -> str:
        """Get the address currently selected by the user."""
        return self._get_text("get_current_address")

    def get_current_function(self) -> str:
        """Get the function currently selected by the user."""
        return self._get_text("get_current_function")

    def get_function_by_address(self, address: str) -> str:
        """Get function info at an address."""
        return self._get_text("get_function_by_address", {"address": address})

    def get_data_types(self) -> list:
        """List available data types."""
        return self._get("get_data_types")

    # ------------------------------------------------------------------
    # Compatibility: analyze_apk (delegate to GhidraMCP)
    # ------------------------------------------------------------------

    def analyze_apk(
        self,
        apk_path: str,
        script_path: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> dict[str, Any]:
        """Analyse an APK by importing it into Ghidra via GhidraMCP.

        This requires a running Ghidra instance with the GhidraMCPPlugin.
        If GhidraMCP is not reachable, returns an error directing the user
        to start Ghidra with the plugin loaded.

        Args:
            apk_path:    Path to the APK to analyse.
            script_path: Ignored in GhidraMCP mode (placeholder for
                        compatibility).
            output_dir:  Ignored (placeholder for compatibility).

        Returns:
            dict with ``success`` bool and analysed file info.
        """
        apk_path = os.path.abspath(apk_path)
        if not os.path.isfile(apk_path):
            return {"success": False, "error": f"APK not found: {apk_path}"}

        if not self.healthcheck():
            return {
                "success": False,
                "error": (
                    "GhidraMCP not reachable. "
                    "Start Ghidra, install GhidraMCPPlugin (File -> Install Extensions), "
                    "and ensure the HTTP server is running."
                ),
            }

        result = self._post("importFile", apk_path)
        success = not result.startswith("Error")
        return {
            "success": success,
            "import_path": apk_path,
            "output": result,
            "error": None if success else result,
            "ghidra_mcp_url": self._mcp_url,
        }

    def run_script(
        self,
        project_name: str,
        script_path: str,
        script_args: Optional[list[str]] = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Run a Ghidra script (not supported via GhidraMCP bridge)."""
        return {
            "success": False,
            "error": "run_script is not available via GhidraMCP. "
                     "Use GhidraMCP tools (decompile, rename, list, xrefs) instead.",
        }
