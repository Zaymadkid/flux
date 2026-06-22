"""Ghidra headless analysis client for MPC.

Provides a client for Ghidra headless analysis (analyzeHeadless.bat on Windows)
and optional bridging to GhidraMCP for interactive decompilation.
"""

import json
import logging
import os
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from mpc.config import MPCConfig

logger = logging.getLogger(__name__)


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
    """Client for Ghidra headless analysis.

    Wraps ``analyzeHeadless`` (``analyzeHeadless.bat`` on Windows) for
    automated APK analysis and script execution.  Also provides placeholder
    methods that will eventually bridge to **GhidraMCP** for interactive
    decompilation.
    """

    def __init__(
        self,
        ghidra_path: Optional[str] = None,
        project_dir: Optional[str] = None,
        config: Optional[MPCConfig] = None,
    ) -> None:
        """Initialize the Ghidra client.

        Args:
            ghidra_path: Path to the Ghidra installation directory.
                If omitted, falls back to the ``GHIDRA_HOME`` environment
                variable, then to the default ``C:\\ghidra_11.3`` on Windows.
            project_dir: Directory where Ghidra projects will be created.
                Falls back to the ``GHIDRA_PROJECT_DIR`` environment variable,
                then to ``./ghidra_projects``.
            config: An :class:`MPCConfig` instance.  Created automatically
                when not supplied.
        """
        self._cfg = config or MPCConfig.load()

        self.ghidra_path = (
            ghidra_path
            or os.getenv("GHIDRA_HOME")
            or (r"C:\ghidra_11.3" if platform.system() == "Windows" else "/opt/ghidra_11.3")
        )

        self.project_dir = (
            project_dir
            or os.getenv("GHIDRA_PROJECT_DIR")
            or os.path.join(os.getcwd(), "ghidra_projects")
        )

        self._analyze_headless: str = self._resolve_analyze_headless()
        self._timeout: int = self._cfg.ghidra_timeout

        # Optional GhidraMCP URL for interactive features
        self._mcp_url: str = self._cfg.ghidra_mcp_url

        Path(self.project_dir).mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_analyze_headless(self) -> str:
        """Return the full path to the ``analyzeHeadless`` executable."""
        ghidra_support = os.path.join(self.ghidra_path, "support")
        if platform.system() == "Windows":
            candidate = os.path.join(ghidra_support, "analyzeHeadless.bat")
        else:
            candidate = os.path.join(ghidra_support, "analyzeHeadless")
        if not os.path.isfile(candidate):
            logger.warning("analyzeHeadless not found at %s", candidate)
        return candidate

    def _build_analyze_command(
        self,
        project_name: str,
        import_path: Optional[str] = None,
        post_script: Optional[str] = None,
        script_args: Optional[list[str]] = None,
        overwrite: bool = True,
    ) -> list[str]:
        """Build the ``analyzeHeadless`` command line.

        Args:
            project_name:    Ghidra project name (created if it does not
                            exist).
            import_path:     File or directory to import (``-import``).
            post_script:     Path to a Ghidra script to run after import
                            (``-postScript``).
            script_args:     Extra arguments forwarded to the post script
                            (``-scriptPath`` / ``-postScriptArg``).
            overwrite:       Whether to overwrite an existing project
                            (``-overwrite``).

        Returns:
            A list of command-line arguments ready for ``subprocess``.
        """
        cmd = [self._analyze_headless]

        # Project location
        cmd.append(self.project_dir)
        cmd.append(project_name)

        if overwrite:
            cmd.append("-overwrite")

        if import_path:
            cmd.append("-import")
            cmd.append(import_path)

        if post_script:
            # Ensure the parent directory is on the script path so Ghidra
            # can resolve the script name.
            script_dir = os.path.dirname(os.path.abspath(post_script))
            cmd.append("-scriptPath")
            cmd.append(script_dir)
            cmd.append("-postScript")
            cmd.append(os.path.basename(post_script))
            if script_args:
                for arg in script_args:
                    cmd.append(f"-postScriptArg={arg}")

        cmd.append("-noanalysis")
        return cmd

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_apk(
        self,
        apk_path: str,
        script_path: Optional[str] = None,
        output_dir: Optional[str] = None,
    ) -> dict[str, Any]:
        """Run Ghidra headless analysis on an APK.

        If *script_path* is provided, it is executed as a **postScript**
        after import so you can e.g. dump decompiled code or export a
        report.

        Args:
            apk_path:    Path to the APK to analyse.
            script_path: Optional Ghidra script (``.java`` or ``.py``) to
                         run after the import completes.
            output_dir:  Directory where analysis results (stdout/stderr)
                         are written.  Defaults to a ``ghidra-output``
                         subdirectory under the project directory.

        Returns:
            A dictionary with keys:
            - ``success`` (bool)
            - ``project_path`` / ``project_name`` / ``import_path``
            - ``stdout`` / ``stderr`` (truncated to 100 KiB each)
            - ``return_code``
            - ``error`` (str or ``None``)
        """
        apk_path = os.path.abspath(apk_path)
        if not os.path.isfile(apk_path):
            return {"success": False, "error": f"APK not found: {apk_path}"}

        project_name = f"apk_{Path(apk_path).stem}"
        cmd = self._build_analyze_command(
            project_name=project_name,
            import_path=apk_path,
            post_script=script_path,
        )

        logger.info("Running Ghidra analysis: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            msg = f"Ghidra analysis timed out after {self._timeout}s"
            logger.error(msg)
            return {"success": False, "error": msg}
        except FileNotFoundError:
            msg = (
                f"analyzeHeadless not found at {self._analyze_headless}. "
                "Verify GHIDRA_HOME is set correctly."
            )
            logger.error(msg)
            return {"success": False, "error": msg}
        except OSError as exc:
            msg = f"OS error running Ghidra: {exc}"
            logger.error(msg)
            return {"success": False, "error": msg}

        # Truncate very large output
        MAX_LOG = 100 * 1024  # 100 KiB
        stdout = proc.stdout[:MAX_LOG] if proc.stdout else ""
        stderr = proc.stderr[:MAX_LOG] if proc.stderr else ""

        result: dict[str, Any] = {
            "success": proc.returncode == 0,
            "project_path": self.project_dir,
            "project_name": project_name,
            "import_path": apk_path,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": proc.returncode,
            "error": None if proc.returncode == 0 else stderr[:2000] or "Unknown error",
        }

        # Write output files when requested
        if output_dir:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{project_name}_stdout.log").write_text(stdout, encoding="utf-8")
            (out / f"{project_name}_stderr.log").write_text(stderr, encoding="utf-8")

        return result

    def run_script(
        self,
        project_name: str,
        script_path: str,
        script_args: Optional[list[str]] = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """Run a specific Ghidra script against an existing project.

        The script is executed via ``analyzeHeadless`` with the
        ``-preScript`` (or ``-postScript``) flag.  No import is performed.

        Args:
            project_name: Name of the target Ghidra project.
            script_path:  Path to the Ghidra script (``.java`` / ``.py``).
            script_args:  Optional list of string arguments forwarded to
                          the script via ``-preScriptArg``.
            overwrite:    Whether to open the project with ``-overwrite``
                          (default ``False``).

        Returns:
            Same schema as :meth:`analyze_apk`.
        """
        script_path = os.path.abspath(script_path)
        if not os.path.isfile(script_path):
            return {"success": False, "error": f"Script not found: {script_path}"}

        cmd = [
            self._analyze_headless,
            self.project_dir,
            project_name,
        ]
        if overwrite:
            cmd.append("-overwrite")

        script_dir = os.path.dirname(script_path)
        cmd.append("-scriptPath")
        cmd.append(script_dir)
        cmd.append("-postScript")
        cmd.append(os.path.basename(script_path))
        if script_args:
            for arg in script_args:
                cmd.append(f"-postScriptArg={arg}")

        # Prevent Ghidra from processing any binary
        cmd.append("-readOnly")

        logger.info("Running Ghidra script: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
        except subprocess.TimeoutExpired:
            msg = f"Ghidra script timed out after {self._timeout}s"
            logger.error(msg)
            return {"success": False, "error": msg}
        except FileNotFoundError:
            msg = (
                f"analyzeHeadless not found at {self._analyze_headless}. "
                "Verify GHIDRA_HOME is set correctly."
            )
            logger.error(msg)
            return {"success": False, "error": msg}
        except OSError as exc:
            msg = f"OS error running Ghidra: {exc}"
            logger.error(msg)
            return {"success": False, "error": msg}

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        return {
            "success": proc.returncode == 0,
            "project_path": self.project_dir,
            "project_name": project_name,
            "import_path": None,
            "stdout": stdout,
            "stderr": stderr,
            "return_code": proc.returncode,
            "error": None if proc.returncode == 0 else stderr[:2000] or "Unknown error",
        }

    # ------------------------------------------------------------------
    # GhidraMCP bridge placeholders
    # ------------------------------------------------------------------

    def decompile_method(
        self,
        class_name: str,
        method_name: str,
    ) -> str:
        """Decompile a specific method via GhidraMCP.

        .. note::
            This is a **placeholder** that raises :class:`NotImplementedError`.
            It will be wired to **GhidraMCP** once the bridge is available.

        Args:
            class_name:  Fully qualified class name (e.g.
                        ``com.example.app.MainActivity``).
            method_name: Simple method name to decompile.

        Raises:
            NotImplementedError: Always, until GhidraMCP integration is
                                added.
        """
        raise NotImplementedError(
            "GhidraMCP integration is not yet available. "
            "Set GHIDRA_MCP_URL in your environment and ensure the "
            "GhidraMCP server is running."
        )

    def get_call_graph(
        self,
        project_name: str,
        target_method: str,
    ) -> dict[str, Any]:
        """Retrieve the call graph for a method (placeholder).

        Args:
            project_name:  Ghidra project containing the binary.
            target_method: Fully qualified method signature.

        Raises:
            NotImplementedError: Always, until GhidraMCP integration is
                                added.
        """
        raise NotImplementedError(
            "Call graph extraction via GhidraMCP is not yet available."
        )
