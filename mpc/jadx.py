"""JADX decompiler wrapper for Android APK reverse engineering."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from mpc.config import MPCConfig


class JadxClient:
    """Wraps the JADX CLI decompiler for Android APK reverse engineering."""

    def __init__(self, jadx_path: Optional[str] = None) -> None:
        """Initialize with a config-provided or explicitly supplied JADX binary path.

        Args:
            jadx_path: Optional explicit path or command name for JADX.
                       Falls back to MPCConfig.jadx_bin, then 'jadx' on PATH.

        """
        config = MPCConfig.load()
        self._jadx_bin = jadx_path or config.jadx_bin or "jadx"
        self._timeout = config.tool_timeout

        # Resolve the binary so we can detect early if it is missing.
        self._resolved_bin: Optional[str] = self._resolve_jadx()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def decompile(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
        args: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Run JADX decompilation on an APK.

        Args:
            apk_path: Path to the Android APK.
            output_dir: Destination directory for decompiled sources.
                        Defaults to ``<apk_stem>_jadx`` in the same parent
                        directory as the APK.
            args: Additional CLI flags forwarded to JADX (e.g. ``["--no-res"]``).

        Returns:
            A dict with keys:
                - success (bool): Whether decompilation finished cleanly.
                - exit_code (int): Process return code.
                - stdout (str): Standard output from JADX.
                - stderr (str): Standard error from JADX.
                - output_path (str | None): Resolved output directory on success.
                - error (str | None): Human-readable error message on failure.

        """
        apk = Path(apk_path)
        result: Dict[str, Any] = {
            "success": False,
            "exit_code": -1,
            "stdout": "",
            "stderr": "",
            "output_path": None,
            "error": None,
        }

        # --- Validate inputs ---------------------------------------------------
        if not apk.exists():
            result["error"] = f"APK not found: {apk_path}"
            return result

        if self._resolved_bin is None:
            result["error"] = (
                f"JADX binary not found. Tried '{self._jadx_bin}'. "
                f"Set JADX_HOME environment variable or pass jadx_path."
            )
            return result

        # --- Build output directory --------------------------------------------
        if output_dir is None:
            output_dir = str(apk.parent / f"{apk.stem}_jadx")

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        # --- Build command -----------------------------------------------------
        cmd = [self._resolved_bin, "-d", str(out)]
        if args:
            cmd.extend(args)
        cmd.append(str(apk.resolve()))

        # --- Execute -----------------------------------------------------------
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            result["exit_code"] = proc.returncode
            result["stdout"] = proc.stdout
            result["stderr"] = proc.stderr

            if proc.returncode == 0:
                result["success"] = True
                result["output_path"] = str(out)
            else:
                result["error"] = (
                    f"JADX exited with code {proc.returncode}.\n"
                    f"stderr:\n{proc.stderr[:2000]}"
                )

        except subprocess.TimeoutExpired:
            result["error"] = (
                f"JADX timed out after {self._timeout}s on {apk_path}"
            )
        except FileNotFoundError:
            result["error"] = (
                f"JADX binary '{self._resolved_bin}' could not be executed. "
                f"Verify the path or installation."
            )
        except OSError as exc:
            result["error"] = f"OS error running JADX: {exc}"

        return result

    def decompile_with_report(self, apk_path: str) -> Dict[str, Any]:
        """Decompile an APK with ``--show-bad-code`` and return a summary report.

        Args:
            apk_path: Path to the Android APK.

        Returns:
            A dict containing:
                - success (bool)
                - output_path (str)
                - total_files (int): Number of Java source files produced.
                - bad_code_entries (list[str]): Lines referencing bad/error code.
                - error (str | None)

        """
        result = self.decompile(
            apk_path,
            args=["--show-bad-code"],
        )

        report: Dict[str, Any] = {
            "success": result["success"],
            "output_path": result.get("output_path"),
            "total_files": 0,
            "bad_code_entries": [],
            "error": result.get("error"),
        }

        if result["success"] and result["output_path"]:
            files = self.get_decompiled_files(result["output_path"])
            report["total_files"] = len(files)

            # Gather lines from stderr that indicate bad-code markers.
            bad_pattern = re.compile(
                r"(bad code|error|unresolved|synthetic)", re.IGNORECASE
            )
            for line in result.get("stderr", "").splitlines():
                if bad_pattern.search(line):
                    report["bad_code_entries"].append(line.strip())

        return report

    def get_decompiled_files(self, output_dir: str) -> List[str]:
        """Recursively list every ``.java`` file under *output_dir*.

        Args:
            output_dir: The JADX output root.

        Returns:
            Sorted list of absolute file paths.

        """
        root = Path(output_dir)
        if not root.is_dir():
            return []
        return sorted(str(p) for p in root.rglob("*.java") if p.is_file())

    def search_code(
        self, output_dir: str, pattern: str
    ) -> List[Dict[str, Any]]:
        """Search decompiled Java sources for a regex *pattern*.

        Args:
            output_dir: The JADX output root.
            pattern: A regular expression to search for.

        Returns:
            A list of match dicts, each with keys:
                - file (str): Path to the file containing the match.
                - line (int): 1-based line number.
                - content (str): Full text of the matching line.

        """
        compiled = re.compile(pattern)
        matches: List[Dict[str, Any]] = []

        for java_file in self.get_decompiled_files(output_dir):
            try:
                with open(java_file, encoding="utf-8", errors="replace") as fh:
                    for line_no, text in enumerate(fh, start=1):
                        if compiled.search(text):
                            matches.append(
                                {
                                    "file": java_file,
                                    "line": line_no,
                                    "content": text.rstrip("\n\r"),
                                }
                            )
            except (OSError, UnicodeDecodeError) as exc:
                # Skip files that can not be read gracefully.
                continue

        return matches

    def extract_sources(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Convenience method: decompile an APK and return structured findings.

        This combines :meth:`decompile` and :meth:`get_decompiled_files` into
        a single call suitable for quick analysis pipelines.

        Args:
            apk_path: Path to the Android APK.
            output_dir: Optional output directory (see :meth:`decompile`).

        Returns:
            A dict with keys:
                - success (bool)
                - output_path (str | None)
                - total_files (int)
                - files (list[str])
                - error (str | None)

        """
        result = self.decompile(apk_path, output_dir=output_dir)
        output_path = result.get("output_path")

        files: List[str] = []
        if result["success"] and output_path:
            files = self.get_decompiled_files(output_path)

        return {
            "success": result["success"],
            "output_path": output_path,
            "total_files": len(files),
            "files": files,
            "error": result.get("error"),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_jadx(self) -> Optional[str]:
        """Resolve the JADX binary to an absolute path or ``None``.

        Checks ``shutil.which`` first; if the value looks like a path or
        command name, attempts to find it on ``PATH``.  If the value is an
        absolute path that exists, it is used directly.

        Returns:
            An absolute path string to the JADX binary, or ``None``.

        """
        candidate = self._jadx_bin.strip()

        # If it is an existing file, use it directly.
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

        # Otherwise, look it up on PATH.
        resolved = shutil.which(candidate)
        return resolved
