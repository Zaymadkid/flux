"""Tests for the JADX decompiler wrapper."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, Generator
from unittest.mock import MagicMock, mock_open, patch

import pytest

from mpc.jadx import JadxClient


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def jadx_client() -> JadxClient:
    """Return a JadxClient with a known resolved binary path."""
    client = JadxClient(jadx_path="jadx")
    # Force a resolved binary so the client is "ready" even if JADX is not
    # installed on the CI machine.
    client._resolved_bin = "/usr/local/bin/jadx"
    return client


@pytest.fixture
def fake_apk(tmp_path: Path) -> str:
    """Create a minimal fake APK file and return its path."""
    apk = tmp_path / "app.apk"
    apk.write_text("fake apk content")
    return str(apk)


@pytest.fixture
def decompiled_output(tmp_path: Path) -> str:
    """Create a fake decompiled source tree and return the root path."""
    root = tmp_path / "app_jadx"
    sources = root / "sources" / "com" / "example" / "app"
    sources.mkdir(parents=True, exist_ok=True)

    (sources / "MainActivity.java").write_text(
        "package com.example.app;\n"
        "public class MainActivity {\n"
        "    private String apiKey = \"sk-1234\";\n"
        "    public void onCreate() {}\n"
        "}\n"
    )
    (sources / "Utils.java").write_text(
        "package com.example.app;\n"
        "public class Utils {\n"
        "    public static String secret = \"SECRET\";\n"
        "}\n"
    )
    # A non-Java resource that should be ignored by get_decompiled_files.
    res_dir = root / "resources"
    res_dir.mkdir(parents=True, exist_ok=True)
    (res_dir / "AndroidManifest.xml").write_text("<manifest />")
    return str(root)


# ------------------------------------------------------------------
# __init__
# ------------------------------------------------------------------


class TestInit:
    def test_default_jadx_bin_falls_back_to_config(self) -> None:
        """JadxClient reads ``jadx_bin`` from config when no path given."""
        client = JadxClient()
        # The config default is "jadx" (or JADX_HOME env var).
        assert client._jadx_bin is not None

    def test_explicit_path_override(self) -> None:
        """Explicit *jadx_path* overrides the config value."""
        client = JadxClient(jadx_path="/opt/jadx/bin/jadx")
        assert client._jadx_bin == "/opt/jadx/bin/jadx"

    def test_resolve_jadx_found_on_path(self) -> None:
        """_resolve_jadx returns a path when the binary is on PATH."""
        with patch("shutil.which", return_value="/usr/bin/jadx"):
            client = JadxClient(jadx_path="jadx")
            assert client._resolved_bin == "/usr/bin/jadx"

    def test_resolve_jadx_missing(self) -> None:
        """_resolve_jadx returns None when the binary cannot be found."""
        with patch("shutil.which", return_value=None):
            with patch("os.path.isfile", return_value=False):
                client = JadxClient(jadx_path="nonexistent-jadx")
                assert client._resolved_bin is None


# ------------------------------------------------------------------
# decompile
# ------------------------------------------------------------------


class TestDecompile:
    def test_apk_not_found(self, jadx_client: JadxClient) -> None:
        """Returns an error when the APK file does not exist."""
        result = jadx_client.decompile("/no/such/file.apk")
        assert result["success"] is False
        assert result["error"] is not None
        assert "not found" in result["error"].lower()

    def test_jadx_not_found(self, fake_apk: str) -> None:
        """Returns an error when the JADX binary is not available."""
        client = JadxClient(jadx_path="jadx")
        client._resolved_bin = None
        result = client.decompile(fake_apk)
        assert result["success"] is False
        assert "JADX binary not found" in result["error"]

    @patch("subprocess.run")
    def test_successful_decompile(
        self,
        mock_run: MagicMock,
        jadx_client: JadxClient,
        fake_apk: str,
        tmp_path: Path,
    ) -> None:
        """Returns success when JADX exits with code 0."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Decompilation finished",
            stderr="",
        )

        output_dir = str(tmp_path / "out")
        result = jadx_client.decompile(fake_apk, output_dir=output_dir)

        assert result["success"] is True
        assert result["exit_code"] == 0
        assert result["output_path"] == output_dir
        assert result["error"] is None

        # Verify the constructed command.
        cmd = mock_run.call_args[1]["args"] if "args" in mock_run.call_args else mock_run.call_args[0][0]
        # mock_run can be called with positional or keyword args depending on
        # Python version; we handle both.
        args = (
            mock_run.call_args[0][0]
            if mock_run.call_args[0]
            else mock_run.call_args[1]["args"]
        )
        assert args[0] == "/usr/local/bin/jadx"
        assert "-d" in args
        assert str(tmp_path / "out") in args
        assert fake_apk in args

    @patch("subprocess.run")
    def test_default_output_dir(
        self,
        mock_run: MagicMock,
        jadx_client: JadxClient,
        fake_apk: str,
    ) -> None:
        """Output directory defaults to ``<apk_stem>_jadx`` beside the APK."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        result = jadx_client.decompile(fake_apk)
        assert result["success"] is True
        # The APK is under tmp_path, so the default should be <tmp_path>/app_jadx
        assert result["output_path"] is not None
        assert result["output_path"].endswith("app_jadx")

    @patch("subprocess.run")
    def test_custom_args_forwarded(
        self,
        mock_run: MagicMock,
        jadx_client: JadxClient,
        fake_apk: str,
    ) -> None:
        """Extra CLI args are forwarded to the JADX command."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        jadx_client.decompile(fake_apk, args=["--no-res", "--no-cache"])
        args = (
            mock_run.call_args[0][0]
            if mock_run.call_args[0]
            else mock_run.call_args[1]["args"]
        )
        assert "--no-res" in args
        assert "--no-cache" in args

    @patch("subprocess.run")
    def test_jadx_failure(
        self,
        mock_run: MagicMock,
        jadx_client: JadxClient,
        fake_apk: str,
    ) -> None:
        """Returns an error when JADX exits with a non-zero code."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="ERROR: bad dex",
        )

        result = jadx_client.decompile(fake_apk)
        assert result["success"] is False
        assert result["error"] is not None
        assert "exited with code 1" in result["error"]

    @patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="jadx", timeout=120))
    def test_timeout(
        self,
        mock_run: MagicMock,
        jadx_client: JadxClient,
        fake_apk: str,
    ) -> None:
        """Returns an error when the process times out."""
        result = jadx_client.decompile(fake_apk)
        assert result["success"] is False
        assert "timed out" in result["error"].lower()

    @patch("subprocess.run", side_effect=FileNotFoundError)
    def test_binary_not_executable(
        self,
        mock_run: MagicMock,
        jadx_client: JadxClient,
        fake_apk: str,
    ) -> None:
        """Returns an error when the resolved binary can not be launched."""
        # Temporarily make _resolved_bin point to something that will fail.
        jadx_client._resolved_bin = "/usr/local/bin/jadx"
        result = jadx_client.decompile(fake_apk)
        assert result["success"] is False
        assert "could not be executed" in result["error"]


# ------------------------------------------------------------------
# decompile_with_report
# ------------------------------------------------------------------


class TestDecompileWithReport:
    @patch.object(JadxClient, "decompile")
    @patch.object(JadxClient, "get_decompiled_files")
    def test_success(
        self,
        mock_get_files: MagicMock,
        mock_decompile: MagicMock,
        jadx_client: JadxClient,
    ) -> None:
        """Returns a rich report on success."""
        mock_decompile.return_value = {
            "success": True,
            "output_path": "/out",
            "stdout": "",
            "stderr": "WARNING: bad code at MainActivity.java:42\n"
                       "INFO: decompiled OK\n",
            "exit_code": 0,
            "error": None,
        }
        mock_get_files.return_value = ["/out/MainActivity.java", "/out/Utils.java"]

        report = jadx_client.decompile_with_report("test.apk")
        assert report["success"] is True
        assert report["total_files"] == 2
        assert len(report["bad_code_entries"]) == 1
        assert "bad code" in report["bad_code_entries"][0].lower()

    @patch.object(JadxClient, "decompile")
    def test_failure(self, mock_decompile: MagicMock, jadx_client: JadxClient) -> None:
        """Returns a failure report when decompilation fails."""
        mock_decompile.return_value = {
            "success": False,
            "output_path": None,
            "stdout": "",
            "stderr": "crash",
            "exit_code": 1,
            "error": "JADX exited with code 1.\nstderr:\ncrash",
        }

        report = jadx_client.decompile_with_report("test.apk")
        assert report["success"] is False
        assert report["total_files"] == 0
        assert report["error"] is not None


# ------------------------------------------------------------------
# get_decompiled_files
# ------------------------------------------------------------------


class TestGetDecompiledFiles:
    def test_returns_java_files(
        self, jadx_client: JadxClient, decompiled_output: str
    ) -> None:
        """Only ``.java`` files are returned."""
        files = jadx_client.get_decompiled_files(decompiled_output)
        assert len(files) == 2
        assert all(f.endswith(".java") for f in files)

    def test_non_existent_dir(self, jadx_client: JadxClient) -> None:
        """An empty list is returned for missing directories."""
        files = jadx_client.get_decompiled_files("/no/such/dir")
        assert files == []

    def test_sorted_order(
        self, jadx_client: JadxClient, decompiled_output: str
    ) -> None:
        """Filenames are returned in sorted lexicographic order."""
        files = jadx_client.get_decompiled_files(decompiled_output)
        basenames = [os.path.basename(f) for f in files]
        assert basenames == sorted(basenames)


# ------------------------------------------------------------------
# search_code
# ------------------------------------------------------------------


class TestSearchCode:
    def test_finds_matches(
        self, jadx_client: JadxClient, decompiled_output: str
    ) -> None:
        """Regex patterns are found across decompiled files."""
        matches = jadx_client.search_code(decompiled_output, r"sk-\w+")
        assert len(matches) >= 1
        assert any("apiKey" in m["content"] for m in matches)

    def test_pattern_with_no_matches(
        self, jadx_client: JadxClient, decompiled_output: str
    ) -> None:
        """Empty result for a pattern that does not appear."""
        matches = jadx_client.search_code(decompiled_output, r"thisNeverExists")
        assert matches == []

    def test_malformed_output_dir(
        self, jadx_client: JadxClient
    ) -> None:
        """Empty result for a non-existent output directory."""
        matches = jadx_client.search_code("/no/such/dir", r".*")
        assert matches == []

    def test_file_read_error_skipped(
        self, jadx_client: JadxClient, decompiled_output: str, tmp_path: Path
    ) -> None:
        """Files that raise OSError during read are skipped without crashing."""
        # Place a file that will cause a read error.
        bad = Path(decompiled_output) / "sources" / "com" / "example" / "app" / "Bad.java"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("ok", encoding="utf-8")

        with patch("builtins.open", side_effect=OSError("denied")):
            matches = jadx_client.search_code(decompiled_output, r".*")
        # The client handles the error gracefully and returns an empty list or
        # just skips -- we verify it does not crash.
        assert isinstance(matches, list)

    def test_invalid_regex(self, jadx_client: JadxClient, decompiled_output: str) -> None:
        """An invalid regex pattern raises ``re.error``."""
        with pytest.raises(re.error):  # noqa: A375
            jadx_client.search_code(decompiled_output, r"[invalid")


# ------------------------------------------------------------------
# extract_sources
# ------------------------------------------------------------------


class TestExtractSources:
    @patch.object(JadxClient, "decompile")
    def test_success(
        self,
        mock_decompile: MagicMock,
        jadx_client: JadxClient,
        tmp_path: Path,
    ) -> None:
        """Returns structured results with file list on success."""
        output_dir = str(tmp_path / "out")
        (tmp_path / "out" / "sources").mkdir(parents=True)
        (tmp_path / "out" / "sources" / "A.java").write_text("class A {}")

        mock_decompile.return_value = {
            "success": True,
            "output_path": output_dir,
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "error": None,
        }

        result = jadx_client.extract_sources("test.apk", output_dir=output_dir)
        assert result["success"] is True
        assert result["total_files"] == 1
        assert result["output_path"] == output_dir
        assert result["error"] is None

    @patch.object(JadxClient, "decompile")
    def test_failure(
        self,
        mock_decompile: MagicMock,
        jadx_client: JadxClient,
    ) -> None:
        """Returns failure info when decompilation fails."""
        mock_decompile.return_value = {
            "success": False,
            "output_path": None,
            "exit_code": 1,
            "stdout": "",
            "stderr": "crash",
            "error": "JADX crashed",
        }

        result = jadx_client.extract_sources("test.apk")
        assert result["success"] is False
        assert result["total_files"] == 0
        assert result["files"] == []
        assert result["error"] == "JADX crashed"


# ------------------------------------------------------------------
# Integration-style smoke tests (no actual JADX binary needed)
# ------------------------------------------------------------------


class TestIntegrationSmoke:
    """Quick smoke tests that exercise code paths without a real JADX binary."""

    def test_full_lifecycle_no_jadx(self, tmp_path: Path) -> None:
        """decompile -> failure is consistent when JADX is absent."""
        apk = tmp_path / "test.apk"
        apk.write_text("fake")

        client = JadxClient(jadx_path="definitely-not-jadx")
        assert client._resolved_bin is None

        result = client.decompile(str(apk))
        assert result["success"] is False
        assert "JADX binary not found" in result["error"]

        report = client.decompile_with_report(str(apk))
        assert report["success"] is False

        sources = client.extract_sources(str(apk))
        assert sources["success"] is False

    def test_missing_apk_handled_gracefully(self, jadx_client: JadxClient) -> None:
        """All public methods handle a missing APK without crashing."""
        result = jadx_client.decompile("/no/apk.apk")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

        report = jadx_client.decompile_with_report("/no/apk.apk")
        assert report["success"] is False

        sources = jadx_client.extract_sources("/no/apk.apk")
        assert sources["success"] is False
