"""Tests for the MPC GhidraClient."""

import json
import os
import platform
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mpc.ghidra import GhidraClient


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def ghidra_path(tmp_path: Path) -> str:
    """Create a fake Ghidra installation tree with a dummy
    ``analyzeHeadless`` executable so path resolution succeeds."""
    if platform.system() == "Windows":
        exe = tmp_path / "support" / "analyzeHeadless.bat"
    else:
        exe = tmp_path / "support" / "analyzeHeadless"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text("")
    return str(tmp_path)


@pytest.fixture
def client(ghidra_path: str, tmp_path: Path) -> GhidraClient:
    """Return a GhidraClient pointed at the fake installation."""
    return GhidraClient(
        ghidra_path=ghidra_path,
        project_dir=str(tmp_path / "projects"),
    )


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestInit:
    def test_default_project_dir_creation(self, ghidra_path: str, tmp_path: Path) -> None:
        """Project directory is created on init when it doesn't exist."""
        proj_dir = str(tmp_path / "auto_created")
        client = GhidraClient(ghidra_path=ghidra_path, project_dir=proj_dir)
        assert os.path.isdir(proj_dir)

    def test_analyze_headless_path(self, client: GhidraClient) -> None:
        """The internal path to analyzeHeadless is correct for the platform."""
        expected_name = (
            "analyzeHeadless.bat" if platform.system() == "Windows" else "analyzeHeadless"
        )
        assert client._analyze_headless.endswith(expected_name)

    def test_init_without_args_uses_env_fallback(self, tmp_path: Path, monkeypatch) -> None:
        """Omitting both args falls back to GHIDRA_HOME env var."""
        fake_home = str(tmp_path / "ghidra_env")
        monkeypatch.setenv("GHIDRA_HOME", fake_home)
        Path(fake_home, "support").mkdir(parents=True)
        (Path(fake_home, "support", "analyzeHeadless.bat" if platform.system() == "Windows" else "analyzeHeadless")).write_text("")
        client = GhidraClient(project_dir=str(tmp_path / "projs"))
        assert fake_home in client.ghidra_path


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------


class TestCommandConstruction:
    def test_analyze_apk_basic(self, client: GhidraClient) -> None:
        """Verify the analyzeHeadless command for a basic APK import."""
        cmd = client._build_analyze_command(project_name="test_proj", import_path=r"C:\tmp\app.apk")
        assert client._analyze_headless in cmd[0]
        assert client.project_dir in cmd[1]
        assert cmd[2] == "test_proj"
        assert "-overwrite" in cmd
        assert "-import" in cmd
        assert r"C:\tmp\app.apk" in cmd

    def test_analyze_apk_with_script(self, client: GhidraClient, tmp_path: Path) -> None:
        """Script dir is added to -scriptPath when a postScript is supplied."""
        script = tmp_path / "scripts" / "dump.py"
        script.parent.mkdir(parents=True)
        script.write_text("")
        cmd = client._build_analyze_command(
            project_name="proj",
            import_path=str(tmp_path / "app.apk"),
            post_script=str(script),
            script_args=["--verbose"],
        )
        assert "-scriptPath" in cmd
        assert str(script.parent) in cmd
        assert "-postScript" in cmd
        assert "dump.py" in cmd
        assert "-postScriptArg=--verbose" in cmd

    def test_analyze_apk_without_overwrite(self, client: GhidraClient, tmp_path: Path) -> None:
        """Overwrite flag is omitted when overwrite=False."""
        cmd = client._build_analyze_command(
            project_name="proj",
            import_path=str(tmp_path / "app.apk"),
            overwrite=False,
        )
        assert "-overwrite" not in cmd


# ---------------------------------------------------------------------------
# analyze_apk
# ---------------------------------------------------------------------------


class TestAnalyzeApk:
    def test_apk_not_found(self, client: GhidraClient) -> None:
        """Returns an error dict when the APK does not exist."""
        result = client.analyze_apk(r"C:\nonexistent\missing.apk")
        assert result["success"] is False
        assert "not found" in (result.get("error") or "").lower()

    @patch("mpc.ghidra.subprocess.run")
    def test_successful_analysis(self, mock_run, client: GhidraClient, tmp_path: Path) -> None:
        """A successful subprocess call returns success=True and captures output."""
        apk_path = str(tmp_path / "target.apk")
        Path(apk_path).write_text("fake apk content")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "analysis complete"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = client.analyze_apk(apk_path)
        assert result["success"] is True
        assert result["return_code"] == 0
        assert "analysis complete" in result["stdout"]

    @patch("mpc.ghidra.subprocess.run")
    def test_failed_analysis(self, mock_run, client: GhidraClient, tmp_path: Path) -> None:
        """A nonzero return code is surfaced in the result."""
        apk_path = str(tmp_path / "bad.apk")
        Path(apk_path).write_text("fake")

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "Import error: invalid format"
        mock_run.return_value = mock_proc

        result = client.analyze_apk(apk_path)
        assert result["success"] is False
        assert result["return_code"] == 1
        assert "invalid format" in result["stderr"]

    @patch("mpc.ghidra.subprocess.run")
    def test_output_dir_writes_logs(self, mock_run, client: GhidraClient, tmp_path: Path) -> None:
        """When output_dir is given, stdout and stderr are written to disk."""
        apk_path = str(tmp_path / "target.apk")
        Path(apk_path).write_text("fake")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "stdout content"
        mock_proc.stderr = "stderr content"
        mock_run.return_value = mock_proc

        out_dir = str(tmp_path / "results")
        result = client.analyze_apk(apk_path, output_dir=out_dir)
        assert result["success"] is True

        log_files = list(Path(out_dir).iterdir())
        assert len(log_files) > 0

    @patch("mpc.ghidra.subprocess.run")
    def test_timeout_handling(self, mock_run, client: GhidraClient, tmp_path: Path) -> None:
        """subprocess.TimeoutExpired is caught and returned as an error."""
        from subprocess import TimeoutExpired

        apk_path = str(tmp_path / "timeout.apk")
        Path(apk_path).write_text("fake")
        mock_run.side_effect = TimeoutExpired(cmd="analyzeHeadless", timeout=300)

        result = client.analyze_apk(apk_path)
        assert result["success"] is False
        assert "timed out" in (result.get("error") or "").lower()

    @patch("mpc.ghidra.subprocess.run")
    def test_file_not_found_error(self, mock_run, client: GhidraClient, tmp_path: Path) -> None:
        """FileNotFoundError (missing analyzeHeadless) is handled gracefully."""
        apk_path = str(tmp_path / "missing_exe.apk")
        Path(apk_path).write_text("fake")
        mock_run.side_effect = FileNotFoundError()

        result = client.analyze_apk(apk_path)
        assert result["success"] is False
        assert "not found" in (result.get("error") or "").lower()


# ---------------------------------------------------------------------------
# run_script
# ---------------------------------------------------------------------------


class TestRunScript:
    @patch("mpc.ghidra.subprocess.run")
    def test_script_not_found(self, mock_run, client: GhidraClient) -> None:
        """Missing script returns an error before any subprocess call."""
        result = client.run_script("proj", r"C:\missing\script.py")
        assert result["success"] is False
        assert "not found" in (result.get("error") or "").lower()
        mock_run.assert_not_called()

    @patch("mpc.ghidra.subprocess.run")
    def test_successful_script_run(self, mock_run, client: GhidraClient, tmp_path: Path) -> None:
        """A successful script execution returns the expected result."""
        script = tmp_path / "my_script.py"
        script.write_text("")

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "script done"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        result = client.run_script("existing_proj", str(script))
        assert result["success"] is True
        assert result["project_name"] == "existing_proj"


# ---------------------------------------------------------------------------
# GhidraMCP placeholders
# ---------------------------------------------------------------------------


class TestGhidraMcpPlaceholders:
    def test_decompile_method_raises(self, client: GhidraClient) -> None:
        """decompile_method raises NotImplementedError until GhidraMCP is wired."""
        with pytest.raises(NotImplementedError, match="GhidraMCP"):
            client.decompile_method("com.example.Foo", "bar")

    def test_get_call_graph_raises(self, client: GhidraClient) -> None:
        """get_call_graph raises NotImplementedError until GhidraMCP is wired."""
        with pytest.raises(NotImplementedError, match="GhidraMCP"):
            client.get_call_graph("proj", "com.example.Foo::bar")
