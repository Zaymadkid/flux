"""Tests for the MobSF REST API client."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests
from requests import Response

from mpc.mobsf import (
    MobSFClient,
    MobSFAuthError,
    MobSFConnectionError,
    MobSFNotFoundError,
    MobSFAPIError,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set environment variables to known test values."""
    monkeypatch.setenv("MOBSF_URL", "http://mobsf.test:9000")
    monkeypatch.setenv("MOBSF_API_KEY", "test-api-key-123")
    monkeypatch.setenv("MPC_TOOL_TIMEOUT", "30")


@pytest.fixture
def client(mock_env: None) -> MobSFClient:
    """Return a MobSFClient instance backed by env config."""
    return MobSFClient()


@pytest.fixture
def sample_hash() -> str:
    return "abc123def456"


@pytest.fixture
def sample_upload_response() -> dict:
    return {
        "hash": "abc123def456",
        "file_name": "test.apk",
        "scan_type": "apk",
    }


@pytest.fixture
def sample_scan_response(sample_hash: str) -> dict:
    return {
        "hash": sample_hash,
        "scan_type": "apk",
        "file_name": "test.apk",
    }


@pytest.fixture
def sample_report_json(sample_hash: str) -> dict:
    return {
        "hash": sample_hash,
        "file_name": "test.apk",
        "static_analysis": {
            "permissions": ["INTERNET", "READ_EXTERNAL_STORAGE"],
            "activities": [".MainActivity"],
        },
        "code_analysis": {
            "findings": [],
            "rules_count": 10,
        },
        "malware_analysis": {
            "malware_families": [],
        },
    }


# ── Helper to build a mock Response ──────────────────────────────────────────


def _mock_response(
    status_code: int = 200,
    json_data: dict | None = None,
    content: bytes = b"",
    text: str = "",
    url: str = "http://mobsf.test/api/v1/test",
) -> MagicMock:
    resp = MagicMock(spec=Response)
    resp.status_code = status_code
    resp.url = url
    resp.content = content
    resp.text = text or json.dumps(json_data or {})
    resp.json.return_value = json_data or {}
    resp.__enter__.return_value = resp
    resp.__exit__.return_value = None
    return resp


# ── Configuration & Initialisation ────────────────────────────────────────────


class TestInit:
    def test_defaults_from_env(self, mock_env: None) -> None:
        """Config values from environment are picked up."""
        cli = MobSFClient()
        assert cli.base_url == "http://mobsf.test:9000"
        assert cli.api_key == "test-api-key-123"

    def test_explicit_values_override_env(self, mock_env: None) -> None:
        """Constructor arguments override environment variables."""
        cli = MobSFClient(
            base_url="http://custom:8080",
            api_key="custom-key",
        )
        assert cli.base_url == "http://custom:8080"
        assert cli.api_key == "custom-key"

    def test_no_api_key_allowed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Omitting API key should still work (MobSF may allow it)."""
        monkeypatch.delenv("MOBSF_API_KEY", raising=False)
        cli = MobSFClient(base_url="http://nokey:8000")
        assert cli.api_key is None
        assert "Authorization" not in cli._session.headers

    def test_base_url_trailing_slash_stripped(self, mock_env: None) -> None:
        """Trailing slashes on the base URL are removed."""
        cli = MobSFClient(base_url="http://example.com/")
        assert cli.base_url == "http://example.com"


# ── Upload ─────────────────────────────────────────────────────────────────────


class TestUpload:
    def test_upload_success(
        self,
        client: MobSFClient,
        sample_upload_response: dict,
        tmp_path: Path,
    ) -> None:
        """A valid file upload returns the expected JSON payload."""
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"fake apk content")

        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(json_data=sample_upload_response),
        ) as mock_req:
            result = client.upload(str(apk))

        assert result == sample_upload_response
        # Verify the file was sent as a multipart upload.
        call_kwargs = mock_req.call_args[1]
        assert "files" in call_kwargs
        file_tuple = call_kwargs["files"]["file"]
        assert file_tuple[0] == "test.apk"  # original file name

    def test_upload_file_not_found(self, client: MobSFClient) -> None:
        """A missing file path raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            client.upload("/nonexistent/path.apk")

    def test_upload_connection_error(
        self, client: MobSFClient, tmp_path: Path
    ) -> None:
        """A connection failure raises MobSFConnectionError."""
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"fake")

        with patch.object(
            client._session, "request"
        ) as mock_req:
            mock_req.side_effect = requests.ConnectionError("refused")
            with pytest.raises(MobSFConnectionError, match="refused"):
                client.upload(str(apk))

    def test_upload_timeout(
        self, client: MobSFClient, tmp_path: Path
    ) -> None:
        """A timeout raises MobSFConnectionError."""
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"fake")

        with patch.object(client._session, "request") as mock_req:
            mock_req.side_effect = requests.Timeout("timed out")
            with pytest.raises(MobSFConnectionError, match="timed out"):
                client.upload(str(apk))

    def test_upload_auth_error(
        self, client: MobSFClient, tmp_path: Path
    ) -> None:
        """A 401 response raises MobSFAuthError."""
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"fake")

        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(
                status_code=401,
                text="Invalid API Key",
            ),
        ):
            with pytest.raises(MobSFAuthError, match="Invalid API Key"):
                client.upload(str(apk))

    def test_upload_api_error(
        self, client: MobSFClient, tmp_path: Path
    ) -> None:
        """A 500 response raises MobSFAPIError."""
        apk = tmp_path / "test.apk"
        apk.write_bytes(b"fake")

        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(
                status_code=500,
                text="Internal Server Error",
            ),
        ):
            with pytest.raises(MobSFAPIError, match="500"):
                client.upload(str(apk))


# ── Scan ───────────────────────────────────────────────────────────────────────


class TestScan:
    def test_scan_success(
        self,
        client: MobSFClient,
        sample_hash: str,
        sample_scan_response: dict,
    ) -> None:
        """A successful scan returns the expected payload."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(json_data=sample_scan_response),
        ) as mock_req:
            result = client.scan(sample_hash)

        assert result == sample_scan_response
        call_kwargs = mock_req.call_args[1]
        assert call_kwargs["data"] == {"hash": sample_hash, "scan_type": "apk"}

    def test_scan_custom_type(
        self,
        client: MobSFClient,
        sample_hash: str,
    ) -> None:
        """scan_type is passed through correctly."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(json_data={"status": "ok"}),
        ) as mock_req:
            client.scan(sample_hash, scan_type="ipa")

        sent_data = mock_req.call_args[1]["data"]
        assert sent_data["scan_type"] == "ipa"

    def test_scan_not_found(self, client: MobSFClient) -> None:
        """A 404 for an unknown hash raises MobSFNotFoundError."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(
                status_code=404,
                text="Hash not found",
            ),
        ):
            with pytest.raises(MobSFNotFoundError, match="404"):
                client.scan("bad_hash")


# ── Report (JSON) ──────────────────────────────────────────────────────────────


class TestReportJson:
    def test_report_json_success(
        self,
        client: MobSFClient,
        sample_hash: str,
        sample_report_json: dict,
    ) -> None:
        """report_json returns the full report."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(json_data=sample_report_json),
        ):
            result = client.report_json(sample_hash)

        assert result == sample_report_json
        assert "static_analysis" in result

    def test_report_json_not_found(self, client: MobSFClient) -> None:
        """A 404 for an unknown hash raises MobSFNotFoundError."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(
                status_code=404,
                text="Report not found",
            ),
        ):
            with pytest.raises(MobSFNotFoundError):
                client.report_json("bad_hash")


# ── Report (PDF) ───────────────────────────────────────────────────────────────


class TestReportPdf:
    def test_report_pdf_success(
        self,
        client: MobSFClient,
        sample_hash: str,
        tmp_path: Path,
    ) -> None:
        """PDF report is downloaded and saved to the specified path."""
        pdf_content = b"%PDF-1.4 fake pdf content"
        output = tmp_path / "report.pdf"

        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(content=pdf_content),
        ):
            saved = client.report_pdf(sample_hash, output_path=str(output))

        assert output.read_bytes() == pdf_content
        assert Path(saved).resolve() == output.resolve()

    def test_report_pdf_default_output_path(
        self,
        client: MobSFClient,
        sample_hash: str,
    ) -> None:
        """When output_path is None, PDF is saved as <hash>.pdf in CWD."""
        pdf_content = b"%PDF-1.4 fake"

        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(content=pdf_content),
        ):
            saved = client.report_pdf(sample_hash)

        expected = Path.cwd() / f"{sample_hash}.pdf"
        assert Path(saved).resolve() == expected.resolve()
        assert Path(saved).read_bytes() == pdf_content
        # Clean up
        Path(saved).unlink(missing_ok=True)


# ── SAST Summary ───────────────────────────────────────────────────────────────


class TestGetSastSummary:
    def test_summary_contains_expected_keys(
        self,
        client: MobSFClient,
        sample_hash: str,
        sample_report_json: dict,
    ) -> None:
        """SAST summary extracts the relevant sections."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(json_data=sample_report_json),
        ):
            summary = client.get_sast_summary(sample_hash)

        assert "static_analysis" in summary
        assert "code_analysis" in summary
        assert "malware_analysis" in summary

    def test_summary_empty_when_report_missing_keys(
        self,
        client: MobSFClient,
        sample_hash: str,
    ) -> None:
        """Sections missing from the report default to empty dicts."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(json_data={"hash": sample_hash}),
        ):
            summary = client.get_sast_summary(sample_hash)

        assert summary["static_analysis"] == {}
        assert summary["code_analysis"] == {}
        assert summary["malware_analysis"] == {}


# ── Error handling ─────────────────────────────────────────────────────────────


class TestErrorHandling:
    def test_connection_error(self, client: MobSFClient) -> None:
        """requests.ConnectionError is translated to MobSFConnectionError."""
        with patch.object(
            client._session,
            "request",
            side_effect=requests.ConnectionError("Connection refused"),
        ):
            with pytest.raises(MobSFConnectionError, match="refused"):
                client.report_json("some_hash")

    def test_timeout_error(self, client: MobSFClient) -> None:
        """requests.Timeout is translated to MobSFConnectionError."""
        with patch.object(
            client._session,
            "request",
            side_effect=requests.Timeout("timed out"),
        ):
            with pytest.raises(MobSFConnectionError, match="timed out"):
                client.report_json("some_hash")

    def test_403_auth_error(self, client: MobSFClient) -> None:
        """HTTP 403 raises MobSFAuthError."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(status_code=403, text="Forbidden"),
        ):
            with pytest.raises(MobSFAuthError, match="403"):
                client.report_json("some_hash")

    def test_404_not_found(self, client: MobSFClient) -> None:
        """HTTP 404 raises MobSFNotFoundError."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(status_code=404, text="Not Found"),
        ):
            with pytest.raises(MobSFNotFoundError, match="404"):
                client.report_json("some_hash")

    def test_unexpected_status(self, client: MobSFClient) -> None:
        """Other non-2xx status codes raise MobSFAPIError."""
        with patch.object(
            client._session,
            "request",
            return_value=_mock_response(
                status_code=418,
                text="I'm a teapot",
            ),
        ):
            with pytest.raises(MobSFAPIError, match="418"):
                client.report_json("some_hash")


# ── Config integration ─────────────────────────────────────────────────────────


class TestConfigIntegration:
    def test_default_timeout_from_config(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """tool_timeout from MPCConfig is used when no explicit timeout."""
        monkeypatch.setenv("MOBSF_URL", "http://localhost:9000")
        monkeypatch.setenv("MPC_TOOL_TIMEOUT", "45")
        cli = MobSFClient()
        assert cli._timeout == 45

    def test_explicit_timeout_override(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Explicit timeout argument overrides the config value."""
        monkeypatch.setenv("MOBSF_URL", "http://localhost:9000")
        cli = MobSFClient(timeout=10)
        assert cli._timeout == 10

    def test_session_headers_include_api_key(self, client: MobSFClient) -> None:
        """The session carries the Authorization header with the API key."""
        assert client._session.headers.get("Authorization") == "test-api-key-123"

    def test_config_load_uses_default_url(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """When no env vars are set, MobSFClient falls back to defaults."""
        monkeypatch.delenv("MOBSF_URL", raising=False)
        monkeypatch.delenv("MOBSF_API_KEY", raising=False)
        cli = MobSFClient()
        # MPCConfig.mobsf_url defaults to "http://localhost:9000"
        assert cli.base_url == "http://localhost:9000"
        assert cli.api_key is None
