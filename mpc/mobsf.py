"""MobSF REST API client for MPC.

Provides a typed Python client for the Mobile Security Framework (MobSF)
REST API, handling upload, scan, report retrieval, and SAST analysis.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ── Custom Exceptions ──────────────────────────────────────────────────────────


class MobSFError(Exception):
    """Base exception for MobSF client errors."""


class MobSFConnectionError(MobSFError):
    """Raised when the client cannot connect to the MobSF server."""


class MobSFAuthError(MobSFError):
    """Raised when the API key is invalid or missing."""


class MobSFNotFoundError(MobSFError):
    """Raised when a requested resource is not found (HTTP 404)."""


class MobSFAPIError(MobSFError):
    """Raised when the MobSF API returns a non-success status code."""


# ── Response data containers ───────────────────────────────────────────────────


@dataclass
class UploadResult:
    """Result of a MobSF file upload."""
    hash: str
    file_name: str
    scan_type: str


@dataclass
class ScanResult:
    """Result of a MobSF scan initiation."""
    scan_type: str
    hash: str
    file_name: str
    # The full API response payload is preserved for downstream access.
    raw: Dict[str, Any]


# ── Client ─────────────────────────────────────────────────────────────────────


class MobSFClient:
    """A typed client for the MobSF REST API.

    Usage::

        client = MobSFClient()
        upload = client.upload("app.apk")
        result = client.scan(upload.hash)
        report = client.report_json(upload.hash)
    """

    DEFAULT_TIMEOUT: int = 120
    DEFAULT_MAX_RETRIES: int = 3

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        *,
        timeout: int | None = None,
    ) -> None:
        """Initialize the MobSF client.

        Parameters
        ----------
        base_url:
            MobSF server URL.  Falls back to the ``MOBSF_URL`` environment
            variable, then to ``http://localhost:9000``.
        api_key:
            MobSF REST API key.  Falls back to the ``MOBSF_API_KEY``
            environment variable.
        timeout:
            Request-level timeout in seconds.  Falls back to the
            ``MPC_TOOL_TIMEOUT`` environment variable, then 120.
        """
        self.base_url = (
            base_url
            or os.getenv("MOBSF_URL")
            or "http://localhost:9000"
        ).rstrip("/")
        self.api_key = api_key or os.getenv("MOBSF_API_KEY")

        env_timeout = os.getenv("MPC_TOOL_TIMEOUT")
        self._timeout = timeout or (
            int(env_timeout) if env_timeout is not None else None
        ) or self.DEFAULT_TIMEOUT

        # Prepare a reusable session with retry support.
        self._session = requests.Session()
        self._session.headers.update(self._default_headers)

        retries = Retry(
            total=self.DEFAULT_MAX_RETRIES,
            backoff_factor=0.5,
            allowed_methods={"GET", "POST"},
            status_forcelist={429, 500, 502, 503, 504},
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    # ── Properties ─────────────────────────────────────────────────────────

    @property
    def _default_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if self.api_key:
            headers["Authorization"] = self.api_key
        return headers

    # ── Internal helpers ───────────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Make an HTTP request and handle error responses."""
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self._timeout)

        try:
            resp = self._session.request(method, url, **kwargs)
        except requests.ConnectionError as exc:
            raise MobSFConnectionError(
                f"Could not connect to MobSF at {self.base_url}: {exc}"
            ) from exc
        except requests.Timeout as exc:
            raise MobSFConnectionError(
                f"Request to MobSF timed out after {self._timeout}s: {exc}"
            ) from exc
        except requests.RequestException as exc:
            raise MobSFConnectionError(
                f"HTTP request failed: {exc}"
            ) from exc

        self._raise_for_status(resp)
        return resp

    @staticmethod
    def _raise_for_status(resp: requests.Response) -> None:
        """Check the response status and raise an appropriate exception."""
        status = resp.status_code
        if 200 <= status < 300:
            return

        if status == 401 or status == 403:
            raise MobSFAuthError(
                f"MobSF authentication failed ({status}): "
                f"{resp.text.strip() or 'Invalid or missing API key'}"
            )
        if status == 404:
            raise MobSFNotFoundError(
                f"Resource not found at {resp.url} ({status})"
            )
        raise MobSFAPIError(
            f"MobSF API returned HTTP {status} for {resp.url}: "
            f"{resp.text.strip() or 'Unknown error'}"
        )

    # ── Public API methods ─────────────────────────────────────────────────

    def upload(self, file_path: str | os.PathLike[str]) -> Dict[str, Any]:
        """Upload an APK/IPA file to MobSF for analysis.

        Parameters
        ----------
        file_path:
            Path to the APK or IPA file on disk.

        Returns
        -------
        dict
            JSON payload from MobSF containing ``hash``, ``file_name``,
            and ``scan_type``.

        Raises
        ------
        MobSFConnectionError
            If the server is unreachable.
        MobSFAuthError
            If the API key is invalid.
        MobSFAPIError
            If the upload itself fails.
        """
        path = Path(file_path).resolve(strict=True)

        with path.open("rb") as fh:
            files = {"file": (path.name, fh, "application/octet-stream")}
            resp = self._request("POST", "/api/v1/upload", files=files)

        data: Dict[str, Any] = resp.json()
        return data

    def scan(
        self,
        file_hash: str,
        scan_type: str = "apk",
    ) -> Dict[str, Any]:
        """Start a security scan on an uploaded file.

        Parameters
        ----------
        file_hash:
            The hash returned by :meth:`upload`.
        scan_type:
            File type (``"apk"``, ``"ipa"``, etc.).  Defaults to ``"apk"``.

        Returns
        -------
        dict
            Scan result payload from MobSF.

        Raises
        ------
        MobSFConnectionError
            If the server is unreachable.
        MobSFAuthError
            If the API key is invalid.
        MobSFNotFoundError
            If the hash is unknown.
        MobSFAPIError
            If the scan request fails.
        """
        data: Dict[str, Any] = {"hash": file_hash, "scan_type": scan_type}
        resp = self._request("POST", "/api/v1/scan", data=data)
        return resp.json()

    def report_json(self, file_hash: str) -> Dict[str, Any]:
        """Retrieve the full JSON analysis report for a scanned file.

        Parameters
        ----------
        file_hash:
            The hash returned by :meth:`upload`.

        Returns
        -------
        dict
            Complete MobSF JSON report.

        Raises
        ------
        MobSFConnectionError
            If the server is unreachable.
        MobSFAuthError
            If the API key is invalid.
        MobSFNotFoundError
            If the hash is unknown.
        MobSFAPIError
            If the request fails.
        """
        resp = self._request(
            "POST",
            "/api/v1/report_json",
            data={"hash": file_hash},
        )
        return resp.json()

    def report_pdf(
        self,
        file_hash: str,
        output_path: str | os.PathLike[str] | None = None,
    ) -> str:
        """Download a PDF report for a scanned file.

        Parameters
        ----------
        file_hash:
            The hash returned by :meth:`upload`.
        output_path:
            Where to save the PDF.  If ``None``, the PDF is saved as
            ``<hash>.pdf`` in the current working directory.

        Returns
        -------
        str
            The absolute path to the downloaded PDF.

        Raises
        ------
        MobSFConnectionError
            If the server is unreachable.
        MobSFAuthError
            If the API key is invalid.
        MobSFNotFoundError
            If the hash is unknown.
        MobSFAPIError
            If the download itself fails.
        """
        if output_path is None:
            output_path = Path.cwd() / f"{file_hash}.pdf"

        resp = self._request(
            "POST",
            "/api/v1/download_pdf",
            data={"hash": file_hash},
            stream=True,
        )

        dest = Path(output_path)
        dest.write_bytes(resp.content)
        return str(dest.resolve())

    def get_sast_summary(self, file_hash: str) -> Dict[str, Any]:
        """Get a summary of the SAST (static analysis) findings.

        Fetches the JSON report and returns the static/code analysis
        sections so callers can inspect findings without downloading
        the entire report.

        Parameters
        ----------
        file_hash:
            The hash returned by :meth:`upload`.

        Returns
        -------
        dict
            A dictionary with at least ``"static_analysis"`` and
            ``"code_analysis"`` keys (populated when available).

        Raises
        ------
        MobSFConnectionError
            If the server is unreachable.
        MobSFAuthError
            If the API key is invalid.
        MobSFNotFoundError
            If the hash is unknown.
        MobSFAPIError
            If the request fails.
        """
        report = self.report_json(file_hash)
        return {
            "static_analysis": report.get("static_analysis", {}),
            "code_analysis": report.get("code_analysis", {}),
            "malware_analysis": report.get("malware_analysis", {}),
        }
