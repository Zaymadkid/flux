"""Tests for the FLUX Ghidra client (powered by GhidraMCP)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mpc.ghidra import DEFAULT_GHIDRA_MCP_URL, GhidraClient, GhidraMCPError


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def client() -> GhidraClient:
    return GhidraClient(mcp_url="http://127.0.0.1:8080/")


# ------------------------------------------------------------------
# Initialization
# ------------------------------------------------------------------


class TestInit:
    def test_defaults_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GHIDRA_MCP_URL", "http://127.0.0.1:8080/")
        c = GhidraClient(mcp_url=None)
        assert c._mcp_url == "http://127.0.0.1:8080/"

    def test_explicit_url_override(self) -> None:
        c = GhidraClient(mcp_url="http://localhost:9090/")
        assert c._mcp_url == "http://localhost:9090/"

    def test_url_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GHIDRA_MCP_URL", "http://10.0.0.1:8080/")
        c = GhidraClient()
        assert c._mcp_url == "http://10.0.0.1:8080/"


# ------------------------------------------------------------------
# HTTP helpers
# ------------------------------------------------------------------


class TestHttpHelpers:
    def test_get_success(self, client: GhidraClient) -> None:
        with patch.object(client._session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.ok = True
            mock_resp.text = "func1\nfunc2\nfunc3"
            mock_get.return_value = mock_resp

            result = client._get("methods", {"offset": 0, "limit": 10})
            assert result == ["func1", "func2", "func3"]
            mock_get.assert_called_once_with(
                "http://127.0.0.1:8080/methods",
                params={"offset": 0, "limit": 10},
                timeout=10,
            )

    def test_get_error(self, client: GhidraClient) -> None:
        with patch.object(client._session, "get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.ok = False
            mock_resp.status_code = 404
            mock_resp.text = "Not Found"
            mock_get.return_value = mock_resp

            result = client._get("methods")
            assert result[0].startswith("Error 404")

    def test_get_connection_error(self, client: GhidraClient) -> None:
        with patch.object(client._session, "get") as mock_get:
            from requests.exceptions import ConnectionError
            mock_get.side_effect = ConnectionError("Connection refused")

            result = client._get("methods")
            assert result[0].startswith("GhidraMCP connection failed")

    def test_post_success(self, client: GhidraClient) -> None:
        with patch.object(client._session, "post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.ok = True
            mock_resp.text = "decompiled code"
            mock_post.return_value = mock_resp

            result = client._post("decompile", "main")
            assert result == "decompiled code"

    def test_post_error(self, client: GhidraClient) -> None:
        with patch.object(client._session, "post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.ok = False
            mock_resp.status_code = 500
            mock_resp.text = "Internal Server Error"
            mock_post.return_value = mock_resp

            result = client._post("decompile", "main")
            assert result.startswith("Error 500")


# ------------------------------------------------------------------
# Healthcheck
# ------------------------------------------------------------------


class TestHealthcheck:
    def test_healthy(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["OK"]):
            assert client.healthcheck() is True

    def test_unhealthy(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["Error 404: Not Found"]):
            assert client.healthcheck() is False

    def test_connection_error(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["GhidraMCP connection failed"]):
            assert client.healthcheck() is False


# ------------------------------------------------------------------
# Function / Symbol listing
# ------------------------------------------------------------------


class TestListing:
    def test_list_functions(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["main", "helper", "init"]):
            result = client.list_functions()
            assert result == ["main", "helper", "init"]

    def test_list_methods_paginated(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["method_a", "method_b"]) as mock_get:
            result = client.list_methods(offset=10, limit=50)
            mock_get.assert_called_with("methods", {"offset": 10, "limit": 50})
            assert result == ["method_a", "method_b"]

    def test_list_classes(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["ClassA", "ClassB"]):
            result = client.list_classes()
            assert result == ["ClassA", "ClassB"]

    def test_list_segments(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=[".text", ".data", ".bss"]):
            result = client.list_segments()
            assert result == [".text", ".data", ".bss"]

    def test_list_imports(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["printf", "malloc"]):
            result = client.list_imports()
            assert result == ["printf", "malloc"]

    def test_list_exports(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["DllMain"]):
            result = client.list_exports()
            assert result == ["DllMain"]

    def test_list_strings(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["Hello", "World"]):
            result = client.list_strings(limit=10)
            assert result == ["Hello", "World"]

    def test_list_strings_with_filter(self, client: GhidraClient) -> None:
        with patch.object(client, "_get") as mock_get:
            mock_get.return_value = ["password_setting"]
            result = client.list_strings(filter="password")
            mock_get.assert_called_with("strings", {"offset": 0, "limit": 2000, "filter": "password"})
            assert result == ["password_setting"]

    def test_search_functions_by_name(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["main"]):
            result = client.search_functions_by_name("main")
            assert result == ["main"]

    def test_search_functions_empty_query(self, client: GhidraClient) -> None:
        result = client.search_functions_by_name("")
        assert "Error" in result[0]


# ------------------------------------------------------------------
# Decompilation
# ------------------------------------------------------------------


class TestDecompilation:
    def test_decompile_function(self, client: GhidraClient) -> None:
        with patch.object(client, "_post", return_value="int main() { return 0; }"):
            result = client.decompile_function("main")
            assert "int main" in result

    def test_decompile_function_by_address(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["int main() { return 0; }"]):
            result = client.decompile_function_by_address("0x140001000")
            assert "int main" in result

    def test_disassemble_function(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["0x1000: push rbp"]):
            result = client.disassemble_function("0x140001000")
            assert "0x1000" in result[0]


# ------------------------------------------------------------------
# Renaming
# ------------------------------------------------------------------


class TestRenaming:
    def test_rename_function(self, client: GhidraClient) -> None:
        with patch.object(client, "_post", return_value="OK"):
            result = client.rename_function("func_1", "calculateHash")
            assert result == "OK"

    def test_rename_data(self, client: GhidraClient) -> None:
        with patch.object(client, "_post", return_value="OK"):
            result = client.rename_data("0x140005000", "secret_key")
            assert result == "OK"

    def test_rename_variable(self, client: GhidraClient) -> None:
        with patch.object(client, "_post", return_value="OK"):
            result = client.rename_variable("main", "v1", "userCount")
            assert result == "OK"


# ------------------------------------------------------------------
# Cross-references
# ------------------------------------------------------------------


class TestXrefs:
    def test_get_xrefs_to(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["0x1000: call main"]):
            result = client.get_xrefs_to("0x140001000")
            assert "0x1000" in result[0]

    def test_get_xrefs_from(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["0x140001000: call printf"]):
            result = client.get_xrefs_from("0x140001000")
            assert "call printf" in result[0]

    def test_get_function_xrefs(self, client: GhidraClient) -> None:
        with patch.object(client, "_get", return_value=["0x1000: call main"]):
            result = client.get_function_xrefs("main")
            assert result == ["0x1000: call main"]


# ------------------------------------------------------------------
# Comments / Prototypes
# ------------------------------------------------------------------


class TestModification:
    def test_set_decompiler_comment(self, client: GhidraClient) -> None:
        with patch.object(client, "_post", return_value="OK"):
            result = client.set_decompiler_comment("0x140001000", "TODO: review")
            assert result == "OK"

    def test_set_function_prototype(self, client: GhidraClient) -> None:
        with patch.object(client, "_post", return_value="OK"):
            result = client.set_function_prototype("0x140001000", "int main(int argc, char** argv)")
            assert result == "OK"


# ------------------------------------------------------------------
# analyze_apk (GhidraMCP mode)
# ------------------------------------------------------------------


class TestAnalyzeApk:
    def test_apk_not_found(self, client: GhidraClient) -> None:
        result = client.analyze_apk("/nonexistent/test.apk")
        assert result["success"] is False
        assert "not found" in result["error"]

    def test_healthcheck_fails(self, client: GhidraClient) -> None:
        with patch.object(client, "healthcheck", return_value=False):
            result = client.analyze_apk(__file__)
            assert result["success"] is False
            assert "not reachable" in result["error"]

    def test_import_success(self, client: GhidraClient) -> None:
        with patch.object(client, "healthcheck", return_value=True):
            with patch.object(client, "_post", return_value="Imported OK"):
                result = client.analyze_apk(__file__)
                assert result["success"] is True
                assert result["output"] == "Imported OK"

    def test_import_failure(self, client: GhidraClient) -> None:
        with patch.object(client, "healthcheck", return_value=True):
            with patch.object(client, "_post", return_value="Error 500: fail"):
                result = client.analyze_apk(__file__)
                assert result["success"] is False


# ------------------------------------------------------------------
# run_script
# ------------------------------------------------------------------


class TestRunScript:
    def test_not_supported(self, client: GhidraClient) -> None:
        result = client.run_script("proj", "script.py")
        assert result["success"] is False
        assert "not available" in result["error"]
