# MPC (Mobile Pentesting Companion) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend Medusa (Ch0pin/medusa v3.9.6+) with MobSF static scanning, JADX decompilation, and Ghidra deep binary analysis — unified under a single `mpc` CLI and MCP server.

**Architecture:** Medusa remains the core (90+ Frida modules, MANGO for static prep). New `mpc/` Python package adds MobSF REST client, JADX wrapper, GhidraMCP bridge, and pipeline orchestrator. Existing `medusa_android_mcp.py` extended with new MCP tools. New `modules/mobsf/` Medusa module for interactive MobSF scans.

**Tech Stack:** Python 3.10+, Medusa v3.9.6, MobSF REST API, JADX CLI/MCP, GhidraMCP (LaurieWired), FastMCP (MCP SDK)

---

### Task 1: Project Setup & Directory Structure

**Files:**
- Create: `mpc/__init__.py`
- Create: `mpc/config.py`
- Create: `setup.sh`
- Modify: `requirements.txt`

- [ ] **Step 1: Create the MPC package directory and __init__.py**

```bash
mkdir -p mpc modules/mobsf tests
```

`mpc/__init__.py`:
```python
"""MPC - Mobile Pentesting Companion. Extends Medusa with MobSF, JADX, Ghidra."""
```

- [ ] **Step 2: Write the config module**

`mpc/config.py`:
```python
import os
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class MPCConfig:
    mobsf_url: str = os.getenv("MOBSF_URL", "http://localhost:9000")
    mobsf_api_key: Optional[str] = os.getenv("MOBSF_API_KEY")
    jadx_bin: str = os.getenv("JADX_HOME", "jadx")
    jadx_mcp_url: str = os.getenv("JADX_MCP_URL", "http://localhost:8651")
    ghidra_mcp_url: str = os.getenv("GHIDRA_MCP_URL", "http://localhost:8080")
    mcp_port: int = int(os.getenv("MPC_MCP_PORT", "8000"))
    report_dir: str = os.getenv("MPC_REPORT_DIR", "./reports")
    tool_timeout: int = 120
    ghidra_timeout: int = 300

    @classmethod
    def load(cls) -> "MPCConfig":
        return cls()
```

- [ ] **Step 3: Write setup.sh**

`setup.sh`:
```bash
#!/usr/bin/env bash
set -euo pipefail

echo "[*] MPC - Mobile Pentesting Companion Setup"
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt
pip3 install -r requirements-mcp.txt 2>/dev/null || true

echo "[*] Checking external tools..."
command -v adb >/dev/null && echo "  [OK] adb" || echo "  [WARN] adb not found"
command -v jadx >/dev/null && echo "  [OK] jadx" || echo "  [WARN] jadx not found"

echo ""
echo "[+] Setup complete. Run: python mpc.py --help"
```

- [ ] **Step 4: Update requirements.txt**

Append to `requirements.txt`:
```
requests>=2.31.0
python-dotenv>=1.0.0
```

- [ ] **Step 5: Commit**

```bash
git add mpc/__init__.py mpc/config.py setup.sh requirements.txt
git commit -m "feat: add MPC package structure and config"
```

---

### Task 2: MobSF Module

**Files:**
- Create: `mpc/mobsf.py`
- Create: `tests/test_mobsf.py`

- [ ] **Step 1: Write the test**

`tests/test_mobsf.py`:
```python
import pytest
from mpc.mobsf import MobSFClient

def test_mobsf_client_init():
    client = MobSFClient(url="http://localhost:9000", api_key="test")
    assert client.url == "http://localhost:9000"
    assert client.api_key == "test"

def test_mobsf_client_no_key_raises():
    with pytest.raises(ValueError, match="MOBSF_API_KEY"):
        MobSFClient(url="http://localhost:9000", api_key=None)
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd mpc-re && pip install -e . && pytest tests/test_mobsf.py -v
```
Expected: FAIL with `ModuleNotFoundError` for `mpc.mobsf`

- [ ] **Step 3: Write MobSF client**

`mpc/mobsf.py`:
```python
import os
import json
import logging
import requests
from typing import Optional, Dict, Any

log = logging.getLogger(__name__)

class MobSFClient:
    def __init__(self, url: str = None, api_key: str = None):
        self.url = (url or os.getenv("MOBSF_URL", "http://localhost:9000")).rstrip("/")
        self.api_key = api_key or os.getenv("MOBSF_API_KEY")
        if not self.api_key:
            raise ValueError("MOBSF_API_KEY is required")
        self.session = requests.Session()
        self.session.headers.update({"Authorization": self.api_key})

    def scan(self, apk_path: str) -> Dict[str, Any]:
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")
        with open(apk_path, "rb") as f:
            files = {"file": (os.path.basename(apk_path), f, "application/octet-stream")}
            resp = self.session.post(f"{self.url}/api/v1/upload", files=files, timeout=300)
            resp.raise_for_status()
            upload_data = resp.json()
        scan_hash = upload_data.get("hash") or upload_data.get("scan_id", "")
        resp2 = self.session.post(f"{self.url}/api/v1/scan", json={"hash": scan_hash, "scan_type": "apk"}, timeout=300)
        resp2.raise_for_status()
        return resp2.json()

    def report(self, scan_hash: str) -> Dict[str, Any]:
        resp = self.session.post(f"{self.url}/api/v1/report_json", json={"hash": scan_hash}, timeout=120)
        resp.raise_for_status()
        return resp.json()

    def list_scans(self) -> list:
        resp = self.session.get(f"{self.url}/api/v1/scans", timeout=30)
        resp.raise_for_status()
        return resp.json().get("scans", [])

    def delete_scan(self, scan_hash: str) -> bool:
        resp = self.session.post(f"{self.url}/api/v1/delete_scan", json={"hash": scan_hash}, timeout=30)
        return resp.ok
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_mobsf.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mpc/mobsf.py tests/test_mobsf.py
git commit -m "feat: add MobSF REST client module"
```

---

### Task 3: JADX Module

**Files:**
- Create: `mpc/jadx.py`
- Create: `tests/test_jadx.py`

- [ ] **Step 1: Write the test**

`tests/test_jadx.py`:
```python
import pytest
import tempfile
from pathlib import Path
from mpc.jadx import JadxWrapper, JadxError

def test_jadx_init_defaults():
    j = JadxWrapper()
    assert j.bin == "jadx"

def test_jadx_decompile_no_apk_raises():
    j = JadxWrapper()
    with pytest.raises(JadxError):
        j.decompile("/nonexistent.apk")

def test_jadx_search_empty_dir():
    j = JadxWrapper()
    with tempfile.TemporaryDirectory() as tmp:
        results = j.search("test", tmp)
        assert results == []
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_jadx.py -v
```
Expected: FAIL

- [ ] **Step 3: Write JADX wrapper**

`mpc/jadx.py`:
```python
import os
import re
import subprocess
import logging
from pathlib import Path
from typing import List, Optional

log = logging.getLogger(__name__)

class JadxError(Exception):
    pass

class JadxWrapper:
    def __init__(self, bin_path: str = None):
        self.bin = bin_path or os.getenv("JADX_HOME", "jadx")

    def decompile(self, apk_path: str, output_dir: str = None) -> str:
        if not os.path.isfile(apk_path):
            raise JadxError(f"APK not found: {apk_path}")
        if output_dir is None:
            output_dir = os.path.splitext(os.path.basename(apk_path))[0] + "_jadx"
        cmd = [self.bin, "-d", output_dir, apk_path]
        log.info("Running: %s", " ".join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise JadxError(f"jadx failed: {result.stderr}")
        return output_dir

    def search(self, keyword: str, search_dir: str) -> List[str]:
        matches = []
        for root, _, files in os.walk(search_dir):
            for f in files:
                if f.endswith(".java"):
                    path = Path(root) / f
                    try:
                        content = path.read_text(errors="ignore")
                        if keyword in content:
                            matches.append(str(path))
                    except Exception:
                        continue
        return matches

    def get_class_source(self, class_name: str, search_dir: str) -> Optional[str]:
        rel_path = class_name.replace(".", "/") + ".java"
        for root, _, files in os.walk(search_dir):
            if rel_path in [os.path.relpath(os.path.join(root, f), search_dir).replace("\\", "/") for f in files if f.endswith(".java")]:
                full = os.path.join(root, os.path.basename(rel_path))
                return Path(full).read_text(errors="ignore")
        return None
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_jadx.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mpc/jadx.py tests/test_jadx.py
git commit -m "feat: add JADX decompilation wrapper"
```

---

### Task 4: Ghidra Module

**Files:**
- Create: `mpc/ghidra.py`
- Create: `tests/test_ghidra.py`

- [ ] **Step 1: Write the test**

`tests/test_ghidra.py`:
```python
import pytest
from mpc.ghidra import GhidraClient, GhidraError

def test_ghidra_init():
    g = GhidraClient(url="http://localhost:8080")
    assert g.url == "http://localhost:8080"

def test_ghidra_analyze_no_binary():
    g = GhidraClient(url="http://localhost:8080")
    with pytest.raises(GhidraError):
        g.analyze("/nonexistent.so")
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_ghidra.py -v
```
Expected: FAIL

- [ ] **Step 3: Write Ghidra client (bridges to GhidraMCP)**

`mpc/ghidra.py`:
```python
import os
import json
import logging
import requests
from typing import Dict, Any, List, Optional

log = logging.getLogger(__name__)

class GhidraError(Exception):
    pass

class GhidraClient:
    def __init__(self, url: str = None):
        self.url = (url or os.getenv("GHIDRA_MCP_URL", "http://localhost:8080")).rstrip("/")

    def _call(self, method: str, params: dict = None) -> Dict[str, Any]:
        payload = {"jsonrpc": "2.0", "method": method, "params": params or {}, "id": 1}
        try:
            resp = requests.post(f"{self.url}/mcp", json=payload, timeout=300)
            resp.raise_for_status()
            return resp.json()
        except requests.ConnectionError:
            raise GhidraError("Cannot connect to GhidraMCP bridge. Is Ghidra running?")

    def analyze(self, binary_path: str) -> Dict[str, Any]:
        if not os.path.isfile(binary_path):
            raise GhidraError(f"Binary not found: {binary_path}")
        result = self._call("tools/call_proxy/ghidra.auto_analyze", {"path": binary_path})
        return result

    def decompile(self, function_name: str) -> str:
        result = self._call("tools/call_proxy/ghidra.decompile_function", {"name": function_name})
        return result.get("result", {}).get("decompiled", "")

    def list_functions(self) -> List[str]:
        result = self._call("tools/call_proxy/ghidra.list_functions")
        return result.get("result", {}).get("functions", [])

    def list_exports(self) -> List[str]:
        result = self._call("tools/call_proxy/ghidra.list_exports")
        return result.get("result", {}).get("exports", [])

    def rename_symbol(self, old: str, new: str) -> bool:
        result = self._call("tools/call_proxy/ghidra.rename_symbol", {"old_name": old, "new_name": new})
        return result.get("result", {}).get("success", False)
```

- [ ] **Step 4: Run test to verify it passes**

```bash
pytest tests/test_ghidra.py -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add mpc/ghidra.py tests/test_ghidra.py
git commit -m "feat: add GhidraMCP bridge client"
```

---

### Task 5: Pipeline Orchestrator

**Files:**
- Create: `mpc/pipeline.py`
- Create: `mpc/report.py`
- Create: `tests/test_pipeline.py`
- Create: `tests/test_report.py`

- [ ] **Step 1: Write the report builder test**

`tests/test_report.py`:
```python
import pytest
import tempfile
from pathlib import Path
from mpc.report import Report

def test_report_empty():
    r = Report()
    assert r.to_dict() == {"stages": {}, "summary": {"total": 0, "passed": 0, "skipped": 0, "failed": 0}}

def test_report_add_stage():
    r = Report()
    r.add_stage("mobsf", "passed", {"findings": ["secret_in_code"]})
    assert r.stages["mobsf"]["status"] == "passed"
    assert r.summary()["passed"] == 1

def test_report_to_json(tmp_path):
    r = Report()
    r.add_stage("test", "passed", {})
    path = r.save_json(tmp_path)
    assert Path(path).exists()
```

- [ ] **Step 2: Run test to verify it fails**

```bash
pytest tests/test_report.py -v
```
Expected: FAIL

- [ ] **Step 3: Write Report builder**

`mpc/report.py`:
```python
import json
import os
from datetime import datetime
from typing import Dict, Any, List

class Report:
    def __init__(self, target: str = ""):
        self.target = target
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.stages: Dict[str, dict] = {}

    def add_stage(self, name: str, status: str, data: dict = None):
        self.stages[name] = {"status": status, "data": data or {}}

    def summary(self) -> dict:
        counts = {"total": len(self.stages), "passed": 0, "skipped": 0, "failed": 0}
        for s in self.stages.values():
            st = s["status"]
            if st in counts:
                counts[st] += 1
        return counts

    def to_dict(self) -> dict:
        return {"target": self.target, "timestamp": self.timestamp, "stages": self.stages, "summary": self.summary()}

    def save_json(self, output_dir: str) -> str:
        os.makedirs(output_dir, exist_ok=True)
        fname = f"mpc_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        path = os.path.join(output_dir, fname)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path
```

- [ ] **Step 4: Write pipeline orchestrator test**

`tests/test_pipeline.py`:
```python
import pytest
from mpc.pipeline import Pipeline
from mpc.config import MPCConfig

def test_pipeline_init():
    cfg = MPCConfig()
    p = Pipeline(cfg)
    assert p.config == cfg

def test_pipeline_run_static_no_apk():
    p = Pipeline(MPCConfig())
    report = p.run_static("/nonexistent.apk")
    assert report.stages["mobsf"]["status"] == "failed"
```

- [ ] **Step 5: Write Pipeline orchestrator**

`mpc/pipeline.py`:
```python
import os
import logging
from typing import Optional
from mpc.config import MPCConfig
from mpc.report import Report

log = logging.getLogger(__name__)

class Pipeline:
    def __init__(self, config: Optional[MPCConfig] = None):
        self.config = config or MPCConfig.load()

    def run_all(self, apk_path: str, package: str = None) -> Report:
        report = Report(target=apk_path)
        report = self.run_static(apk_path, report)
        if package:
            report = self._run_dynamic(package, report)
        native_libs = self._find_native_libs(apk_path)
        for lib in native_libs:
            report = self._run_deep(lib, report)
        return report

    def run_static(self, apk_path: str, report: Report = None) -> Report:
        report = report or Report(target=apk_path)
        # MobSF scan
        try:
            from mpc.mobsf import MobSFClient
            client = MobSFClient(url=self.config.mobsf_url, api_key=self.config.mobsf_api_key)
            scan_result = client.scan(apk_path)
            report.add_stage("mobsf", "passed", {"findings": scan_result})
        except Exception as e:
            log.warning("MobSF scan failed: %s", e)
            report.add_stage("mobsf", "skipped" if "MOBSF_API_KEY" in str(e) else "failed", {"error": str(e)})
        # JADX decompile
        try:
            from mpc.jadx import JadxWrapper
            jadx = JadxWrapper(bin_path=self.config.jadx_bin)
            out_dir = jadx.decompile(apk_path)
            report.add_stage("jadx", "passed", {"output_dir": out_dir})
        except Exception as e:
            log.warning("JADX decompile failed: %s", e)
            report.add_stage("jadx", "failed", {"error": str(e)})
        return report

    def _run_dynamic(self, package: str, report: Report) -> Report:
        report.add_stage("frida", "skipped", {"note": "Use 'mpc frida' for interactive Medusa session"})
        return report

    def _run_deep(self, binary_path: str, report: Report) -> Report:
        try:
            from mpc.ghidra import GhidraClient
            ghidra = GhidraClient(url=self.config.ghidra_mcp_url)
            result = ghidra.analyze(binary_path)
            functions = ghidra.list_functions()
            report.add_stage(f"ghidra_{os.path.basename(binary_path)}", "passed",
                             {"analysis": result, "functions": functions})
        except Exception as e:
            log.warning("Ghidra analysis failed for %s: %s", binary_path, e)
            report.add_stage(f"ghidra_{os.path.basename(binary_path)}", "failed", {"error": str(e)})
        return report

    @staticmethod
    def _find_native_libs(apk_path: str) -> list:
        libs = []
        import zipfile
        if os.path.isfile(apk_path):
            try:
                with zipfile.ZipFile(apk_path) as z:
                    for name in z.namelist():
                        if name.startswith("lib/") and name.endswith(".so"):
                            libs.append(name)
            except Exception:
                pass
        return libs
```

- [ ] **Step 6: Run tests**

```bash
pytest tests/test_pipeline.py tests/test_report.py -v
```
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add mpc/pipeline.py mpc/report.py tests/test_pipeline.py tests/test_report.py
git commit -m "feat: add pipeline orchestrator and report builder"
```

---

### Task 6: MobSF Medusa Module

**Files:**
- Create: `modules/mobsf/__init__.py`
- Create: `modules/mobsf/scan.py`

- [ ] **Step 1: Create the module __init__.py**

`modules/mobsf/__init__.py`:
```python
"""MobSF integration module for Medusa"""
```

- [ ] **Step 2: Write the MobSF scan Medusa module**

`modules/mobsf/scan.py`:
```python
"""
Medusa module: MobSF Static Scan
Triggers MobSF scan from within Medusa interactive mode.
Usage (inside Medusa): use mobsf/scan
"""
import os

meta = {
    "name": "MobSF Static Scan",
    "description": "Upload APK to MobSF and retrieve automated static analysis",
    "author": "MPC",
    "version": "1.0",
    "supported_platforms": ["android"],
}

def run(frida_session, package, config, modules):
    mobsf_url = os.getenv("MOBSF_URL", "http://localhost:9000")
    mobsf_key = os.getenv("MOBSF_API_KEY", "")
    apk_path = config.get("apk_path", "")
    if not apk_path or not mobsf_key:
        print("[!] Set MOBSF_API_KEY and apk_path in config")
        return
    from mpc.mobsf import MobSFClient
    client = MobSFClient(url=mobsf_url, api_key=mobsf_key)
    result = client.scan(apk_path)
    print(f"[+] MobSF scan complete: {result.get('package_name', 'unknown')}")
    return result
```

- [ ] **Step 3: Commit**

```bash
git add modules/mobsf/
git commit -m "feat: add MobSF Medusa module for interactive scanning"
```

---

### Task 7: Enhanced MCP Server — Merge New Tools into medusa_android_mcp.py

**Files:**
- Modify: `medusa_android_mcp.py`

This is the most complex task. Medusa's `medusa_android_mcp.py` (96KB) uses FastMCP. We add new tool definitions at the end of the file.

- [ ] **Step 1: Add MPC imports and config to medusa_android_mcp.py**

Near the top of `medusa_android_mcp.py`, after existing imports, add:
```python
# MPC extensions
from mpc.config import MPCConfig
from mpc.mobsf import MobSFClient
from mpc.jadx import JadxWrapper
from mpc.ghidra import GhidraClient
from mpc.pipeline import Pipeline
```

Append the `MPCConfig` instantiation near existing config:
```python
mpc_config = MPCConfig.load()
```

- [ ] **Step 2: Add MobSF MCP tools**

Before the `if __name__ == "__main__"` block, add new MCP tool functions:

```python
@mcp.tool("mobsf_scan")
def mobsf_scan(file_path: str) -> str:
    """Upload an APK file to MobSF for automated static analysis. Returns scan results as JSON."""
    try:
        client = MobSFClient(url=mpc_config.mobsf_url, api_key=mpc_config.mobsf_api_key)
        result = client.scan(file_path)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool("mobsf_get_report")
def mobsf_get_report(scan_hash: str) -> str:
    """Get detailed MobSF report for a previous scan."""
    try:
        client = MobSFClient(url=mpc_config.mobsf_url, api_key=mpc_config.mobsf_api_key)
        report = client.report(scan_hash)
        return json.dumps(report, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})
```

- [ ] **Step 3: Add JADX MCP tools**

```python
@mcp.tool("jadx_decompile")
def jadx_decompile(apk_path: str) -> str:
    """Decompile an APK using JADX. Returns path to decompiled output."""
    try:
        jadx = JadxWrapper(bin_path=mpc_config.jadx_bin)
        out_dir = jadx.decompile(apk_path)
        return json.dumps({"output_dir": out_dir, "status": "ok"})
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool("jadx_search")
def jadx_search(keyword: str, search_dir: str) -> str:
    """Search decompiled JADX source for a keyword. Returns matching file paths."""
    try:
        jadx = JadxWrapper(bin_path=mpc_config.jadx_bin)
        matches = jadx.search(keyword, search_dir)
        return json.dumps({"matches": matches, "count": len(matches)})
    except Exception as e:
        return json.dumps({"error": str(e)})
```

- [ ] **Step 4: Add Ghidra MCP tools**

```python
@mcp.tool("ghidra_analyze")
def ghidra_analyze(binary_path: str) -> str:
    """Import and auto-analyze a native binary in Ghidra."""
    try:
        ghidra = GhidraClient(url=mpc_config.ghidra_mcp_url)
        result = ghidra.analyze(binary_path)
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool("ghidra_decompile")
def ghidra_decompile(function_name: str) -> str:
    """Decompile a function by name using Ghidra."""
    try:
        ghidra = GhidraClient(url=mpc_config.ghidra_mcp_url)
        decompiled = ghidra.decompile(function_name)
        return decompiled
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool("ghidra_list_functions")
def ghidra_list_functions() -> str:
    """List all functions in the currently loaded Ghidra project."""
    try:
        ghidra = GhidraClient(url=mpc_config.ghidra_mcp_url)
        functions = ghidra.list_functions()
        return json.dumps(functions, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})
```

- [ ] **Step 5: Add Pipeline MCP tools**

```python
@mcp.tool("pipeline_scan")
def pipeline_scan(apk_path: str, package: str = "") -> str:
    """Run full MPC pipeline: MobSF scan + JADX decompile + (optional Frida / Ghidra)."""
    try:
        pipeline = Pipeline(config=mpc_config)
        report = pipeline.run_all(apk_path, package=package if package else None)
        return json.dumps(report.to_dict(), indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool("pipeline_static")
def pipeline_static(apk_path: str) -> str:
    """Run static-only pipeline: MobSF + JADX."""
    try:
        pipeline = Pipeline(config=mpc_config)
        report = pipeline.run_static(apk_path)
        return json.dumps(report.to_dict(), indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})
```

- [ ] **Step 6: Commit**

```bash
git add medusa_android_mcp.py
git commit -m "feat: add MPC MCP tools (MobSF, JADX, Ghidra, Pipeline)"
```

---

### Task 8: MPC CLI Entry Point

**Files:**
- Create: `mpc.py` (or modify medusa.py — but cleaner to add a new wrapper)
- Create: `mpc` (Unix shell script entry point)

- [ ] **Step 1: Write the mpc CLI**

`mpc.py`:
```python
#!/usr/bin/env python3
"""MPC - Mobile Pentesting Companion CLI"""
import sys
import os
import json
import argparse
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
log = logging.getLogger("mpc")

def cmd_scan(args):
    from mpc.pipeline import Pipeline
    from mpc.config import MPCConfig
    cfg = MPCConfig.load()
    pipeline = Pipeline(cfg)
    report = pipeline.run_all(args.apk, package=args.package)
    path = report.save_json(cfg.report_dir)
    summary = report.summary()
    print(f"[+] Scan complete. Passed: {summary['passed']}, Skipped: {summary['skipped']}, Failed: {summary['failed']}")
    print(f"[+] Report saved: {path}")

def cmd_static(args):
    from mpc.pipeline import Pipeline
    from mpc.config import MPCConfig
    cfg = MPCConfig.load()
    pipeline = Pipeline(cfg)
    report = pipeline.run_static(args.apk)
    path = report.save_json(cfg.report_dir)
    print(f"[+] Static analysis complete. Report: {path}")

def cmd_mobsf(args):
    from mpc.mobsf import MobSFClient
    from mpc.config import MPCConfig
    cfg = MPCConfig.load()
    client = MobSFClient(url=cfg.mobsf_url, api_key=cfg.mobsf_api_key)
    result = client.scan(args.apk)
    print(json.dumps(result, indent=2, default=str))

def cmd_jadx(args):
    from mpc.jadx import JadxWrapper
    from mpc.config import MPCConfig
    cfg = MPCConfig.load()
    jadx = JadxWrapper(bin_path=cfg.jadx_bin)
    out_dir = jadx.decompile(args.apk)
    print(f"[+] Decompiled to: {out_dir}")

def cmd_ghidra(args):
    from mpc.ghidra import GhidraClient
    from mpc.config import MPCConfig
    cfg = MPCConfig.load()
    ghidra = GhidraClient(url=cfg.ghidra_mcp_url)
    if args.command == "analyze":
        result = ghidra.analyze(args.binary)
        print(json.dumps(result, indent=2, default=str))
    elif args.command == "functions":
        funcs = ghidra.list_functions()
        print(f"\n".join(funcs))
    elif args.command == "exports":
        exports = ghidra.list_exports()
        print(f"\n".join(exports))

def cmd_frida(args):
    """Launch Medusa interactive mode (original)"""
    import subprocess
    subprocess.run([sys.executable, "medusa.py"] + sys.argv[2:])

def cmd_mcp(args):
    """Start the MPC MCP server"""
    from mpc.config import MPCConfig
    cfg = MPCConfig.load()
    log.info("Starting MPC MCP server on port %d...", cfg.mcp_port)
    os.environ.setdefault("MEDUSA_MCP_TRANSPORT", "streamable-http")
    import medusa_android_mcp
    medusa_android_mcp.run_mcp(host="0.0.0.0", port=cfg.mcp_port)

def main():
    parser = argparse.ArgumentParser(description="MPC - Mobile Pentesting Companion")
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="Full pipeline scan (MobSF + JADX + Frida + Ghidra)")
    p_scan.add_argument("apk", help="Path to APK file")
    p_scan.add_argument("--package", "-p", help="Package name for dynamic analysis")

    p_static = sub.add_parser("static", help="Static analysis only (MobSF + JADX)")
    p_static.add_argument("apk", help="Path to APK file")

    p_mobsf = sub.add_parser("mobsf", help="MobSF scan only")
    p_mobsf.add_argument("apk", help="Path to APK file")

    p_jadx = sub.add_parser("jadx", help="JADX decompile only")
    p_jadx.add_argument("apk", help="Path to APK file")

    p_ghidra = sub.add_parser("ghidra", help="Ghidra binary analysis")
    p_ghidra.add_argument("command", choices=["analyze", "functions", "exports"])
    p_ghidra.add_argument("binary", nargs="?", help="Path to binary (for 'analyze')")

    sub.add_parser("frida", help="Launch Medusa interactive Frida mode")
    sub.add_parser("mcp", help="Start MPC MCP server")
    sub.add_parser("report", help="View latest report")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return

    commands = {
        "scan": cmd_scan,
        "static": cmd_static,
        "mobsf": cmd_mobsf,
        "jadx": cmd_jadx,
        "ghidra": cmd_ghidra,
        "frida": cmd_frida,
        "mcp": cmd_mcp,
        "report": lambda a: print("Run 'mpc scan' first, then check reports/ directory"),
    }
    commands[args.command](args)

if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Create shell wrapper**

`mpc` (Unix executable):
```bash
#!/usr/bin/env bash
exec python3 "$(dirname "$0")/mpc.py" "$@"
```

- [ ] **Step 3: Make executable**

```bash
chmod +x mpc.py mpc
```

- [ ] **Step 4: Verify help works**

```bash
python mpc.py --help
```
Expected: Shows help with all subcommands

- [ ] **Step 5: Commit**

```bash
git add mpc.py mpc
git commit -m "feat: add MPC CLI entry point with all commands"
```

---

### Task 9: Integration — Verify All Tools Wire Together

- [ ] **Step 1: Test the full import chain**

```bash
python -c "
from mpc.config import MPCConfig
from mpc.mobsf import MobSFClient
from mpc.jadx import JadxWrapper
from mpc.ghidra import GhidraClient
from mpc.pipeline import Pipeline
from mpc.report import Report
print('[OK] All MPC modules import successfully')
"
```
Expected: Prints success message

- [ ] **Step 2: Commit**

```bash
git add -A
git commit -m "chore: finalize MPC integration"
```
