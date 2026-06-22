
<p align="center">
  <img src="assets/images/flux_logo.svg" alt="FLUX Logo" width="280">
</p>

<h1 align="center">FLUX</h1>
<p align="center"><strong>Mobile Security Analysis Forge</strong></p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=flat-square" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/license-GPL--3.0-orange?style=flat-square" alt="License">
  <img src="https://img.shields.io/badge/Frida-16.x-red?style=flat-square" alt="Frida">
  <img src="https://img.shields.io/badge/MCP-enabled-brightgreen?style=flat-square" alt="MCP">
</p>

<p align="center">
  FLUX combines four powerful mobile security tools into a unified analysis platform —<br>
  static analysis, dynamic instrumentation, decompilation, and deep binary inspection —<br>
  all accessible through a single CLI, interactive shell, or MCP server.
</p>

---

## Overview

FLUX is an **evolving** mobile security testing platform. It's built on top of:

| Tool | Role |
|------|------|
| **Medusa** | Frida-based dynamic instrumentation (90+ hook modules) |
| **MobSF** | Static analysis, malware scanning, SAST |
| **JADX** | DEX/APK decompilation to readable Java |
| **Ghidra** | Deep binary analysis and decompilation |

FLUX pipelines these tools together — upload an APK to MobSF for scanning, decompile it with JADX for vulnerability search, instrument it with Medusa hooks, and generate a unified report — all in one command.

---

## Quick Start

```bash
# Requirements
pip install -r requirements-mcp.txt

# Analyze an APK
python mpc.py analyze target.apk --mobsf --jadx

# Start the interactive shell
python mpc.py

# Start the MCP server
python mpc_mcp_server.py --transport stdio
```

### What You Need

Each tool is optional — FLUX works with whatever you have available:

- **MobSF** → `pip install mobsf` or use a remote instance (set `MOBSF_URL`)
- **JADX** → `choco install jadx` or download from [jadx.io](https://jadx.io)
- **Ghidra** → Download from [ghidra-sre.org](https://ghidra-sre.org) (set `GHIDRA_HOME`)
- **Medusa/ADB** → Included. Connect an Android device or emulator.

---

## Tools

FLUX exposes these tools through its CLI and MCP server:

### Pipeline Tools
- `analyze_apk` — Full sequential analysis (MobSF + JADX + Ghidra)
- `analyze_apk_parallel` — MobSF + JADX in parallel
- `generate_report` — Run pipeline + generate JSON/MD/HTML reports
- `search_vulnerabilities` — Regex search decompiled code for 10+ vulnerability patterns

### MobSF Tools
- `mobsf_healthcheck` — Verify MobSF server connectivity
- `mobsf_upload` — Upload APK/IPA for analysis
- `mobsf_scan` — Start static/malware scan
- `mobsf_report` — Fetch full JSON report
- `mobsf_sast_summary` — Extract SAST findings summary

### JADX Tools
- `jadx_decompile` — Decompile APK to readable Java source
- `jadx_search` — Search decompiled code with regex
- `jadx_list_files` — List all decompiled Java files

### Ghidra Tools (powered by GhidraMCP)
- `ghidra_healthcheck` — Check GhidraMCP server connectivity
- `ghidra_import_apk` — Import APK into Ghidra for analysis
- `ghidra_decompile_function` — Decompile a function to C code
- `ghidra_decompile_function_by_address` — Decompile function at hex address
- `ghidra_disassemble_function` — Get assembly for a function
- `ghidra_list_functions` — List all function names
- `ghidra_list_methods` — List paginated function names
- `ghidra_list_classes` — List namespace/class names
- `ghidra_list_segments` — List memory segments
- `ghidra_list_imports` — List imported symbols
- `ghidra_list_exports` — List exported symbols
- `ghidra_list_strings` — List defined strings with addresses
- `ghidra_search_functions` — Search functions by name substring
- `ghidra_rename_function` — Rename a function
- `ghidra_rename_data` — Rename a data label
- `ghidra_get_xrefs_to` — Get cross-references to an address
- `ghidra_get_xrefs_from` — Get cross-references from an address
- `ghidra_get_function_xrefs` — Get references to a function
- `ghidra_set_decompiler_comment` — Set comment in pseudocode
- `ghidra_set_disassembly_comment` — Set comment in disassembly

### Medusa Integration (via interactive shell)
- 90+ Frida hook modules for dynamic instrumentation
- SSL pinning bypass, root detection bypass, crypto monitoring
- Network traffic interception, filesystem monitoring
- Intent fuzzing, deep link testing

### Report Formats
- **JSON** — Machine-readable structured findings
- **Markdown** — Formatted with severity badges (critical/high/medium/low/info)
- **HTML** — Minimal standalone page with severity-colored cards

### Vulnerability Patterns (default)
Hardcoded API keys, insecure WebView configs, weak hashing (MD5/SHA1), SQL injection, sensitive data logging, mutable pending intents, custom deeplink schemes, insecure Random, SSL pinning bypass, world-writable files.

---

## Usage

### CLI

```bash
# Analyze
python mpc.py analyze target.apk --mobsf --jadx

# Parallel analysis
python mpc.py analyze-parallel target.apk

# MobSF only
python mpc.py mobsf-upload target.apk
python mpc.py mobsf-scan <file_hash>
python mpc.py mobsf-report <file_hash>

# JADX only
python mpc.py jadx-decompile target.apk
python mpc.py jadx-search target.apk "(?i)api_key|secret|password"

# Generate report
python mpc.py report target.apk --output-dir ./reports

# Interactive shell
python mpc.py
```

### MCP Server

```bash
# Start with stdio transport (for IDE integration)
python mpc_mcp_server.py --transport stdio

# Start with HTTP transport
python mpc_mcp_server.py --transport streamable-http --port 8000
```

### Configuration (Environment Variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `MOBSF_URL` | `http://localhost:8000` | MobSF server URL |
| `MOBSF_API_KEY` | — | MobSF REST API key |
| `JADX_HOME` | — | Path to JADX installation |
| `GHIDRA_HOME` | `C:\ghidra_11.3` | Path to Ghidra installation |
| `MPC_MCP_HOST` | `0.0.0.0` | MCP server bind host |
| `MPC_MCP_PORT` | `8000` | MCP server port |
| `MPC_MCP_TRANSPORT` | `streamable-http` | MCP transport protocol |

---

## Project Structure

```
FLUX/
├── mpc/                    # Core Python package
│   ├── mobsf.py            # MobSF REST API client
│   ├── jadx.py             # JADX CLI wrapper
│   ├── ghidra.py           # GhidraMCP client (decompile, rename, xrefs, etc.)
│   ├── pipeline.py         # Analysis orchestrator
│   ├── report.py           # Report generator (JSON/MD/HTML)
│   └── config.py           # Environment-based configuration
├── mpc.py                  # Interactive CLI entry point
├── mpc_mcp_server.py       # MCP protocol server
├── modules/                # Medusa Frida hook modules (90+)
│   └── mobsf/              # MobSF metadata collection module
├── ghidramcp/               # GhidraMCP plugin + bridge (LaurieWired)
│   ├── bridge_mcp_ghidra.py # Python MCP bridge to Ghidra
│   ├── src/                 # Ghidra plugin Java source
│   └── lib/                 # Ghidra extension JAR
├── medusa_android_mcp.py   # Medusa MCP server
├── tests/                  # 132 pytest tests
│   ├── test_mobsf.py
│   ├── test_jadx.py
│   ├── test_ghidra.py
│   ├── test_pipeline.py
│   └── test_report.py
└── assets/
    └── images/
        └── flux_logo.svg   # FLUX logo
```

---

## Credits

FLUX brings together exceptional open-source projects. All credit to their creators:

- **[Medusa](https://github.com/Ch0pin/medusa)** — The foundation. Medusa provides 90+ Frida-based instrumentation modules for Android security testing, plus the interactive CLI and MCP server that FLUX builds upon.
- **[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)** — Mobile Security Framework. Automated static, dynamic, and malware analysis for Android/iOS apps.
- **[JADX](https://github.com/skylot/jadx)** — DEX to Java decompiler. Transforms APK bytecode into readable Java source.
- **[GhidraMCP](https://github.com/LaurieWired/GhidraMCP)** — MCP Server for Ghidra by LaurieWired. Provides decompilation, renaming, cross-referencing, and binary analysis tools through Ghidra's plugin system.

FLUX is **GPL-3.0 licensed** — the same license as Medusa, which it extends.

---

## Status

**Active development.** FLUX is evolving — more tools, more modules, and deeper integrations are being added.

- 153 passing tests
- 4 integrated tools (Medusa, MobSF, JADX, GhidraMCP)
- 31 MCP tools
- 10 vulnerability pattern categories
- 3 report formats (JSON, MD, HTML)
