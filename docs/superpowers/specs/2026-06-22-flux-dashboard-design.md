# FLUX Dashboard Design

## Overview

A lightweight local web dashboard for browsing FLUX analysis results. Built with Bottle (single-file Python web framework, zero dependencies). Reads reports from FLUX's data directory — no database, no running analysis — just a readable view of what FLUX has already produced.

## Architecture

- **Single file:** `mpc_dashboard.py` in the project root
- **Framework:** Bottle (stdlib only, no pip install needed beyond what FLUX already requires)
- **Data source:** `flux_data/` directory where FLUX saves analysis reports (JSON)
- **Server:** Bottle dev server, configurable port (default 9000)
- **Startup:** `python mpc_dashboard.py` opens the browser automatically

## Data Format

The dashboard reads from `flux_data/`, which contains one subdirectory per analyzed APK:

```
flux_data/
├── target.apk_2026-06-22_10-30-00/
│   ├── report.json          # Full pipeline report
│   ├── report.md            # Markdown report
│   ├── report.html          # HTML report
│   ├── status.json          # Scan metadata (date, tools used, file hash)
│   └── findings.json        # Normalized findings list
└── another.apk_2026-06-21_14-00-00/
    └── ...
```

`findings.json` is the primary data source — it's already produced by FLUX's pipeline and contains normalized findings with severity, title, description, and tool source.

## Pages

### Page 1 — Project List (`/`)

- Lists all analyzed APKs from `flux_data/`, sorted by most recent first
- Each row shows: APK name, date analyzed, tool summary (which tools ran), finding counts by severity
- "Open" link to project detail
- Search/filter by APK name

### Page 2 — Project Detail (`/project/<name>`)

- Summary bar with severity counts (critical/high/medium/low/info)
- Findings table with columns: severity (color-coded badge), title, tool (MobSF/JADX/Ghidra), location
- Click a finding to expand and see full description, code snippet, and remediation
- Quick links: "Re-analyze" (opens CLI command), "Download reports" (JSON/MD/HTML)

### Page 3 — Raw Report Viewer (`/project/<name>/report`)

- Shows the full report in a readable format
- Links to download raw JSON/MD/HTML files

## UI

- **CSS framework:** None. Single CSS file with minimal styling (dark theme, matches FLUX brand colors from logo)
- **No JavaScript frameworks.** Plain vanilla JS for filtering and expand/collapse
- **Responsive** — works on desktop and tablet
- **Dark theme** by default (orange accent to match FLUX forge/anvil logo)

## Implementation Plan

1. Create `mpc_dashboard.py` with Bottle routes
2. Add `flux_data/` directory discovery and JSON loading helpers
3. Build Project List page (template + CSS)
4. Build Project Detail page (template + CSS)
5. Build Report Viewer page
6. Add auto-open browser on startup
7. Add `--port` argument (default 9000)
8. Write tests
