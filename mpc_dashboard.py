#!/usr/bin/env python3
"""FLUX Dashboard - local web UI for browsing analysis reports."""

from __future__ import annotations

import argparse
import json
import os
import webbrowser
from pathlib import Path
from typing import Any

import bottle
from bottle import route, template, static_file, redirect, request

DEFAULT_PORT = 9000
DEFAULT_REPORT_DIR = os.getenv("MPC_REPORT_DIR", "./reports")


def load_reports(report_dir: str) -> list[dict[str, Any]]:
    """Scan report_dir for *_report.json files and return metadata."""
    reports: list[dict[str, Any]] = []
    base = Path(report_dir).resolve()
    if not base.is_dir():
        return reports
    for f in sorted(base.glob("*_report.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            reports.append({
                "filename": f.name,
                "path": str(f),
                "apk_name": data.get("metadata", {}).get("apk_name", f.stem),
                "generated_at": data.get("metadata", {}).get("generated_at", ""),
                "tools_used": data.get("metadata", {}).get("tools_used", []),
                "summary": data.get("summary", {}),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def load_report_detail(report_dir: str, apk_name: str) -> dict[str, Any] | None:
    """Load a single report JSON by APK name."""
    base = Path(report_dir).resolve()
    candidates = list(base.glob(f"{apk_name}_report.json"))
    if not candidates:
        for f in base.glob("*_report.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            if data.get("metadata", {}).get("apk_name") == apk_name:
                return data
        return None
    try:
        return json.loads(candidates[0].read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# ── Routes ──────────────────────────────────────────────────────────

@route("/")
def index():
    redirect("/projects")


@route("/projects")
def project_list():
    reports = load_reports(_report_dir)
    return template(_TMPL_LIST, reports=reports, title="FLUX Dashboard", _report_dir=_report_dir)


@route("/projects/<apk_name:path>")
def project_detail(apk_name):
    data = load_report_detail(_report_dir, apk_name)
    if data is None:
        return "<h1>Not Found</h1><p>No report found for that APK.</p>"
    return template(
        _TMPL_DETAIL,
        data=data,
        apk_name=apk_name,
        title=f"FLUX - {apk_name}",
    )


@route("/report/<apk_name:path>/report.json")
def report_json(apk_name):
    data = load_report_detail(_report_dir, apk_name)
    if data is None:
        return bottle.HTTPResponse(status=404)
    return data


# ── Templates ───────────────────────────────────────────────────────

_TMPL_LIST = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui,-apple-system,sans-serif}
body{background:#0d1117;color:#c9d1d9;min-height:100vh}
.header{background:#161b22;border-bottom:1px solid #30363d;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
.header h1{font-size:1.25rem;color:#f0883e}.header span{color:#8b949e;font-size:.9rem}
.container{max-width:1200px;margin:0 auto;padding:2rem}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1.25rem;margin-bottom:1rem;transition:border-color .2s}
.card:hover{border-color:#f0883e}
.card h2{font-size:1.1rem;color:#f0883e;margin-bottom:.5rem}
.card .meta{font-size:.85rem;color:#8b949e;margin-bottom:.5rem}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600;margin-right:4px}
.critical{background:#d73a4a;color:#fff}.high{background:#d29922;color:#fff}
.medium{background:#9e6a03;color:#fff}.low{background:#58a6ff;color:#fff}.info{background:#30363d;color:#8b949e}
.empty{text-align:center;padding:4rem;color:#8b949e}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.tools{font-size:.8rem;color:#8b949e;margin-top:.5rem}
</style>
</head>
<body>
<div class="header"><h1>FLUX Dashboard</h1><span>Browse analysis reports</span></div>
<div class="container">
% if not reports:
<div class="empty">
<h2>No reports found</h2>
<p>Run an analysis first: <code>python mpc.py analyze target.apk</code></p>
<p>Reports are read from: <code>{{ _report_dir }}</code></p>
</div>
% else:
% for r in reports:
<a href="/projects/{{ r['apk_name'] }}">
<div class="card">
<h2>{{ r['apk_name'] }}</h2>
<div class="meta">{{ r['generated_at'][:19].replace('T',' ') }}</div>
<div class="meta">
% s = r['summary']
Total: <strong>{{ s.get('total_findings',0) }}</strong> findings
% for sev in ['critical','high','medium','low','info']:
% count = s.get('by_severity',{}).get(sev,0)
% if count:
<span class="badge {{ sev }}">{{ sev }}: {{ count }}</span>
% end
% end
</div>
<div class="tools">Tools: {{ ' '.join(r['tools_used']) }}</div>
</div>
</a>
% end
% end
</div>
</body>
</html>
"""

_TMPL_DETAIL = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box;font-family:system-ui,-apple-system,sans-serif}
body{background:#0d1117;color:#c9d1d9;min-height:100vh}
.header{background:#161b22;border-bottom:1px solid #30363d;padding:1rem 2rem;display:flex;align-items:center;gap:1rem}
.header h1{font-size:1.25rem;color:#f0883e}.header a{color:#58a6ff;font-size:.9rem}
.container{max-width:1200px;margin:0 auto;padding:2rem}
.summary-bar{display:flex;gap:1rem;margin-bottom:2rem;flex-wrap:wrap}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem 1.5rem;text-align:center;min-width:100px}
.stat-card .num{font-size:1.5rem;font-weight:700}.stat-card .label{font-size:.8rem;color:#8b949e;margin-top:4px}
.stat-card.crit .num{color:#d73a4a}.stat-card.high .num{color:#d29922}
.stat-card.med .num{color:#9e6a03}.stat-card.low .num{color:#58a6ff}.stat-card.info .num{color:#8b949e}
.findings-table{width:100%;border-collapse:collapse}
.findings-table th{text-align:left;padding:.75rem;border-bottom:2px solid #30363d;color:#8b949e;font-size:.85rem;text-transform:uppercase}
.findings-table td{padding:.75rem;border-bottom:1px solid #21262d;font-size:.9rem}
.findings-table tr:hover td{background:#161b22}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.75rem;font-weight:600}
.badge.critical{background:#d73a4a;color:#fff}.badge.high{background:#d29922;color:#fff}
.badge.medium{background:#9e6a03;color:#fff}.badge.low{background:#58a6ff;color:#fff}.badge.info{background:#30363d;color:#8b949e}
.finding-detail{display:none;background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:1rem;margin-top:8px;font-size:.85rem;line-height:1.5}
.finding-detail.open{display:block}
.finding-detail .field{margin-bottom:8px}
.finding-detail .field-label{color:#8b949e;font-size:.8rem;text-transform:uppercase;margin-bottom:2px}
.clickable{cursor:pointer}
.empty{text-align:center;padding:4rem;color:#8b949e}
.actions{display:flex;gap:.75rem;margin-top:1rem}
.btn{display:inline-block;padding:.5rem 1rem;border-radius:6px;font-size:.85rem;text-decoration:none}
.btn-outline{border:1px solid #30363d;color:#c9d1d9}.btn-outline:hover{background:#30363d}
</style>
</head>
<body>
<div class="header">
<a href="/projects">&larr; Projects</a>
<h1>{{ apk_name }}</h1>
<span style="color:#8b949e;font-size:.9rem">{{ data.get('metadata',{}).get('generated_at','')[:19].replace('T',' ') }}</span>
</div>
<div class="container">

% summary = data.get('summary',{})
<div class="summary-bar">
<div class="stat-card crit"><div class="num">{{ summary.get('by_severity',{}).get('critical',0) }}</div><div class="label">Critical</div></div>
<div class="stat-card high"><div class="num">{{ summary.get('by_severity',{}).get('high',0) }}</div><div class="label">High</div></div>
<div class="stat-card med"><div class="num">{{ summary.get('by_severity',{}).get('medium',0) }}</div><div class="label">Medium</div></div>
<div class="stat-card low"><div class="num">{{ summary.get('by_severity',{}).get('low',0) }}</div><div class="label">Low</div></div>
<div class="stat-card info"><div class="num">{{ summary.get('by_severity',{}).get('info',0) }}</div><div class="label">Info</div></div>
<div style="display:flex;align-items:center;margin-left:auto">
<a class="btn btn-outline" href="/report/{{ apk_name }}/report.json">Download JSON</a>
</div>
</div>

% findings = data.get('findings',[])
% if not findings:
<div class="empty"><h2>No findings</h2><p>The analysis completed but no issues were detected.</p></div>
% else:
<table class="findings-table">
<thead><tr><th>Severity</th><th>Title</th><th>Tool</th><th>Location</th></tr></thead>
<tbody>
% for i, f in enumerate(findings):
<tr class="clickable" onclick="toggleDetail('detail-{{ i }}')">
<td><span class="badge {{ f['severity'] }}">{{ f['severity'] }}</span></td>
<td>{{ f['title'] }}</td>
<td>{{ f['tool'] }}</td>
<td>{{ f.get('location','')[:60] }}</td>
</tr>
<tr id="detail-{{ i }}" class="finding-detail"><td colspan="4">
<div class="field"><div class="field-label">Description</div>{{ f.get('description','') }}</div>
% if f.get('location'):
<div class="field"><div class="field-label">Location</div><code>{{ f['location'] }}</code></div>
% end
% if f.get('recommendation'):
<div class="field"><div class="field-label">Recommendation</div>{{ f['recommendation'] }}</div>
% end
<div class="field"><div class="field-label">Category</div>{{ f.get('category','') }}</div>
</td></tr>
% end
</tbody>
</table>
% end
</div>
<script>
function toggleDetail(id){var el=document.getElementById(id);if(!el)return;el.classList.toggle('open');el.style.display=el.classList.contains('open')?'table-row':'none';}
</script>
</body>
</html>
"""


def main() -> None:
    parser = argparse.ArgumentParser(description="FLUX Dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default {DEFAULT_PORT})")
    parser.add_argument("--report-dir", default=DEFAULT_REPORT_DIR, help="Report directory (default: ./reports)")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    args = parser.parse_args()

    global _report_dir
    _report_dir = args.report_dir

    if not args.no_browser:
        webbrowser.open(f"http://localhost:{args.port}/projects")

    bottle.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
