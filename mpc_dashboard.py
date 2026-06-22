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
from bottle import route, template, redirect

DEFAULT_PORT = 9000
DEFAULT_REPORT_DIR = os.getenv("MPC_REPORT_DIR", "./reports")

# Mutable module-level config set by main()
_config = {"report_dir": DEFAULT_REPORT_DIR}


def load_reports(report_dir: str) -> list[dict[str, Any]]:
    reports: list[dict[str, Any]] = []
    base = Path(report_dir).resolve()
    if not base.is_dir():
        return reports
    for f in sorted(base.glob("*_report.json"), reverse=True):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            reports.append({
                "filename": f.name,
                "apk_name": data.get("metadata", {}).get("apk_name", f.stem),
                "generated_at": data.get("metadata", {}).get("generated_at", ""),
                "tools_used": data.get("metadata", {}).get("tools_used", []),
                "summary": data.get("summary", {}),
            })
        except (json.JSONDecodeError, OSError):
            continue
    return reports


def load_report_detail(report_dir: str, apk_name: str) -> dict[str, Any] | None:
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


_LOGO_SVG = """<svg viewBox="0 0 120 120" fill="none" class="logo-svg">
  <circle cx="60" cy="60" r="56" stroke="currentColor" stroke-width="1.5" fill="none" opacity="0.3"/>
  <circle cx="60" cy="60" r="48" stroke="currentColor" stroke-width="0.5" fill="none" opacity="0.15"/>
  <path d="M42 80 L42 50 L60 36 L78 50 L78 80 Z" stroke="currentColor" stroke-width="1.5" fill="none"/>
  <path d="M48 72 L48 55 L60 46 L72 55 L72 72 Z" stroke="currentColor" stroke-width="1" fill="none" opacity="0.5"/>
  <line x1="60" y1="36" x2="60" y2="84" stroke="currentColor" stroke-width="0.5" opacity="0.2"/>
  <circle cx="60" cy="60" r="3" fill="currentColor"/>
  <path d="M55 72 L60 66 L65 72" stroke="currentColor" stroke-width="1" fill="none"/>
  <line x1="60" y1="66" x2="60" y2="78" stroke="currentColor" stroke-width="1"/>
</svg>"""


@route("/")
def index():
    redirect("/projects")


@route("/projects")
def project_list():
    reports = load_reports(_config["report_dir"])
    return template(_PAGE_LIST, reports=reports, logo_svg=_LOGO_SVG, report_dir=_config["report_dir"], _BASE_CSS=_BASE_CSS)


@route("/projects/<apk_name:path>")
def project_detail(apk_name):
    data = load_report_detail(_config["report_dir"], apk_name)
    if data is None:
        return "<h1>Not found</h1>"
    return template(_PAGE_DETAIL, data=data, apk_name=apk_name, logo_svg=_LOGO_SVG, _BASE_CSS=_BASE_CSS)


@route("/api/report/<apk_name:path>")
def report_json(apk_name):
    data = load_report_detail(_config["report_dir"], apk_name)
    if data is None:
        return bottle.HTTPResponse(status=404)
    bottle.response.content_type = "application/json"
    return json.dumps(data, indent=2)


_BASE_CSS = """
*{margin:0;padding:0;box-sizing:border-box}
html,body{height:100%}
body{background:#080b10;color:#c9d1d9;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;display:flex;line-height:1.5}
::selection{background:#f0883e40;color:#fff}
a{color:inherit;text-decoration:none}
a:hover{color:#f0883e}

.sidebar{width:220px;min-width:220px;background:#0c1017;border-right:1px solid #1a1f2a;display:flex;flex-direction:column;padding:2rem 1.5rem;height:100vh;position:sticky;top:0}
.sidebar .logo-wrap{display:flex;align-items:center;gap:.75rem;margin-bottom:2.5rem}
.logo-svg{width:36px;height:36px;color:#f0883e;flex-shrink:0}
.logo-text{font-size:1.1rem;font-weight:600;letter-spacing:-.02em;color:#e1e4e8}
.logo-text span{color:#f0883e}
.sidebar .tagline{font-size:.75rem;color:#5a6270;margin-top:-1.5rem;margin-bottom:2.5rem;padding-left:3rem}
.sidebar nav{display:flex;flex-direction:column;gap:.25rem}
.sidebar nav a{display:flex;align-items:center;gap:.75rem;padding:.6rem .75rem;border-radius:8px;font-size:.875rem;color:#8b949e;transition:all .2s}
.sidebar nav a:hover{background:#131a24;color:#e1e4e8}
.sidebar nav a.active{background:#f0883e10;color:#f0883e;font-weight:500}
.sidebar .nav-icon{width:16px;height:16px;opacity:.6}
.sidebar-footer{margin-top:auto;font-size:.75rem;color:#3a4250}

.main{flex:1;min-width:0;padding:2.5rem 3rem;max-width:1100px}
.page-title{font-size:1.5rem;font-weight:600;letter-spacing:-.02em;margin-bottom:.5rem;color:#e1e4e8}
.page-sub{font-size:.875rem;color:#5a6270;margin-bottom:2.5rem}

.reports-list{display:flex;flex-direction:column;gap:.75rem}
.report-card{display:flex;align-items:center;justify-content:space-between;padding:1.25rem 1.5rem;background:#0c1017;border:1px solid #1a1f2a;border-radius:12px;transition:all .25s;cursor:pointer;animation:fadeUp .4s ease both}
.report-card:nth-child(1){animation-delay:0s}
.report-card:nth-child(2){animation-delay:.05s}
.report-card:nth-child(3){animation-delay:.1s}
.report-card:nth-child(4){animation-delay:.15s}
.report-card:nth-child(5){animation-delay:.2s}
.report-card:nth-child(n+6){animation-delay:.25s}
.report-card:hover{background:#10171f;border-color:#f0883e30;transform:translateY(-1px)}
.report-card:active{transform:translateY(0)}
.card-left{min-width:0}
.card-name{font-size:1rem;font-weight:500;color:#e1e4e8;margin-bottom:.25rem}
.card-meta{font-size:.8rem;color:#5a6270}
.card-stats{display:flex;align-items:center;gap:.75rem;flex-shrink:0}
.sev-dot{display:inline-flex;align-items:center;gap:4px;font-size:.75rem;font-weight:500}
.sev-dot::before{content:'';width:6px;height:6px;border-radius:50%;flex-shrink:0}
.sev-dot.critical{color:#f85149}.sev-dot.critical::before{background:#f85149}
.sev-dot.high{color:#d29922}.sev-dot.high::before{background:#d29922}
.sev-dot.medium{color:#bb8009}.sev-dot.medium::before{background:#bb8009}
.sev-dot.low{color:#58a6ff}.sev-dot.low::before{background:#58a6ff}
.sev-dot.info{color:#5a6270}.sev-dot.info::before{background:#5a6270}
.card-arrow{color:#3a4250;font-size:1.1rem;transition:transform .2s;margin-left:.5rem}
.report-card:hover .card-arrow{color:#f0883e;transform:translateX(3px)}

@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}

.empty-state{text-align:center;padding:5rem 2rem;animation:fadeUp .5s ease}
.empty-state .empty-icon{width:48px;height:48px;color:#3a4250;margin-bottom:1.5rem}
.empty-state h2{font-size:1.2rem;font-weight:500;color:#5a6270;margin-bottom:.5rem}
.empty-state p{font-size:.875rem;color:#3a4250}
.empty-state code{background:#0c1017;padding:.15rem .5rem;border-radius:4px;font-size:.8rem}

/* --- Detail page --- */
.breadcrumbs{display:flex;align-items:center;gap:.5rem;font-size:.875rem;color:#5a6270;margin-bottom:2rem}
.breadcrumbs a{color:#5a6270;transition:color .2s}
.breadcrumbs a:hover{color:#f0883e}
.breadcrumbs .sep{color:#3a4250}
.detail-header{display:flex;align-items:flex-start;justify-content:space-between;gap:1rem;margin-bottom:2rem;animation:fadeUp .35s ease}
.detail-header h1{font-size:1.5rem;font-weight:600;letter-spacing:-.02em;color:#e1e4e8}
.detail-header .date{font-size:.8rem;color:#5a6270;margin-top:.25rem}
.detail-header .tools-used{display:flex;gap:.5rem;margin-top:.5rem}
.tool-tag{font-size:.75rem;padding:.2rem .6rem;border-radius:6px;background:#131a24;color:#5a6270;border:1px solid #1a1f2a}

.summary-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:.75rem;margin-bottom:2.5rem;animation:fadeUp .4s ease .1s both}
.stat-tile{background:#0c1017;border:1px solid #1a1f2a;border-radius:10px;padding:1rem;text-align:center;transition:border-color .2s}
.stat-tile:hover{border-color:#1e2630}
.stat-num{font-size:1.75rem;font-weight:700;line-height:1;margin-bottom:.25rem}
.stat-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:#5a6270}
.stat-tile.critical .stat-num{color:#f85149}
.stat-tile.high .stat-num{color:#d29922}
.stat-tile.medium .stat-num{color:#bb8009}
.stat-tile.low .stat-num{color:#58a6ff}
.stat-tile.info .stat-num{color:#5a6270}

.section-head{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em;color:#3a4250;margin-bottom:1rem;padding-bottom:.5rem;border-bottom:1px solid #1a1f2a}

.findings-list{display:flex;flex-direction:column;gap:4px;animation:fadeUp .4s ease .2s both}
.finding-row{background:#0c1017;border:1px solid #1a1f2a;border-radius:8px;transition:all .2s;overflow:hidden}
.finding-row:hover{border-color:#1e2630}
.finding-header{display:flex;align-items:center;gap:1rem;padding:.9rem 1.25rem;cursor:pointer;user-select:none;transition:background .2s}
.finding-header:hover{background:#10171f}
.finding-sev{width:3px;min-width:3px;height:24px;border-radius:2px;flex-shrink:0}
.finding-sev.critical{background:#f85149}.finding-sev.high{background:#d29922}
.finding-sev.medium{background:#bb8009}.finding-sev.low{background:#58a6ff}.finding-sev.info{background:#3a4250}
.finding-title{flex:1;font-size:.9rem;color:#e1e4e8;min-width:0}
.finding-tool{font-size:.75rem;color:#5a6270;min-width:40px;text-align:right}
.finding-toggle{color:#3a4250;font-size:.7rem;transition:transform .25s;min-width:12px;text-align:center}
.finding-toggle.open{transform:rotate(180deg)}

.finding-body{max-height:0;overflow:hidden;transition:max-height .3s ease,border-color .3s;border-top:0 solid #1a1f2a}
.finding-body.open{max-height:400px;border-top-width:1px;border-top-style:solid}
.finding-body-inner{padding:1rem 1.25rem 1.25rem}
.finding-body .field{margin-bottom:.75rem}
.finding-body .field:last-child{margin-bottom:0}
.finding-body .field-label{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:#5a6270;margin-bottom:.25rem}
.finding-body .field-value{font-size:.85rem;color:#8b949e;line-height:1.6}
.finding-body code{padding:.15rem .4rem;background:#131a24;border-radius:4px;font-size:.8rem;color:#c9d1d9}

.btn{display:inline-flex;align-items:center;gap:.5rem;padding:.5rem 1rem;border-radius:8px;font-size:.8rem;font-weight:500;transition:all .2s;cursor:pointer;border:none;background:transparent}
.btn-primary{background:#f0883e;color:#080b10}
.btn-primary:hover{background:#d9772e}
.btn-ghost{color:#5a6270;border:1px solid #1a1f2a}
.btn-ghost:hover{color:#e1e4e8;border-color:#3a4250}
.header-actions{display:flex;gap:.5rem;flex-shrink:0}

@media(max-width:768px){
.sidebar{display:none}
.main{padding:1.5rem}
.summary-grid{grid-template-columns:repeat(3,1fr)}
}
"""

_PAGE_LIST = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FLUX — reports</title>
<style>{{ !_BASE_CSS }}</style>
</head>
<body>
<aside class="sidebar">
  <div class="logo-wrap">{{ !logo_svg }}<span class="logo-text">FL<span>U</span>X</span></div>
  <div class="tagline">analysis forge</div>
  <nav>
    <a href="/projects" class="active">
      <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="5" height="6" rx="1"/><rect x="9" y="2" width="5" height="4" rx="1"/><rect x="2" y="10" width="5" height="4" rx="1"/><rect x="9" y="8" width="5" height="6" rx="1"/></svg>
      Reports
    </a>
  </nav>
  <div class="sidebar-footer">v1 &middot; local</div>
</aside>
<div class="main">
  <h1 class="page-title">Reports</h1>
  <p class="page-sub">Browse APK analysis results</p>
  % if not reports:
  <div class="empty-state">
    <svg class="empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
    <h2>No reports yet</h2>
    <p>Run <code>python mpc.py analyze target.apk</code> to generate one.</p>
    <p style="margin-top:.25rem">Looking in <code>{{ report_dir }}</code></p>
  </div>
  % else:
  <div class="reports-list">
  % for r in reports:
    <a href="/projects/{{ r['apk_name'] }}" class="report-card">
      <div class="card-left">
        <div class="card-name">{{ r['apk_name'] }}</div>
        <div class="card-meta">{{ r['generated_at'][:19].replace('T',' ') }} &middot; {{ ' '.join(r['tools_used']) }}</div>
      </div>
      <div class="card-stats">
        % s = r['summary']
        % for sev in ['critical','high','medium','low','info']:
        %   count = s.get('by_severity',{}).get(sev,0)
        %   if count:
        <span class="sev-dot {{ sev }}">{{ count }}</span>
        %   end
        % end
        <span class="card-arrow">&rarr;</span>
      </div>
    </a>
  % end
  </div>
  % end
</div>
</body>
</html>"""

_PAGE_DETAIL = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FLUX — {{ apk_name }}</title>
<style>{{ !_BASE_CSS }}</style>
</head>
<body>
<aside class="sidebar">
  <div class="logo-wrap">{{ !logo_svg }}<span class="logo-text">FL<span>U</span>X</span></div>
  <div class="tagline">analysis forge</div>
  <nav>
    <a href="/projects">
      <svg class="nav-icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="2" width="5" height="6" rx="1"/><rect x="9" y="2" width="5" height="4" rx="1"/><rect x="2" y="10" width="5" height="4" rx="1"/><rect x="9" y="8" width="5" height="6" rx="1"/></svg>
      Reports
    </a>
  </nav>
  <div class="sidebar-footer">v1 &middot; local</div>
</aside>
<div class="main">
  <div class="breadcrumbs">
    <a href="/projects">Reports</a>
    <span class="sep">/</span>
    <span>{{ apk_name[:40] }}</span>
  </div>

  <div class="detail-header">
    <div>
      <h1>{{ apk_name }}</h1>
      <div class="date">{{ data.get('metadata',{}).get('generated_at','')[:19].replace('T',' ') }}</div>
      <div class="tools-used">
        % for t in data.get('metadata',{}).get('tools_used',[]):
        <span class="tool-tag">{{ t }}</span>
        % end
      </div>
    </div>
    <div class="header-actions">
      <a href="/api/report/{{ apk_name }}" class="btn btn-ghost">JSON</a>
    </div>
  </div>

  % summary = data.get('summary',{})
  <div class="summary-grid">
    <div class="stat-tile critical"><div class="stat-num">{{ summary.get('by_severity',{}).get('critical',0) }}</div><div class="stat-label">Critical</div></div>
    <div class="stat-tile high"><div class="stat-num">{{ summary.get('by_severity',{}).get('high',0) }}</div><div class="stat-label">High</div></div>
    <div class="stat-tile medium"><div class="stat-num">{{ summary.get('by_severity',{}).get('medium',0) }}</div><div class="stat-label">Medium</div></div>
    <div class="stat-tile low"><div class="stat-num">{{ summary.get('by_severity',{}).get('low',0) }}</div><div class="stat-label">Low</div></div>
    <div class="stat-tile info"><div class="stat-num">{{ summary.get('by_severity',{}).get('info',0) }}</div><div class="stat-label">Info</div></div>
  </div>

  % findings = data.get('findings',[])
  <div class="section-head">Findings &mdash; {{ len(findings) }} total</div>
  % if not findings:
  <div class="empty-state" style="padding:3rem">
    <h2>No findings</h2>
    <p>Analysis completed clean.</p>
  </div>
  % else:
  <div class="findings-list">
  % for i, f in enumerate(findings):
    <div class="finding-row">
      <div class="finding-header" onclick="toggle({{i}})">
        <div class="finding-sev {{ f['severity'] }}"></div>
        <span class="finding-title">{{ f['title'] }}</span>
        <span class="finding-tool">{{ f['tool'] }}</span>
        <span class="finding-toggle" id="toggle-{{i}}">&#9660;</span>
      </div>
      <div class="finding-body" id="body-{{i}}">
        <div class="finding-body-inner">
          <div class="field"><div class="field-label">Description</div><div class="field-value">{{ f.get('description','') }}</div></div>
          % if f.get('location'):
          <div class="field"><div class="field-label">Location</div><div class="field-value"><code>{{ f['location'] }}</code></div></div>
          % end
          % if f.get('recommendation'):
          <div class="field"><div class="field-label">Recommendation</div><div class="field-value">{{ f['recommendation'] }}</div></div>
          % end
          <div class="field"><div class="field-label">Category</div><div class="field-value">{{ f.get('category','') }}</div></div>
        </div>
      </div>
    </div>
  % end
  </div>
  % end
</div>
<script>
function toggle(i){
  var body=document.getElementById('body-'+i),tg=document.getElementById('toggle-'+i),open=body.classList.toggle('open');
  tg&&tg.classList.toggle('open');
}
window.addEventListener('click',function(e){
  var row=e.target.closest('.finding-row');
  if(!row)return;
  if(e.target.closest('.finding-body'))return;
  var h=row.querySelector('.finding-header');
  if(h&&h.contains(e.target))return;
});
</script>
</body>
</html>"""


def main() -> None:
    parser = argparse.ArgumentParser(description="FLUX Dashboard")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port (default {DEFAULT_PORT})")
    parser.add_argument("--report-dir", default=DEFAULT_REPORT_DIR, help=f"Report directory (default: {DEFAULT_REPORT_DIR})")
    parser.add_argument("--no-browser", action="store_true", help="Don't open browser automatically")
    args = parser.parse_args()

    global _config
    _config["report_dir"] = args.report_dir

    if not args.no_browser:
        webbrowser.open(f"http://localhost:{args.port}/projects")

    bottle.run(host="0.0.0.0", port=args.port, debug=False)


if __name__ == "__main__":
    main()
