"""
generate_pages.py — Scan output/ directories and generate GitHub Pages HTML reports.

Usage:
    python -m sc_audit_crew.generate_pages [--output-dir output/] [--pages-dir _site/]

Called by GitHub Actions on push to master when output/** changes.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import date
from pathlib import Path

# ---------------------------------------------------------------------------
# HTML Templates
# ---------------------------------------------------------------------------

# Placeholders use {{name}} syntax so single { } in CSS/JS are unaffected.
# Substitution: re.sub(r'\{\{(\w+)\}\}', lambda m: data[m.group(1)], template)

_REPORT_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{project_name}} — Security Audit Report</title>
<style>
:root {
  --bg:       #0d1117;
  --surface:  #161b22;
  --surface2: #21262d;
  --border:   #30363d;
  --text:     #e6edf3;
  --muted:    #8b949e;
  --accent:   #58a6ff;
  --critical: #ff4444;
  --high:     #ff8c00;
  --medium:   #d4a017;
  --low:      #4488ff;
  --info:     #6e7681;
  --radius:   8px;
  --max-w:    900px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  font-size: 15px;
  line-height: 1.6;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* ── Layout ────────────────────────────────────────────────── */
header {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  padding: 24px 0 0;
}
.header-inner { max-width: var(--max-w); margin: 0 auto; padding: 0 24px; }
.brand { font-size: 13px; color: var(--muted); margin-bottom: 8px; }
.brand a { color: var(--muted); }
.brand a:hover { color: var(--text); }
header h1 { font-size: 26px; font-weight: 700; margin-bottom: 10px; }
.header-meta { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; padding-bottom: 16px; }
.badge {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 2px 10px;
  font-size: 12px;
  color: var(--muted);
}

/* ── Stats bar ─────────────────────────────────────────────── */
.stats-bar {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}
.stats-inner {
  max-width: var(--max-w);
  margin: 0 auto;
  padding: 0 24px;
  display: flex;
  gap: 0;
}
.stat {
  flex: 1;
  text-align: center;
  padding: 14px 0;
  border-right: 1px solid var(--border);
  cursor: default;
}
.stat:last-child { border-right: none; }
.stat .num { display: block; font-size: 24px; font-weight: 700; }
.stat .lbl { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); }
.stat.critical .num { color: var(--critical); }
.stat.high     .num { color: var(--high); }
.stat.medium   .num { color: var(--medium); }
.stat.low      .num { color: var(--low); }
.stat.info     .num { color: var(--info); }

/* ── Nav ───────────────────────────────────────────────────── */
nav {
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: sticky;
  top: 0;
  z-index: 100;
}
.nav-inner {
  max-width: var(--max-w);
  margin: 0 auto;
  padding: 0 24px;
  display: flex;
  gap: 4px;
}
nav a {
  display: inline-block;
  padding: 10px 14px;
  color: var(--muted);
  font-size: 13px;
  border-bottom: 2px solid transparent;
  transition: color .15s, border-color .15s;
}
nav a:hover { color: var(--text); text-decoration: none; border-color: var(--border); }

/* ── Content sections ──────────────────────────────────────── */
.content { max-width: var(--max-w); margin: 0 auto; padding: 32px 24px; }
.section { margin-bottom: 48px; }
.section h2 {
  font-size: 20px;
  font-weight: 600;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 18px;
}
.section p { margin-bottom: 12px; color: var(--text); }

/* ── Scope table ───────────────────────────────────────────── */
.scope-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.scope-table th, .scope-table td {
  padding: 9px 14px;
  text-align: left;
  border-bottom: 1px solid var(--border);
}
.scope-table th { background: var(--surface2); color: var(--muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }
.scope-table td:first-child { font-family: monospace; font-size: 13px; }

/* ── Filter bar ────────────────────────────────────────────── */
.filter-bar {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-bottom: 18px;
  align-items: center;
}
.filter-bar select, .filter-bar input {
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  color: var(--text);
  padding: 7px 12px;
  font-size: 13px;
  outline: none;
}
.filter-bar select:focus, .filter-bar input:focus { border-color: var(--accent); }
.filter-bar input { flex: 1; min-width: 180px; }
.finding-count { color: var(--muted); font-size: 13px; margin-left: auto; }

/* ── Finding cards ─────────────────────────────────────────── */
.finding-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  margin-bottom: 10px;
  overflow: hidden;
  border-left: 3px solid var(--border);
  transition: border-color .15s;
}
.finding-card.sev-critical { border-left-color: var(--critical); }
.finding-card.sev-high     { border-left-color: var(--high); }
.finding-card.sev-medium   { border-left-color: var(--medium); }
.finding-card.sev-low      { border-left-color: var(--low); }
.finding-card.sev-informational { border-left-color: var(--info); }

.finding-header {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 14px 18px;
  cursor: pointer;
  user-select: none;
}
.finding-header:hover { background: var(--surface2); }

.sev-badge {
  display: inline-block;
  padding: 2px 9px;
  border-radius: 20px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: .4px;
  white-space: nowrap;
  flex-shrink: 0;
}
.sev-badge.critical    { background: #2d0000; color: var(--critical); border: 1px solid var(--critical); }
.sev-badge.high        { background: #2d1800; color: var(--high);     border: 1px solid var(--high); }
.sev-badge.medium      { background: #2d2200; color: var(--medium);   border: 1px solid var(--medium); }
.sev-badge.low         { background: #00112d; color: var(--low);      border: 1px solid var(--low); }
.sev-badge.informational { background: var(--surface2); color: var(--info); border: 1px solid var(--border); }

.finding-id { font-family: monospace; font-size: 12px; color: var(--muted); flex-shrink: 0; }
.finding-title { font-weight: 500; font-size: 14px; flex: 1; }
.finding-loc { font-family: monospace; font-size: 11px; color: var(--muted); flex-shrink: 0; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.chevron { color: var(--muted); font-size: 11px; flex-shrink: 0; transition: transform .2s; }
.finding-card.open .chevron { transform: rotate(90deg); }

.finding-body {
  max-height: 0;
  overflow: hidden;
  transition: max-height .3s ease;
}
.finding-card.open .finding-body { max-height: 9999px; }
.finding-body-inner { padding: 0 18px 18px; border-top: 1px solid var(--border); }

.field { margin-top: 16px; }
.field h4 { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); margin-bottom: 8px; }
.field p, .field div { font-size: 14px; line-height: 1.6; }

/* ── Code blocks ───────────────────────────────────────────── */
pre {
  background: #010409;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 14px;
  overflow-x: auto;
  margin: 10px 0;
}
pre code {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 13px;
  line-height: 1.5;
  color: #e6edf3;
}
code {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
  font-size: 13px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 5px;
}
pre code { background: none; border: none; padding: 0; border-radius: 0; }

/* ── References ────────────────────────────────────────────── */
.ref-badge {
  display: inline-block;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 2px 8px;
  font-family: monospace;
  font-size: 12px;
  margin: 2px 4px 2px 0;
  color: var(--accent);
}

/* ── Definitions table ─────────────────────────────────────── */
.def-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.def-table th, .def-table td { padding: 10px 14px; border-bottom: 1px solid var(--border); }
.def-table th { background: var(--surface2); font-size: 12px; text-transform: uppercase; color: var(--muted); text-align: left; }

/* ── Recommendations ───────────────────────────────────────── */
.rec-list { list-style: none; padding: 0; }
.rec-list li {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 14px 18px;
  margin-bottom: 10px;
  font-size: 14px;
  line-height: 1.6;
}
.rec-list li strong { color: var(--accent); }

/* ── Footer ────────────────────────────────────────────────── */
footer {
  border-top: 1px solid var(--border);
  padding: 24px;
  text-align: center;
  color: var(--muted);
  font-size: 13px;
}
footer a { color: var(--muted); }
footer a:hover { color: var(--text); }
</style>
</head>
<body>

<header>
  <div class="header-inner">
    <div class="brand">
      <a href="../index.html">← All Audits</a>
    </div>
    <h1>{{project_name}}</h1>
    <div class="header-meta">
      <span class="badge">📅 {{audit_date}}</span>
      {{chain_badge}}
      {{protocol_badge}}
      <span class="badge">Solidity</span>
    </div>
  </div>
</header>

<div class="stats-bar">
  <div class="stats-inner">
    <div class="stat critical"><span class="num">{{stat_critical}}</span><span class="lbl">Critical</span></div>
    <div class="stat high">   <span class="num">{{stat_high}}</span>   <span class="lbl">High</span></div>
    <div class="stat medium"> <span class="num">{{stat_medium}}</span> <span class="lbl">Medium</span></div>
    <div class="stat low">    <span class="num">{{stat_low}}</span>    <span class="lbl">Low</span></div>
    <div class="stat info">   <span class="num">{{stat_info}}</span>   <span class="lbl">Informational</span></div>
  </div>
</div>

<nav>
  <div class="nav-inner">
    <a href="#summary">Summary</a>
    <a href="#scope">Scope</a>
    <a href="#methodology">Methodology</a>
    <a href="#findings">Findings</a>
    <a href="#recommendations">Recommendations</a>
    <a href="#definitions">Severity Definitions</a>
  </div>
</nav>

<div class="content">

  <section class="section" id="summary">
    <h2>Executive Summary</h2>
    {{executive_summary_html}}
  </section>

  <section class="section" id="scope">
    <h2>Scope</h2>
    <table class="scope-table">
      <thead><tr><th>File</th><th>Lines</th><th>Notes</th></tr></thead>
      <tbody>{{scope_rows_html}}</tbody>
    </table>
  </section>

  <section class="section" id="methodology">
    <h2>Methodology</h2>
    {{methodology_html}}
  </section>

  <section class="section" id="findings">
    <h2>Findings</h2>
    <div class="filter-bar">
      <select id="filter-sev">
        <option value="">All Severities</option>
        <option>Critical</option>
        <option>High</option>
        <option>Medium</option>
        <option>Low</option>
        <option>Informational</option>
      </select>
      <select id="filter-src">
        <option value="">All Sources</option>
        <option value="manual_review">Manual Review</option>
        <option value="static_analysis">Static Analysis</option>
        <option value="threat_model">Threat Model</option>
        <option value="code_quality">Code Quality</option>
      </select>
      <input type="search" id="filter-q" placeholder="Search findings…">
      <span class="finding-count" id="finding-count"></span>
    </div>
    <div id="findings-list"></div>
  </section>

  <section class="section" id="recommendations">
    <h2>General Recommendations</h2>
    <ul class="rec-list" id="rec-list">{{recommendations_html}}</ul>
  </section>

  <section class="section" id="definitions">
    <h2>Severity Definitions</h2>
    <table class="def-table">
      <thead><tr><th>Severity</th><th>Description</th></tr></thead>
      <tbody>
        <tr><td><span class="sev-badge critical">Critical</span></td><td>Direct loss of funds or complete protocol compromise possible without preconditions.</td></tr>
        <tr><td><span class="sev-badge high">High</span></td><td>Loss of funds or significant protocol disruption possible under realistic conditions.</td></tr>
        <tr><td><span class="sev-badge medium">Medium</span></td><td>Logic bugs or vulnerabilities that could impact protocol correctness or user experience.</td></tr>
        <tr><td><span class="sev-badge low">Low</span></td><td>Best-practice deviations or minor issues with limited impact.</td></tr>
        <tr><td><span class="sev-badge informational">Info</span></td><td>Observations, gas optimisations, and code quality improvements.</td></tr>
      </tbody>
    </table>
  </section>

</div>

<footer>
  Generated by <a href="https://github.com/{{github_repo}}">SCAuditCrew</a> &middot; {{generated_date}}
</footer>

<script>
const FINDINGS = {{findings_json}};

function escHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function mdToHtml(text) {
  if (!text) return '';
  // Fenced code blocks
  text = text.replace(/```(?:[a-z]*)\\n([\\s\\S]*?)```/g, function(_, code) {
    return '<pre><code>' + escHtml(code) + '</code></pre>';
  });
  // Inline code
  text = text.replace(/`([^`]+)`/g, function(_, c) { return '<code>' + escHtml(c) + '</code>'; });
  // Bold
  text = text.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Paragraphs: split on double newline
  var parts = text.split(/\\n{2,}/);
  return parts.map(function(p) {
    p = p.trim();
    if (!p) return '';
    if (p.startsWith('<pre>') || p.startsWith('<ul>') || p.startsWith('<ol>')) return p;
    // Bullet lists
    if (/^[-*] /m.test(p)) {
      var items = p.split('\\n').filter(function(l) { return l.trim(); }).map(function(l) {
        return '<li>' + l.replace(/^[-*] /, '') + '</li>';
      });
      return '<ul style="margin:8px 0 8px 20px">' + items.join('') + '</ul>';
    }
    // Numbered lists
    if (/^\d+\.\s/m.test(p)) {
      var items = p.split('\\n').filter(function(l) { return l.trim(); }).map(function(l) {
        return '<li>' + l.replace(/^\d+\.\s+/, '') + '</li>';
      });
      return '<ol style="margin:8px 0 8px 20px">' + items.join('') + '</ol>';
    }
    return '<p>' + p.replace(/\\n/g, ' ') + '</p>';
  }).join('');
}

function sevClass(s) {
  return (s || 'informational').toLowerCase().replace(/\s+/g, '');
}

function buildCard(f) {
  var sc = sevClass(f.severity);
  var loc = '';
  if (f.file) {
    loc = f.file;
    if (f.line_start) loc += ':' + f.line_start;
    if (f.function) loc += ' (' + f.function + ')';
  }
  var refs = '';
  if (f.references && f.references.length) {
    refs = '<div class="field"><h4>References</h4>' +
      f.references.map(function(r) { return '<span class="ref-badge">' + escHtml(r) + '</span>'; }).join('') +
      '</div>';
  }
  var impact = f.impact ? '<div class="field"><h4>Impact</h4>' + mdToHtml(f.impact) + '</div>' : '';
  var srcLabel = {
    'manual_review': 'Manual Review',
    'static_analysis': 'Static Analysis',
    'threat_model': 'Threat Model',
    'code_quality': 'Code Quality'
  }[f.source] || f.source || '';

  return '<div class="finding-card sev-' + sc + '" ' +
      'data-sev="' + escHtml(f.severity) + '" ' +
      'data-src="' + escHtml(f.source || '') + '" ' +
      'data-title="' + escHtml((f.title || '') + ' ' + (f.id || '') + ' ' + (f.description || '')).toLowerCase() + '">' +
    '<div class="finding-header" onclick="toggleCard(this.parentElement)">' +
      '<span class="sev-badge ' + sc + '">' + escHtml(f.severity) + '</span>' +
      '<span class="finding-id">' + escHtml(f.id) + '</span>' +
      '<span class="finding-title">' + escHtml(f.title) + '</span>' +
      (loc ? '<span class="finding-loc" title="' + escHtml(loc) + '">' + escHtml(loc) + '</span>' : '') +
      '<span class="chevron">&#9658;</span>' +
    '</div>' +
    '<div class="finding-body"><div class="finding-body-inner">' +
      (srcLabel ? '<div class="field"><h4>Source</h4><p>' + escHtml(srcLabel) + '</p></div>' : '') +
      '<div class="field"><h4>Description</h4>' + mdToHtml(f.description) + '</div>' +
      impact +
      '<div class="field"><h4>Recommendation</h4>' + mdToHtml(f.recommendation) + '</div>' +
      refs +
    '</div></div>' +
  '</div>';
}

function toggleCard(card) {
  card.classList.toggle('open');
}

function renderAll() {
  var sev = document.getElementById('filter-sev').value;
  var src = document.getElementById('filter-src').value;
  var q   = document.getElementById('filter-q').value.toLowerCase().trim();

  var visible = FINDINGS.filter(function(f) {
    if (sev && f.severity !== sev) return false;
    if (src && (f.source || '') !== src) return false;
    if (q && !(f.title + ' ' + f.id + ' ' + (f.description || '')).toLowerCase().includes(q)) return false;
    return true;
  });

  document.getElementById('findings-list').innerHTML = visible.map(buildCard).join('');
  document.getElementById('finding-count').textContent = visible.length + ' of ' + FINDINGS.length + ' findings';
}

document.getElementById('filter-sev').addEventListener('change', renderAll);
document.getElementById('filter-src').addEventListener('change', renderAll);
document.getElementById('filter-q').addEventListener('input', renderAll);
renderAll();
</script>

</body>
</html>
"""

_INDEX_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Smart Contract Audit Reports</title>
<style>
:root {
  --bg: #0d1117; --surface: #161b22; --surface2: #21262d;
  --border: #30363d; --text: #e6edf3; --muted: #8b949e;
  --accent: #58a6ff; --critical: #ff4444; --high: #ff8c00;
  --medium: #d4a017; --low: #4488ff; --info: #6e7681;
  --radius: 8px; --max-w: 900px;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  font-size: 15px; line-height: 1.6; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 32px 24px; text-align: center; }
header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; }
header p { color: var(--muted); font-size: 14px; }
.content { max-width: var(--max-w); margin: 0 auto; padding: 32px 24px; }
.audit-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr)); gap: 16px; }
.audit-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 22px;
  transition: border-color .15s;
  display: block;
  color: var(--text);
}
.audit-card:hover { border-color: var(--accent); text-decoration: none; }
.audit-card h3 { font-size: 17px; font-weight: 600; margin-bottom: 6px; }
.audit-card .date { font-size: 13px; color: var(--muted); margin-bottom: 14px; }
.pill-row { display: flex; gap: 8px; flex-wrap: wrap; }
.pill {
  padding: 3px 10px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 700;
}
.pill.critical { background: #2d0000; color: var(--critical); border: 1px solid var(--critical); }
.pill.high     { background: #2d1800; color: var(--high);     border: 1px solid var(--high); }
.pill.medium   { background: #2d2200; color: var(--medium);   border: 1px solid var(--medium); }
.pill.low      { background: #00112d; color: var(--low);      border: 1px solid var(--low); }
.pill.info     { background: var(--surface2); color: var(--info); border: 1px solid var(--border); }
.empty { text-align: center; color: var(--muted); padding: 64px 0; }
footer { border-top: 1px solid var(--border); padding: 24px; text-align: center; color: var(--muted); font-size: 13px; }
footer a { color: var(--muted); }
</style>
</head>
<body>
<header>
  <h1>Smart Contract Audit Reports</h1>
  <p>Generated by <a href="https://github.com/{{github_repo}}">SCAuditCrew</a></p>
</header>
<div class="content">
  {{audit_cards_html}}
</div>
<footer>
  Generated on {{generated_date}} &middot; <a href="https://github.com/{{github_repo}}">SCAuditCrew</a>
</footer>
</body>
</html>
"""

# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------

def _render(template: str, data: dict) -> str:
    """Replace {{key}} placeholders; missing keys become empty string."""
    return re.sub(
        r"\{\{(\w+)\}\}",
        lambda m: str(data.get(m.group(1), "")),
        template,
    )


# ---------------------------------------------------------------------------
# Data parsing
# ---------------------------------------------------------------------------

_OUTPUT_DIR_RE = re.compile(r"^(.+)_(\d{4}-\d{2}-\d{2})$")


def _extract_json_block(text: str) -> str:
    """Extract JSON from text, handling optional ```json fences and scratchpad prefix."""
    match = re.search(r"```(?:json)?\s*\n?([\s\S]*?)\n?```", text)
    if match:
        return match.group(1).strip()
    # Fall back: strip only leading/trailing fences (backward compat)
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*\n?", "", text)
    text = re.sub(r"\n?```\s*$", "", text)
    return text.strip()


def parse_peer_review(output_dir: Path) -> tuple[list[dict], dict] | None:
    """Parse 05_peer_review.md → (findings, stats). Returns None on failure."""
    path = output_dir / "05_peer_review.md"
    if not path.exists():
        return None
    try:
        raw = _extract_json_block(path.read_text(encoding="utf-8"))
        data = json.loads(raw)
        findings_raw: list[dict] = data.get("deduplicated_findings", [])
        # Filter out stub duplicate references (only have id + duplicate_of)
        findings = [
            f for f in findings_raw
            if f.get("title") or f.get("description")
        ]
        stats: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings:
            sev = f.get("severity", "Informational")
            if sev in stats:
                stats[sev] += 1
            else:
                stats["Informational"] += 1
        return findings, stats
    except Exception as exc:
        print(f"  [warn] Could not parse {path.name}: {exc}", file=sys.stderr)
        return None


def parse_findings_json(output_dir: Path) -> tuple[list[dict], dict] | None:
    """Parse findings.json (fixer-subset) as fallback. Returns None on failure."""
    path = output_dir / "findings.json"
    if not path.exists():
        return None
    try:
        findings_raw: list[dict] = json.loads(path.read_text(encoding="utf-8"))
        stats: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for f in findings_raw:
            sev = f.get("severity", "Informational")
            stats[sev] = stats.get(sev, 0) + 1
        return findings_raw, stats
    except Exception as exc:
        print(f"  [warn] Could not parse {path.name}: {exc}", file=sys.stderr)
        return None


def _normalise_finding(raw: dict, from_peer_review: bool) -> dict:
    """Normalise a raw finding dict to a consistent schema."""
    if from_peer_review:
        loc = raw.get("location") or {}
        file_path = loc.get("file", "")
    else:
        file_path = raw.get("file", "")

    # Normalise Windows backslashes
    file_path = file_path.replace("\\", "/")

    return {
        "id":             raw.get("id", ""),
        "title":          raw.get("title", "Untitled"),
        "severity":       raw.get("severity", "Informational"),
        "category":       raw.get("category", ""),
        "source":         raw.get("source", ""),
        "file":           file_path,
        "line_start":     raw.get("line_start") if not from_peer_review
                          else (raw.get("location") or {}).get("line_start"),
        "line_end":       raw.get("line_end") if not from_peer_review
                          else (raw.get("location") or {}).get("line_end"),
        "function":       raw.get("function", "") if not from_peer_review
                          else (raw.get("location") or {}).get("function", ""),
        "description":    raw.get("description", ""),
        "impact":         raw.get("impact", ""),
        "recommendation": raw.get("recommendation", ""),
        "references":     raw.get("references", []),
        "confidence":     raw.get("confidence", 1.0),
        "needs_poc":      raw.get("needs_poc", False),
        "status":         raw.get("status", "Open"),
    }


def load_audit(output_dir: Path) -> tuple[list[dict], dict, dict]:
    """
    Load audit data from output directory.
    Returns (findings, stats, report_sections).
    Prefers 05_peer_review.md; falls back to findings.json.
    """
    result = parse_peer_review(output_dir)
    from_peer_review = True
    if result is None:
        result = parse_findings_json(output_dir)
        from_peer_review = False
    if result is None:
        print(f"  [warn] No findings data found in {output_dir}", file=sys.stderr)
        findings_raw, stats = [], {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    else:
        findings_raw, stats = result

    findings = [_normalise_finding(f, from_peer_review) for f in findings_raw]
    report_sections = parse_audit_report_md(output_dir)
    return findings, stats, report_sections


def parse_audit_report_md(output_dir: Path) -> dict:
    """
    Extract named sections from audit_report.md.
    Returns dict with keys: executive_summary, scope_rows, methodology, recommendations.
    """
    path = output_dir / "audit_report.md"
    empty = {"executive_summary": "", "scope_rows": [], "methodology": "", "recommendations": ""}
    if not path.exists():
        return empty

    text = path.read_text(encoding="utf-8")

    def extract_section(name: str) -> str:
        pattern = rf"##\s+{re.escape(name)}\s*\n([\s\S]*?)(?=\n##\s|\Z)"
        m = re.search(pattern, text)
        return m.group(1).strip() if m else ""

    # Scope: extract table rows (skip header and separator lines)
    scope_text = extract_section("Scope")
    scope_rows = []
    for line in scope_text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            continue
        if re.match(r"^\|[\s:|-]+\|", line):
            continue  # separator line
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) >= 1 and cells[0].lower() in ("file", ""):
            continue  # header row
        scope_rows.append(cells)

    # Recommendations: numbered list items
    rec_text = extract_section("General Recommendations")

    return {
        "executive_summary": extract_section("Executive Summary"),
        "scope_rows":        scope_rows,
        "methodology":       extract_section("Methodology"),
        "recommendations":   rec_text,
    }


# ---------------------------------------------------------------------------
# HTML rendering helpers
# ---------------------------------------------------------------------------

def _paragraphs(text: str) -> str:
    """Wrap plain text in <p> tags (split on double newline)."""
    if not text:
        return "<p><em>Not available.</em></p>"
    paras = re.split(r"\n{2,}", text.strip())
    return "".join(f"<p>{html.escape(p.strip())}</p>" for p in paras if p.strip())


def _scope_rows_html(rows: list[list[str]]) -> str:
    if not rows:
        return '<tr><td colspan="3"><em>Not available.</em></td></tr>'
    out = []
    for cells in rows:
        # Pad to 3 columns
        while len(cells) < 3:
            cells.append("")
        out.append(
            "<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in cells[:3]) + "</tr>"
        )
    return "\n".join(out)


def _recommendations_html(text: str) -> str:
    """Convert numbered recommendation list from markdown to <li> items."""
    if not text:
        return "<li>No general recommendations recorded.</li>"
    items = re.split(r"\n(?=\d+\.\s)", text.strip())
    out = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        # Strip leading "N. "
        item = re.sub(r"^\d+\.\s+", "", item)
        # Bold the first sentence (up to first colon or period)
        item = re.sub(r"^(\*\*[^*]+\*\*)", r"\1", item)
        # Convert **bold** markers
        item = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", item)
        out.append(f"<li>{item}</li>")
    return "\n".join(out) if out else "<li>No general recommendations recorded.</li>"


# ---------------------------------------------------------------------------
# HTML report generation
# ---------------------------------------------------------------------------

def _slug(project_name: str, audit_date: str) -> str:
    safe = re.sub(r"[^\w-]", "-", project_name).lower().strip("-")
    return f"{safe}-{audit_date}"


def generate_html_report(
    findings: list[dict],
    stats: dict,
    report_sections: dict,
    project_name: str,
    audit_date: str,
    github_repo: str = "",
) -> str:
    data = {
        "project_name":          html.escape(project_name),
        "audit_date":            html.escape(audit_date),
        "chain_badge":           "",
        "protocol_badge":        "",
        "stat_critical":         str(stats.get("Critical", 0)),
        "stat_high":             str(stats.get("High", 0)),
        "stat_medium":           str(stats.get("Medium", 0)),
        "stat_low":              str(stats.get("Low", 0)),
        "stat_info":             str(stats.get("Informational", 0)),
        "executive_summary_html": _paragraphs(report_sections.get("executive_summary", "")),
        "scope_rows_html":       _scope_rows_html(report_sections.get("scope_rows", [])),
        "methodology_html":      _paragraphs(report_sections.get("methodology", "")),
        "recommendations_html":  _recommendations_html(report_sections.get("recommendations", "")),
        "findings_json":         json.dumps(findings, ensure_ascii=False, indent=None),
        "generated_date":        str(date.today()),
        "github_repo":           html.escape(github_repo),
    }
    return _render(_REPORT_TEMPLATE, data)


def generate_index_html(
    audits: list[dict],
    github_repo: str = "",
) -> str:
    """Generate the root index listing all audits."""
    if not audits:
        cards_html = '<div class="empty"><p>No audit reports found.</p></div>'
    else:
        cards = []
        for a in sorted(audits, key=lambda x: x["audit_date"], reverse=True):
            stats = a.get("stats", {})
            pills = ""
            for sev, cls in [("Critical","critical"),("High","high"),("Medium","medium"),("Low","low"),("Informational","info")]:
                n = stats.get(sev, 0)
                if n:
                    pills += f'<span class="pill {cls}">{n} {sev}</span>'
            no_findings = "<span style=\"color:var(--muted)\">No findings</span>"
            cards.append(
                f'<a class="audit-card" href="{html.escape(a["slug"])}/index.html">'
                f'<h3>{html.escape(a["project_name"])}</h3>'
                f'<div class="date">📅 {html.escape(a["audit_date"])}</div>'
                f'<div class="pill-row">{pills or no_findings}</div>'
                f'</a>'
            )
        cards_html = '<div class="audit-grid">' + "\n".join(cards) + "</div>"

    data = {
        "audit_cards_html": cards_html,
        "generated_date":   str(date.today()),
        "github_repo":      html.escape(github_repo),
    }
    return _render(_INDEX_TEMPLATE, data)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Generate GitHub Pages HTML reports from sc-audit-crew output directories.",
    )
    parser.add_argument(
        "--output-dir",
        default="output",
        help="Directory containing audit output subdirectories (default: output/)",
    )
    parser.add_argument(
        "--pages-dir",
        default="_site",
        help="Directory to write generated HTML into (default: _site/)",
    )
    parser.add_argument(
        "--github-repo",
        default="",
        help="GitHub repo slug (user/repo) for footer links, e.g. myuser/sc-audit-crew",
    )
    parser.add_argument(
        "--filter-dirs",
        nargs="*",
        default=None,
        metavar="DIR",
        help=(
            "Only regenerate HTML for these output subdirectory names "
            "(e.g. CerebrumStaking_2026-03-26). "
            "The root index.html is always rebuilt from all output dirs."
        ),
    )
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    pages_dir  = Path(args.pages_dir)

    if not output_dir.exists():
        print(f"Error: output directory '{output_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)

    pages_dir.mkdir(parents=True, exist_ok=True)

    # Discover all valid audit directories: {Name}_{YYYY-MM-DD}
    all_audit_dirs = sorted(
        d for d in output_dir.iterdir()
        if d.is_dir() and _OUTPUT_DIR_RE.match(d.name)
    )

    if not all_audit_dirs:
        print(f"No audit directories found in '{output_dir}'.", file=sys.stderr)

    # Determine which dirs to regenerate HTML for
    filter_set = set(args.filter_dirs) if args.filter_dirs else None
    if filter_set:
        regen_dirs = [d for d in all_audit_dirs if d.name in filter_set]
        skip_dirs  = [d for d in all_audit_dirs if d.name not in filter_set]
        print(f"Regenerating {len(regen_dirs)} report(s), skipping {len(skip_dirs)}.")
    else:
        regen_dirs = all_audit_dirs

    audits_meta = []
    generated = 0

    for audit_dir in all_audit_dirs:
        m = _OUTPUT_DIR_RE.match(audit_dir.name)
        if not m:
            continue
        project_name = m.group(1).replace("_", " ")
        audit_date   = m.group(2)
        slug         = _slug(project_name, audit_date)

        if audit_dir in regen_dirs:
            print(f"  Generating {audit_dir.name} -> {slug}/")
            findings, stats, sections = load_audit(audit_dir)

            report_html = generate_html_report(
                findings=findings,
                stats=stats,
                report_sections=sections,
                project_name=project_name,
                audit_date=audit_date,
                github_repo=args.github_repo,
            )

            out_dir = pages_dir / slug
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "index.html").write_text(report_html, encoding="utf-8")
            print(f"    -> {out_dir / 'index.html'} ({len(findings)} findings)")
            generated += 1
        else:
            # Still need stats for the index — load only the lightweight parts
            _, stats, _ = load_audit(audit_dir)
            print(f"  Skipping  {audit_dir.name} (not changed)")

        audits_meta.append({
            "project_name": project_name,
            "audit_date":   audit_date,
            "slug":         slug,
            "stats":        stats,
        })

    # Root index is always rebuilt
    index_html = generate_index_html(audits_meta, github_repo=args.github_repo)
    (pages_dir / "index.html").write_text(index_html, encoding="utf-8")
    print(f"\nGenerated {generated} report(s) -> {pages_dir}/")
    print(f"Root index -> {pages_dir / 'index.html'}")


if __name__ == "__main__":
    main()
