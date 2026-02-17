# Copyright 2026 Cisco Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""
Self-contained HTML reporter with inline pipeline flow diagrams.
"""

from __future__ import annotations

import html
from typing import Any

from ...core.models import Finding, Report, ScanResult, Severity
from .markdown_reporter import extract_pipeline_flows

# ---------------------------------------------------------------------------
# Severity → colour mapping
# ---------------------------------------------------------------------------
_SEV_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "INFO": "#6b7280",
}

_VERDICT_COLORS = {
    "MALICIOUS": "#dc2626",
    "SUSPICIOUS": "#ea580c",
    "SAFE": "#16a34a",
    "UNKNOWN": "#6b7280",
}

_EFFORT_BADGES = {
    "LOW": ("Low", "#16a34a"),
    "MEDIUM": ("Medium", "#ca8a04"),
    "HIGH": ("High", "#ea580c"),
}


def _esc(text: str | None) -> str:
    """HTML-escape a string (safe for attributes and text nodes)."""
    return html.escape(str(text or ""), quote=True)


class HTMLReporter:
    """Generates self-contained HTML reports with inline pipeline flow diagrams."""

    def generate_report(self, data: ScanResult | Report) -> str:
        if isinstance(data, ScanResult):
            return self._generate_scan_result_report(data)
        return self._generate_multi_skill_report(data)

    # ------------------------------------------------------------------
    # Single-skill report
    # ------------------------------------------------------------------
    def _generate_scan_result_report(self, result: ScanResult) -> str:
        meta: dict[str, Any] = result.scan_metadata or {}
        risk_assessment = meta.get("meta_risk_assessment", {})
        correlations = meta.get("meta_correlations", [])
        recommendations = meta.get("meta_recommendations", [])

        sev_counts = {
            "CRITICAL": len(result.get_findings_by_severity(Severity.CRITICAL)),
            "HIGH": len(result.get_findings_by_severity(Severity.HIGH)),
            "MEDIUM": len(result.get_findings_by_severity(Severity.MEDIUM)),
            "LOW": len(result.get_findings_by_severity(Severity.LOW)),
            "INFO": len(result.get_findings_by_severity(Severity.INFO)),
        }

        parts: list[str] = []
        parts.append(self._html_head(result.skill_name))
        parts.append('<body>\n<div class="container">')
        parts.append(self._banner(result, risk_assessment))
        parts.append(self._severity_bar(sev_counts))
        if correlations:
            parts.append(self._correlations_section(correlations, result.findings))
        if recommendations:
            parts.append(self._recommendations_section(recommendations))
        parts.append(self._findings_table(result.findings))
        parts.append("</div>")
        parts.append(self._scripts())
        parts.append("</body>\n</html>")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Multi-skill report (lightweight fallback)
    # ------------------------------------------------------------------
    def _generate_multi_skill_report(self, report: Report) -> str:
        parts: list[str] = []
        parts.append(self._html_head("Skills Security Scan"))
        parts.append('<body>\n<div class="container">')
        parts.append(f"<h1>Skills Security Scan ({report.total_skills_scanned} skills)</h1>")
        parts.append(f"<p>Total findings: {report.total_findings}</p>")
        for res in report.scan_results:
            parts.append(f"<h2>{_esc(res.skill_name)}</h2>")
            parts.append(self._findings_table(res.findings))
        parts.append("</div>")
        parts.append(self._scripts())
        parts.append("</body>\n</html>")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # HTML head with inline CSS
    # ------------------------------------------------------------------
    def _html_head(self, title: str) -> str:
        return f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_esc(title)} — Skill Scanner Report</title>
<style>
:root {{
  --bg: #0f172a;
  --surface: #1e293b;
  --surface2: #334155;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --accent: #38bdf8;
  --border: #475569;
  --crit: #dc2626;
  --high: #ea580c;
  --med: #ca8a04;
  --low: #2563eb;
  --info: #6b7280;
  --safe: #16a34a;
}}
*,*::before,*::after {{ box-sizing:border-box; margin:0; padding:0; }}
body {{ font-family: 'Inter', system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 2rem 1.5rem; }}
h1 {{ font-size: 1.5rem; margin-bottom: .5rem; }}
h2 {{ font-size: 1.25rem; margin: 2rem 0 .75rem; }}
h3 {{ font-size: 1.1rem; margin-bottom: .5rem; }}
a {{ color: var(--accent); text-decoration: none; }}

/* Banner */
.banner {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem 2rem; margin-bottom: 1.5rem; }}
.banner-top {{ display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }}
.badge {{ display: inline-block; padding: .25rem .75rem; border-radius: 6px; font-weight: 700; font-size: .85rem; color: #fff; text-transform: uppercase; }}
.banner p {{ color: var(--muted); margin-top: .75rem; }}
.banner .reason {{ margin-top: .25rem; font-size: .9rem; color: var(--muted); }}

/* Severity bar */
.sev-bar-container {{ margin-bottom: 2rem; }}
.sev-bar {{ display: flex; height: 28px; border-radius: 8px; overflow: hidden; }}
.sev-bar span {{ display: flex; align-items: center; justify-content: center; font-size: .75rem; font-weight: 600; color: #fff; min-width: 28px; }}
.sev-legend {{ display: flex; gap: 1.25rem; margin-top: .5rem; font-size: .8rem; color: var(--muted); }}
.sev-legend i {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 4px; vertical-align: middle; }}

/* Cards */
.card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 1rem; overflow: hidden; }}
.card-header {{ padding: 1rem 1.25rem; cursor: pointer; display: flex; align-items: center; gap: .75rem; user-select: none; }}
.card-header:hover {{ background: var(--surface2); }}
.card-header .chevron {{ transition: transform .2s; font-size: .75rem; color: var(--muted); }}
.card.open .card-header .chevron {{ transform: rotate(90deg); }}
.card-body {{ display: none; padding: 0 1.25rem 1.25rem; }}
.card.open .card-body {{ display: block; }}
.card-title {{ flex: 1; font-weight: 600; }}
.card-count {{ font-size: .8rem; color: var(--muted); }}

/* Tables */
table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
th, td {{ padding: .5rem .75rem; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ background: var(--surface2); color: var(--muted); font-weight: 600; position: sticky; top: 0; cursor: pointer; white-space: nowrap; }}
th:hover {{ color: var(--text); }}
td {{ color: var(--text); }}
tr:hover td {{ background: rgba(56, 189, 248, .04); }}
.sev-pill {{ padding: 2px 8px; border-radius: 4px; font-size: .75rem; font-weight: 600; color: #fff; }}

/* Recommendations */
.rec-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: .75rem; }}
.rec-card h3 {{ display: flex; align-items: center; gap: .5rem; }}
.rec-card .meta {{ display: flex; gap: 1rem; margin: .5rem 0; font-size: .8rem; color: var(--muted); }}
.effort-badge {{ padding: 2px 8px; border-radius: 4px; font-size: .75rem; font-weight: 600; color: #fff; }}

/* Pipeline flow */
.pipe-flow {{ display: flex; align-items: center; flex-wrap: wrap; gap: .35rem; margin: .75rem 0; padding: .75rem 1rem; background: var(--surface2); border-radius: 8px; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: .8rem; }}
.pipe-step {{ padding: .3rem .6rem; border-radius: 4px; background: var(--surface); border: 1px solid var(--border); white-space: nowrap; }}
.pipe-step.source {{ border-color: #22c55e; color: #4ade80; }}
.pipe-step.sink {{ border-color: var(--crit); color: #f87171; }}
.pipe-arrow {{ color: var(--muted); font-weight: 700; }}

/* Remediation */
.remediation {{ background: var(--surface2); border-radius: 8px; padding: .75rem 1rem; margin-top: .75rem; font-size: .85rem; }}

/* Expandable detail rows */
.detail-row td {{ padding: 0; border-bottom: 1px solid var(--border); }}
.detail-row .detail-wrap {{ max-height: 0; overflow: hidden; transition: max-height .3s ease; }}
.detail-row.show .detail-wrap {{ max-height: 600px; }}
.detail-content {{ padding: .75rem 1rem; }}
.detail-content .desc {{ color: var(--muted); font-size: .85rem; margin-bottom: .5rem; }}
.snippet {{ background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: .75rem 1rem; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: .8rem; white-space: pre-wrap; word-break: break-all; color: #e6edf3; max-height: 200px; overflow-y: auto; }}
tr.expandable {{ cursor: pointer; }}
tr.expandable:hover td {{ background: rgba(56, 189, 248, .06); }}
.expand-icon {{ color: var(--muted); font-size: .7rem; transition: transform .2s; display: inline-block; margin-right: .25rem; }}
tr.expandable.expanded .expand-icon {{ transform: rotate(90deg); }}
</style>
</head>"""

    # ------------------------------------------------------------------
    # Top banner
    # ------------------------------------------------------------------
    def _banner(self, result: ScanResult, ra: dict[str, Any]) -> str:
        verdict = ra.get("skill_verdict", "SAFE" if result.is_safe else "SUSPICIOUS")
        risk = ra.get("risk_level", result.max_severity.value)
        summary = ra.get("summary", "")
        reasoning = ra.get("verdict_reasoning", "")
        v_color = _VERDICT_COLORS.get(verdict, _VERDICT_COLORS["UNKNOWN"])

        lines = [
            '<div class="banner">',
            '  <div class="banner-top">',
            f"    <h1>{_esc(result.skill_name)}</h1>",
            f'    <span class="badge" style="background:{v_color}">{_esc(verdict)}</span>',
            f'    <span class="badge" style="background:{_SEV_COLORS.get(risk, "#6b7280")}">Risk: {_esc(risk)}</span>',
            "  </div>",
        ]
        if summary:
            lines.append(f"  <p>{_esc(summary)}</p>")
        if reasoning:
            lines.append(f'  <p class="reason"><strong>Reasoning:</strong> {_esc(reasoning)}</p>')
        lines.append(
            f"  <p>Scan duration: {result.scan_duration_seconds:.2f}s"
            f" &mdash; {len(result.findings)} findings &mdash; "
            f"{result.timestamp.isoformat()}</p>"
        )
        lines.append("</div>")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Stacked severity bar
    # ------------------------------------------------------------------
    def _severity_bar(self, counts: dict[str, int]) -> str:
        total = sum(counts.values()) or 1
        bar_parts: list[str] = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts.get(sev, 0)
            if n == 0:
                continue
            pct = max(n / total * 100, 4)  # min 4% so label fits
            color = _SEV_COLORS.get(sev, "#6b7280")
            bar_parts.append(f'<span style="width:{pct:.1f}%;background:{color}">{n}</span>')
        legend_parts: list[str] = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            n = counts.get(sev, 0)
            color = _SEV_COLORS.get(sev, "#6b7280")
            legend_parts.append(f'<span><i style="background:{color}"></i>{sev}: {n}</span>')

        return (
            '<div class="sev-bar-container">\n'
            f'  <div class="sev-bar">{"".join(bar_parts)}</div>\n'
            f'  <div class="sev-legend">{"".join(legend_parts)}</div>\n'
            "</div>"
        )

    # ------------------------------------------------------------------
    # Correlation groups with inline pipeline flows
    # ------------------------------------------------------------------
    def _correlations_section(self, correlations: list[dict[str, Any]], findings: list[Finding]) -> str:
        parts: list[str] = ["<h2>Attack Correlation Groups</h2>"]
        for i, group in enumerate(correlations):
            name = group.get("group_name", "Correlated Findings")
            severity = group.get("combined_severity", "UNKNOWN")
            indices = group.get("finding_indices", [])
            relationship = group.get("relationship", "")
            remediation = group.get("consolidated_remediation", "")
            sev_color = _SEV_COLORS.get(severity, "#6b7280")

            open_cls = " open" if i == 0 else ""
            parts.append(f'<div class="card{open_cls}" id="corr-{i}">')
            parts.append('  <div class="card-header" onclick="this.parentElement.classList.toggle(\'open\')">')
            parts.append('    <span class="chevron">&#9654;</span>')
            parts.append(f'    <span class="card-title">{_esc(name)}</span>')
            parts.append(f'    <span class="badge" style="background:{sev_color}">{_esc(severity)}</span>')
            parts.append(f'    <span class="card-count">{len(indices)} findings</span>')
            parts.append("  </div>")
            parts.append('  <div class="card-body">')
            if relationship:
                parts.append(f"    <p>{_esc(relationship)}</p>")

            # Inline pipeline taint flows
            chains = extract_pipeline_flows(group, findings)
            for chain in chains:
                parts.append('    <div class="pipe-flow">')
                for si, step in enumerate(chain):
                    cls = "source" if si == 0 else ("sink" if si == len(chain) - 1 else "")
                    parts.append(f'      <span class="pipe-step {cls}">{_esc(step)}</span>')
                    if si < len(chain) - 1:
                        parts.append('      <span class="pipe-arrow">&#10132;</span>')
                parts.append("    </div>")

            # Mini findings table with expandable snippets
            parts.append(f'    <table class="expandable-table" id="corr-tbl-{i}">')
            parts.append(
                "      <tr><th></th><th>#</th><th>Severity</th><th>Rule</th><th>File</th><th>Analyzer</th></tr>"
            )
            for idx in indices:
                if 0 <= idx < len(findings):
                    f = findings[idx]
                    loc = f.file_path or "?"
                    if f.line_number:
                        loc += f":{f.line_number}"
                    sc = _SEV_COLORS.get(f.severity.value, "#6b7280")
                    has_detail = f.snippet or f.description
                    row_cls = ' class="expandable"' if has_detail else ""
                    onclick = ' onclick="toggleDetail(this)"' if has_detail else ""
                    arrow = '<span class="expand-icon">&#9654;</span>' if has_detail else ""
                    parts.append(
                        f"      <tr{row_cls}{onclick}>"
                        f"<td>{arrow}</td>"
                        f"<td>{idx}</td>"
                        f'<td><span class="sev-pill" style="background:{sc}">{_esc(f.severity.value)}</span></td>'
                        f"<td>{_esc(f.rule_id)}</td>"
                        f"<td>{_esc(loc)}</td>"
                        f"<td>{_esc(f.analyzer)}</td>"
                        f"</tr>"
                    )
                    if has_detail:
                        parts.append(
                            '      <tr class="detail-row"><td colspan="6"><div class="detail-wrap"><div class="detail-content">'
                        )
                        if f.description:
                            parts.append(f'<div class="desc">{_esc(f.description)}</div>')
                        if f.snippet:
                            parts.append(f'<div class="snippet">{_esc(f.snippet)}</div>')
                        parts.append("</div></div></td></tr>")
            parts.append("    </table>")
            if remediation:
                parts.append(f'    <div class="remediation"><strong>Remediation:</strong> {_esc(remediation)}</div>')
            parts.append("  </div>")
            parts.append("</div>")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Recommendations
    # ------------------------------------------------------------------
    def _recommendations_section(self, recommendations: list[dict[str, Any]]) -> str:
        parts: list[str] = ["<h2>Recommendations</h2>"]
        for rec in recommendations:
            priority = rec.get("priority", "?")
            title = rec.get("title", "")
            effort = rec.get("effort", "")
            fix = rec.get("fix", "")
            affected = rec.get("affected_findings", [])
            eb_label, eb_color = _EFFORT_BADGES.get(effort, ("?", "#6b7280"))

            parts.append('<div class="rec-card">')
            parts.append(
                f"  <h3>"
                f'<span class="badge" style="background:var(--accent);color:#000">P{priority}</span>'
                f" {_esc(title)}</h3>"
            )
            parts.append(
                f'  <div class="meta">'
                f'<span class="effort-badge" style="background:{eb_color}">{_esc(eb_label)} effort</span>'
                f"<span>{len(affected)} findings affected</span>"
                f"</div>"
            )
            if fix:
                parts.append(f"  <p>{_esc(fix)}</p>")
            parts.append("</div>")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Full findings table
    # ------------------------------------------------------------------
    def _findings_table(self, findings: list[Finding]) -> str:
        if not findings:
            return "<p>No findings.</p>"
        parts: list[str] = ["<h2>All Findings</h2>"]
        parts.append('<table id="findings-table" class="expandable-table">')
        parts.append(
            "<tr>"
            "<th></th>"
            "<th>#</th>"
            "<th>Severity</th>"
            "<th>Category</th>"
            "<th>Rule</th>"
            "<th>Title</th>"
            "<th>File</th>"
            "<th>Analyzer</th>"
            "</tr>"
        )
        for i, f in enumerate(findings):
            loc = f.file_path or ""
            if f.line_number:
                loc += f":{f.line_number}"
            sc = _SEV_COLORS.get(f.severity.value, "#6b7280")
            has_detail = f.snippet or f.description
            row_cls = ' class="expandable"' if has_detail else ""
            onclick = ' onclick="toggleDetail(this)"' if has_detail else ""
            arrow = '<span class="expand-icon">&#9654;</span>' if has_detail else ""
            parts.append(
                f"<tr{row_cls}{onclick}>"
                f"<td>{arrow}</td>"
                f"<td>{i}</td>"
                f'<td><span class="sev-pill" style="background:{sc}">{_esc(f.severity.value)}</span></td>'
                f"<td>{_esc(f.category.value)}</td>"
                f"<td>{_esc(f.rule_id)}</td>"
                f"<td>{_esc(f.title)}</td>"
                f"<td>{_esc(loc)}</td>"
                f"<td>{_esc(f.analyzer)}</td>"
                f"</tr>"
            )
            if has_detail:
                parts.append(
                    '<tr class="detail-row"><td colspan="8"><div class="detail-wrap"><div class="detail-content">'
                )
                if f.description:
                    parts.append(f'<div class="desc">{_esc(f.description)}</div>')
                if f.snippet:
                    parts.append(f'<div class="snippet">{_esc(f.snippet)}</div>')
                parts.append("</div></div></td></tr>")
        parts.append("</table>")
        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Interactive JS (toggle rows, sort table) — zero external deps
    # ------------------------------------------------------------------
    @staticmethod
    def _scripts() -> str:
        return """\
<script>
// Toggle snippet detail row
function toggleDetail(row) {
  row.classList.toggle('expanded');
  const detail = row.nextElementSibling;
  if (detail && detail.classList.contains('detail-row')) {
    detail.classList.toggle('show');
  }
}

// Simple table sort
document.querySelectorAll('#findings-table th').forEach((th, col) => {
  th.addEventListener('click', () => {
    const table = th.closest('table');
    const tbody = table.querySelector('tbody') || table;
    const rows = Array.from(tbody.querySelectorAll('tr')).slice(1);
    const dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
    th.dataset.dir = dir;
    rows.sort((a, b) => {
      const at = a.children[col]?.textContent?.trim() || '';
      const bt = b.children[col]?.textContent?.trim() || '';
      const an = Number(at), bn = Number(bt);
      if (!isNaN(an) && !isNaN(bn)) return dir === 'asc' ? an - bn : bn - an;
      return dir === 'asc' ? at.localeCompare(bt) : bt.localeCompare(at);
    });
    rows.forEach(r => tbody.appendChild(r));
  });
});
</script>"""

    # ------------------------------------------------------------------
    # save_report helper
    # ------------------------------------------------------------------
    def save_report(self, data: ScanResult | Report, output_path: str) -> None:
        report_html = self.generate_report(data)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(report_html)
