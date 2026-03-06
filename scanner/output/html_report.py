"""
Playwright-style HTML report generator.
Creates a single self-contained index.html with embedded CSS/JS.
"""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from pathlib import Path


def _severity_color(severity: str) -> str:
    return {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
    }.get(severity, "#6b7280")


def _severity_bg(severity: str) -> str:
    return {
        "CRITICAL": "#fef2f2",
        "HIGH": "#fff7ed",
        "MEDIUM": "#fefce8",
        "LOW": "#eff6ff",
    }.get(severity, "#f9fafb")


def generate_html_report(findings: list, target: str = "") -> str:
    """Generate a single-file HTML report with embedded CSS and JS."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    def _is_ai(f) -> bool:
        return (
            f.secret_type == "AI Security"
            or f.category == "ai_security"
            or (f.source and str(f.source).startswith("ai:"))
        )

    rows_html = ""
    for idx, f in enumerate(findings, 1):
        color = _severity_color(f.severity)
        bg = _severity_bg(f.severity)
        val_escaped = html.escape(f.matched_value[:60])
        file_escaped = html.escape(str(f.file))
        type_escaped = html.escape(f.secret_type)
        if _is_ai(f):
            type_escaped += ' <span class="ml-badge" title="ML/LLM detection">🤖 ML</span>'
        line_escaped = html.escape(f.line_content.strip()[:120])

        traces_html = ""
        if f.taint_traces:
            traces_items = ""
            for t in f.taint_traces:
                traces_items += f'<div class="trace-item">🔗 {html.escape(t.source_variable)} → {html.escape(t.sink_type)} (line {t.sink_line})</div>'
            traces_html = f'<div class="traces">{traces_items}</div>'

        rows_html += f"""
        <tr class="finding-row" data-severity="{f.severity}">
            <td class="idx">{idx}</td>
            <td><span class="badge" style="background:{color};color:#fff">{f.severity}</span></td>
            <td class="type">{type_escaped}</td>
            <td class="file">{file_escaped}:{f.line_number}</td>
            <td class="score">{f.score}</td>
            <td class="conf">{f.confidence:.2f}</td>
            <td class="value" title="{val_escaped}">{val_escaped}</td>
        </tr>
        <tr class="detail-row" data-severity="{f.severity}" style="display:none">
            <td colspan="7">
                <div class="detail-content" style="border-left:3px solid {color};background:{bg}">
                    <div><strong>Line content:</strong> <code>{line_escaped}</code></div>
                    <div><strong>Entropy:</strong> {f.entropy} | <strong>Category:</strong> {html.escape(f.category)} | <strong>Source:</strong> {html.escape(f.source)}</div>
                    {traces_html}
                </div>
            </td>
        </tr>"""

    # Build container content
    if not findings:
        container_content = '<div class="empty"><div class="icon">✅</div><div>No secrets found</div></div>'
    else:
        container_content = f"""<table>
<thead><tr><th>#</th><th>Severity</th><th>Type</th><th>File</th><th>Score</th><th>Conf</th><th>Value</th></tr></thead>
<tbody>{rows_html}</tbody>
</table>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>☢ Nuclear Scan Report</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#f8fafc; color:#1e293b; }}
.header {{ background:linear-gradient(135deg,#0f172a,#1e293b); color:#fff; padding:24px 32px; }}
.header h1 {{ font-size:24px; margin-bottom:8px; }}
.header .meta {{ color:#94a3b8; font-size:14px; }}
.stats {{ display:flex; gap:16px; padding:16px 32px; background:#fff; border-bottom:1px solid #e2e8f0; flex-wrap:wrap; }}
.stat {{ padding:12px 20px; border-radius:8px; text-align:center; min-width:120px; }}
.stat .count {{ font-size:28px; font-weight:700; }}
.stat .label {{ font-size:12px; text-transform:uppercase; letter-spacing:1px; margin-top:4px; }}
.filters {{ padding:12px 32px; background:#fff; border-bottom:1px solid #e2e8f0; display:flex; gap:8px; align-items:center; }}
.filters label {{ font-size:13px; color:#64748b; margin-right:4px; }}
.filter-btn {{ padding:5px 14px; border:1px solid #e2e8f0; border-radius:6px; background:#fff; cursor:pointer; font-size:13px; transition:all .15s; }}
.filter-btn:hover {{ background:#f1f5f9; }}
.filter-btn.active {{ background:#0f172a; color:#fff; border-color:#0f172a; }}
.container {{ padding:16px 32px; }}
table {{ width:100%; border-collapse:collapse; background:#fff; border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1); }}
th {{ background:#f8fafc; padding:10px 12px; text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:.5px; color:#64748b; border-bottom:2px solid #e2e8f0; }}
td {{ padding:10px 12px; border-bottom:1px solid #f1f5f9; font-size:14px; }}
.finding-row {{ cursor:pointer; transition:background .15s; }}
.finding-row:hover {{ background:#f8fafc; }}
.badge {{ padding:3px 10px; border-radius:12px; font-size:11px; font-weight:600; letter-spacing:.5px; }}
.ml-badge {{ font-size:10px; color:#6366f1; margin-left:4px; }}
.idx {{ color:#94a3b8; width:40px; }}
.file {{ max-width:280px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
.value {{ max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-family:monospace; font-size:12px; }}
.detail-content {{ padding:12px 16px; margin:4px 0; border-radius:4px; font-size:13px; }}
.detail-content div {{ margin-bottom:6px; }}
.detail-content code {{ background:#f1f5f9; padding:2px 6px; border-radius:3px; font-size:12px; }}
.traces {{ margin-top:8px; }}
.trace-item {{ padding:4px 0; color:#64748b; font-size:12px; }}
.empty {{ text-align:center; padding:48px; color:#64748b; }}
.empty .icon {{ font-size:48px; margin-bottom:12px; }}
@media(max-width:768px) {{ .container,.header,.stats,.filters {{ padding:12px 16px; }} .file,.value {{ max-width:120px; }} }}
</style>
</head>
<body>
<div class="header">
    <h1>☢ Nuclear Scan Report</h1>
    <div class="meta">
        Target: <strong>{html.escape(target or 'N/A')}</strong> &nbsp;•&nbsp;
        Generated: {now} &nbsp;•&nbsp;
        Total findings: <strong>{len(findings)}</strong>
    </div>
</div>
<div class="stats">
    <div class="stat" style="background:#fef2f2"><div class="count" style="color:#dc2626">{counts.get('CRITICAL',0)}</div><div class="label" style="color:#dc2626">Critical</div></div>
    <div class="stat" style="background:#fff7ed"><div class="count" style="color:#ea580c">{counts.get('HIGH',0)}</div><div class="label" style="color:#ea580c">High</div></div>
    <div class="stat" style="background:#fefce8"><div class="count" style="color:#ca8a04">{counts.get('MEDIUM',0)}</div><div class="label" style="color:#ca8a04">Medium</div></div>
    <div class="stat" style="background:#eff6ff"><div class="count" style="color:#2563eb">{counts.get('LOW',0)}</div><div class="label" style="color:#2563eb">Low</div></div>
</div>
<div class="filters">
    <label>Filter:</label>
    <button class="filter-btn active" onclick="filterBy('ALL')">All</button>
    <button class="filter-btn" onclick="filterBy('CRITICAL')">Critical</button>
    <button class="filter-btn" onclick="filterBy('HIGH')">High</button>
    <button class="filter-btn" onclick="filterBy('MEDIUM')">Medium</button>
    <button class="filter-btn" onclick="filterBy('LOW')">Low</button>
</div>
<div class="container">
{container_content}
</div>
<script>
document.querySelectorAll('.finding-row').forEach(row => {{
    row.addEventListener('click', () => {{
        const detail = row.nextElementSibling;
        detail.style.display = detail.style.display === 'none' ? '' : 'none';
    }});
}});
function filterBy(sev) {{
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    document.querySelectorAll('.finding-row, .detail-row').forEach(row => {{
        if (sev === 'ALL' || row.dataset.severity === sev) {{
            row.style.display = row.classList.contains('detail-row') ? 'none' : '';
        }} else {{
            row.style.display = 'none';
        }}
    }});
}}
</script>
</body>
</html>"""


def save_html_report(findings: list, target: str = "", output_dir: str = ".nuclear-scan-result") -> Path:
    """Save HTML report to output_dir/index.html. Returns the path."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    report_html = generate_html_report(findings, target)
    report_path = out / "index.html"
    report_path.write_text(report_html, encoding="utf-8")

    # Also save JSON data alongside for programmatic access
    data = []
    for f in findings:
        data.append({
            "file": f.file,
            "line": f.line_number,
            "type": f.secret_type,
            "severity": f.severity,
            "score": f.score,
            "confidence": f.confidence,
            "value": f.matched_value,
            "category": f.category,
            "source": f.source,
            "ai_detection": (
                f.secret_type == "AI Security"
                or f.category == "ai_security"
                or (f.source and str(f.source).startswith("ai:"))
            ),
        })
    json_path = out / "data.json"
    json_path.write_text(json.dumps({"total": len(findings), "findings": data}, indent=2), encoding="utf-8")

    return report_path
