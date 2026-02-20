"""
Report generator — produces JSON and a self-contained HTML dashboard.
"""
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional
from collections import Counter

from core.models import Finding

_SEV_COLORS_HEX = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#ca8a04",
    "LOW":      "#0891b2",
    "INFO":     "#2563eb",
    "UNKNOWN":  "#6b7280",
}


def save_json(findings: List[Finding], output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    data = build_report_data(findings)

    path.write_text(json.dumps(data, indent=2))
    return str(path)


def build_report_data(findings: List[Finding], generated_at: Optional[str] = None) -> Dict:
    """Build a machine-readable payload for reports and agent integrations."""
    return {
        "generated_at": generated_at or datetime.datetime.utcnow().isoformat() + "Z",
        "total_findings": len(findings),
        "severity_counts": _count_severities(findings),
        "findings": [_finding_to_dict(f) for f in _sorted_findings(findings)],
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "title": f.title,
        "description": f.description,
        "scanner": f.scanner,
        "severity": f.worst_severity().value,
        "location": f.location,
        "line_number": f.line_number,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "cve_refs": [
            {
                "cve_id": r.cve_id,
                "description": r.description,
                "cvss_score": r.cvss_score,
                "cvss_vector": r.cvss_vector,
                "severity": r.severity.value,
                "nvd_url": r.nvd_url,
                "mitre_url": r.mitre_url,
                "published": r.published,
                "fixed_versions": r.fixed_versions,
            }
            for r in f.cve_refs
        ],
    }



def save_html(findings: List[Finding], output_path: str, scan_target: str = "") -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    sev_counts = _count_severities(findings)
    sorted_findings = _sorted_findings(findings)
    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    findings_html = "\n".join(_finding_row(f, i) for i, f in enumerate(sorted_findings))
    sev_bars = _severity_bars(sev_counts, len(findings))

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScan Report</title>
<style>
  :root {{
    --bg: #0f1117; --surface: #1a1d27; --border: #2d3148;
    --text: #e2e8f0; --dim: #8892a4; --accent: #60a5fa;
    --crit: #dc2626; --high: #ea580c; --med: #ca8a04;
    --low: #0891b2; --info: #2563eb; --unk: #6b7280;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
  header {{ margin-bottom: 32px; }}
  header h1 {{ font-size: 28px; font-weight: 700; color: var(--accent); }}
  header p {{ color: var(--dim); margin-top: 4px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .stat-card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 16px 20px; }}
  .stat-card .label {{ color: var(--dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }}
  .stat-card .value {{ font-size: 32px; font-weight: 700; margin-top: 4px; }}
  .stat-card.crit .value {{ color: var(--crit); }}
  .stat-card.high .value {{ color: var(--high); }}
  .stat-card.med  .value {{ color: var(--med); }}
  .stat-card.low  .value {{ color: var(--low); }}
  .stat-card.info .value {{ color: var(--info); }}
  .stat-card.total .value {{ color: var(--accent); }}
  .bar-section {{ margin-bottom: 32px; }}
  .bar-row {{ display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }}
  .bar-label {{ width: 80px; font-size: 12px; color: var(--dim); text-align: right; }}
  .bar-track {{ flex: 1; background: var(--border); border-radius: 4px; height: 8px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
  .bar-count {{ width: 32px; text-align: right; font-size: 12px; color: var(--dim); }}
  .filters {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 20px; }}
  .filter-btn {{
    padding: 4px 12px; border-radius: 9999px; border: 1px solid var(--border);
    background: var(--surface); color: var(--text); cursor: pointer; font-size: 12px;
    transition: background 0.2s;
  }}
  .filter-btn:hover, .filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
  .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 10px; margin-bottom: 12px; overflow: hidden; }}
  .finding-header {{
    display: flex; align-items: center; gap: 12px; padding: 14px 18px;
    cursor: pointer; user-select: none;
  }}
  .finding-header:hover {{ background: rgba(255,255,255,0.03); }}
  .badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 700; letter-spacing: 0.05em; white-space: nowrap;
  }}
  .badge.CRITICAL {{ background: var(--crit); color: #fff; }}
  .badge.HIGH     {{ background: var(--high); color: #fff; }}
  .badge.MEDIUM   {{ background: var(--med);  color: #000; }}
  .badge.LOW      {{ background: var(--low);  color: #fff; }}
  .badge.INFO     {{ background: var(--info); color: #fff; }}
  .badge.UNKNOWN  {{ background: var(--unk);  color: #fff; }}
  .scanner-badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; background: var(--border); color: var(--dim);
  }}
  .finding-title {{ font-weight: 600; flex: 1; }}
  .finding-loc {{ color: var(--dim); font-size: 12px; font-family: monospace; }}
  .finding-body {{ padding: 0 18px 16px 18px; border-top: 1px solid var(--border); display: none; }}
  .finding-body.open {{ display: block; }}
  .finding-body p {{ margin-top: 12px; color: var(--dim); }}
  .finding-body .evidence {{
    margin-top: 10px; background: #0a0c12; border-radius: 6px; padding: 10px 14px;
    font-family: monospace; font-size: 12px; color: #f87171; overflow-x: auto; white-space: pre-wrap;
  }}
  .finding-body .remediation {{
    margin-top: 10px; background: rgba(34,197,94,0.07); border-left: 3px solid #22c55e;
    padding: 10px 14px; border-radius: 0 6px 6px 0; color: #86efac; font-size: 13px;
  }}
  .cve-table {{ width: 100%; border-collapse: collapse; margin-top: 14px; font-size: 13px; }}
  .cve-table th {{ text-align: left; color: var(--dim); font-weight: 600; padding: 4px 8px; border-bottom: 1px solid var(--border); }}
  .cve-table td {{ padding: 6px 8px; border-bottom: 1px solid rgba(255,255,255,0.04); }}
  .cve-table a {{ color: var(--accent); text-decoration: none; }}
  .cve-table a:hover {{ text-decoration: underline; }}
  footer {{ margin-top: 48px; color: var(--dim); font-size: 12px; text-align: center; }}
  .expand-icon {{ color: var(--dim); font-size: 12px; }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>🔐 VulnScan Report</h1>
    <p>Target: <strong>{_esc(scan_target or "N/A")}</strong> &nbsp;·&nbsp; Generated: {generated_at}</p>
  </header>

  <div class="stats">
    <div class="stat-card total"><div class="label">Total</div><div class="value">{len(findings)}</div></div>
    <div class="stat-card crit"><div class="label">Critical</div><div class="value">{sev_counts.get("CRITICAL", 0)}</div></div>
    <div class="stat-card high"><div class="label">High</div><div class="value">{sev_counts.get("HIGH", 0)}</div></div>
    <div class="stat-card med"><div class="label">Medium</div><div class="value">{sev_counts.get("MEDIUM", 0)}</div></div>
    <div class="stat-card low"><div class="label">Low</div><div class="value">{sev_counts.get("LOW", 0)}</div></div>
    <div class="stat-card info"><div class="label">Info</div><div class="value">{sev_counts.get("INFO", 0)}</div></div>
  </div>

  <div class="bar-section">
    {sev_bars}
  </div>

  <div class="filters">
    <button class="filter-btn active" onclick="filterFindings(event, 'ALL')">All</button>
    <button class="filter-btn" onclick="filterFindings(event, 'CRITICAL')">Critical</button>
    <button class="filter-btn" onclick="filterFindings(event, 'HIGH')">High</button>
    <button class="filter-btn" onclick="filterFindings(event, 'MEDIUM')">Medium</button>
    <button class="filter-btn" onclick="filterFindings(event, 'LOW')">Low</button>
    <button class="filter-btn" onclick="filterFindings(event, 'dependency')">📦 Dependencies</button>
    <button class="filter-btn" onclick="filterFindings(event, 'sast')">🔍 SAST</button>
    <button class="filter-btn" onclick="filterFindings(event, 'network')">🌐 Network</button>
  </div>

  <div id="findings-list">
    {findings_html}
  </div>

  <footer>
    Generated by <strong>VulnScan</strong> · CVE data from NVD, OSV, and MITRE
  </footer>
</div>

<script>
function toggleFinding(id) {{
  const body = document.getElementById('body-' + id);
  const icon = document.getElementById('icon-' + id);
  body.classList.toggle('open');
  icon.textContent = body.classList.contains('open') ? '▲' : '▼';
}}
function filterFindings(evt, filter) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  if (evt && evt.target) {{
    evt.target.classList.add('active');
  }}
  document.querySelectorAll('.finding').forEach(el => {{
    const sev = el.dataset.severity;
    const scanner = el.dataset.scanner;
    if (filter === 'ALL' || sev === filter || scanner === filter) {{
      el.style.display = '';
    }} else {{
      el.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>"""

    path.write_text(html)
    return str(path)


def _finding_row(finding: Finding, idx: int) -> str:
    sev = finding.worst_severity().value
    loc_suffix = f":{finding.line_number}" if finding.line_number else ""
    scanner_icons = {"dependency": "📦", "sast": "🔍", "network": "🌐"}
    icon = scanner_icons.get(finding.scanner, "⚠️")

    evidence_html = ""
    if finding.evidence:
        ev = _esc(finding.evidence)
        evidence_html = f'<div class="evidence">{ev}</div>'

    remediation_html = ""
    if finding.remediation:
        rem = _esc(finding.remediation)
        remediation_html = f'<div class="remediation">💡 {rem}</div>'

    cve_rows = ""
    if finding.cve_refs:
        header = "<tr><th>CVE / ID</th><th>CVSS</th><th>Severity</th><th>Published</th><th>Links</th></tr>"
        rows = ""
        for ref in sorted(finding.cve_refs, key=lambda r: r.severity.sort_key):
            score = f"{ref.cvss_score:.1f}" if ref.cvss_score is not None else "—"
            sev_badge = f'<span class="badge {ref.severity.value}">{ref.severity.value}</span>'
            links = []
            if ref.nvd_url:
                links.append(f'<a href="{ref.nvd_url}" target="_blank">NVD</a>')
            if ref.mitre_url:
                links.append(f'<a href="{ref.mitre_url}" target="_blank">MITRE</a>')
            rows += f"<tr><td>{_esc(ref.cve_id)}</td><td>{score}</td><td>{sev_badge}</td><td>{ref.published or '—'}</td><td>{' · '.join(links)}</td></tr>"
        cve_rows = f'<table class="cve-table">{header}{rows}</table>'

    return f"""
<div class="finding" data-severity="{sev}" data-scanner="{finding.scanner}">
  <div class="finding-header" onclick="toggleFinding({idx})">
    <span class="badge {sev}">{sev}</span>
    <span class="scanner-badge">{icon} {finding.scanner}</span>
    <span class="finding-title">{_esc(finding.title)}</span>
    <span class="finding-loc">{_esc(finding.location)}{_esc(loc_suffix)}</span>
    <span class="expand-icon" id="icon-{idx}">▼</span>
  </div>
  <div class="finding-body" id="body-{idx}">
    <p>{_esc(finding.description)}</p>
    {evidence_html}
    {remediation_html}
    {cve_rows}
  </div>
</div>"""


def _severity_bars(sev_counts: dict, total: int) -> str:
    bars = ""
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    for sev in order:
        count = sev_counts.get(sev, 0)
        pct = (count / total * 100) if total > 0 else 0
        color = _SEV_COLORS_HEX.get(sev, "#6b7280")
        bars += f"""
<div class="bar-row">
  <div class="bar-label">{sev}</div>
  <div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%;background:{color};"></div></div>
  <div class="bar-count">{count}</div>
</div>"""
    return bars


def _count_severities(findings: List[Finding]) -> dict:
    counts: Counter = Counter()
    for f in findings:
        counts[f.worst_severity().value] += 1
    return dict(counts)


def _sorted_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.worst_severity().sort_key,
            f.scanner,
            f.location,
            f.title,
            f.line_number or 0,
        ),
    )


def _esc(text: Optional[str]) -> str:
    """HTML-escape a string."""
    safe_text = "" if text is None else str(text)
    return (
        safe_text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
    )


# ---------------------------------------------------------------------------
# SARIF 2.1 export (GitHub Code Scanning, GitLab SAST, etc.)
# ---------------------------------------------------------------------------

def build_sarif(findings: List[Finding], generated_at: Optional[str] = None) -> dict:
    """Build a SARIF 2.1.0 log for integration with GitHub Code Scanning and GitLab SAST."""
    from datetime import datetime
    ts = generated_at or datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    rules_seen: dict = {}
    results = []
    for f in _sorted_findings(findings):
        rule_id = (f.scanner + "/" + (f.title or "finding")).replace(" ", "-")[:100]
        if rule_id not in rules_seen:
            rules_seen[rule_id] = {
                "id": rule_id,
                "name": f.title or "Finding",
                "shortDescription": {"text": (f.title or "Finding")[:200]},
                "fullDescription": {"text": (f.description or "")[:1000]},
                "defaultConfiguration": {"level": _severity_to_sarif_level(f.worst_severity().value)},
                "help": {"text": f.remediation or f.description or ""},
            }
        result = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(f.worst_severity().value),
            "message": {"text": (f.title or "") + ": " + ((f.description or "")[:300])},
        }
        loc = {"uri": f.location or "file", "uriBaseId": "%SRCROOT%"}
        if f.line_number:
            loc["region"] = {"startLine": f.line_number}
        result["locations"] = [{"physicalLocation": loc}]
        results.append(result)
    rules = []
    for r in rules_seen.values():
        rule = {
            "id": r["id"],
            "name": r["name"],
            "shortDescription": r["shortDescription"],
            "fullDescription": r["fullDescription"],
            "defaultConfiguration": r["defaultConfiguration"],
            "help": r["help"],
        }
        rules.append(rule)
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "VulnScan",
                    "version": "1.0.0",
                    "informationUri": "https://github.com/your-org/o-vuln",
                    "rules": rules,
                }
            },
            "results": results,
            "invocations": [{"executionSuccessful": True, "endTimeUtc": ts}],
        }]
    }


def _severity_to_sarif_level(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "warning", "INFO": "note", "UNKNOWN": "none"}.get(severity, "none")


def save_sarif(findings: List[Finding], output_path: str, generated_at: Optional[str] = None) -> str:
    """Write SARIF 2.1 to a file. Use for GitHub Code Scanning / GitLab SAST."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sarif = build_sarif(findings, generated_at=generated_at)
    path.write_text(json.dumps(sarif, indent=2))
    return str(path)


# ---------------------------------------------------------------------------
# CSV and Markdown export
# ---------------------------------------------------------------------------

def save_csv(findings: List[Finding], output_path: str) -> str:
    """Write findings to a CSV file."""
    import csv
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Severity", "Scanner", "Title", "Location", "Line", "Description", "Remediation", "CVE IDs"])
        for fnd in _sorted_findings(findings):
            cve_ids = ",".join(r.cve_id for r in fnd.cve_refs) if fnd.cve_refs else ""
            w.writerow([
                fnd.worst_severity().value,
                fnd.scanner,
                fnd.title or "",
                fnd.location or "",
                fnd.line_number or "",
                (fnd.description or "")[:500],
                (fnd.remediation or "")[:300],
                cve_ids,
            ])
    return str(path)


def save_md(findings: List[Finding], output_path: str, scan_target: str = "") -> str:
    """Write findings to a Markdown file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# VulnScan Report",
        "",
        f"**Generated:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC",
        f"**Target:** {scan_target or '.'}",
        f"**Total findings:** {len(findings)}",
        "",
        "| Severity | Scanner | Title | Location |",
        "|----------|---------|-------|----------|",
    ]
    for fnd in _sorted_findings(findings):
        sev = fnd.worst_severity().value
        loc = (fnd.location or "") + (f":{fnd.line_number}" if fnd.line_number else "")
        title = (fnd.title or "").replace("|", "\\|")
        lines.append(f"| {sev} | {fnd.scanner} | {title[:80]} | {loc[:60]} |")
    path.write_text("\n".join(lines), encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------------------
# SBOM (CycloneDX 1.4)
# ---------------------------------------------------------------------------

def build_sbom_cyclonedx(packages: List[dict], generated_at: Optional[str] = None) -> dict:
    """Build a minimal CycloneDX 1.4 JSON SBOM from a list of {name, version, ecosystem}."""
    ts = generated_at or datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    # Map ecosystem to PURL type
    purl_type = {"PyPI": "pypi", "npm": "npm", "crates.io": "cargo", "Go": "golang", "RubyGems": "gem"}
    components = []
    for p in packages:
        name = p.get("name", "")
        version = p.get("version", "")
        ecosystem = p.get("ecosystem", "")
        ptype = purl_type.get(ecosystem, "generic")
        purl = f"pkg:{ptype}/{name}@{version}" if name and version else None
        components.append({
            "type": "library",
            "name": name,
            "version": version,
            "purl": purl,
            "description": f"{name} {version} ({ecosystem})" if ecosystem else None,
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [{"vendor": "VulnScan", "name": "vulnscan", "version": "1.0.0"}],
        },
        "components": components,
    }


def save_sbom(packages: List[dict], output_path: str, generated_at: Optional[str] = None) -> str:
    """Write CycloneDX 1.4 JSON SBOM. Pass packages from scanners.dependency.get_packages(path)."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sbom = build_sbom_cyclonedx(packages, generated_at=generated_at)
    path.write_text(json.dumps(sbom, indent=2), encoding="utf-8")
    return str(path)
