"""Output formatting: terminal table, JSON, and standalone HTML report.

``build_report`` produces the canonical report dict that every output format —
and the backend API — is built from, so the CLI and dashboard always agree.
"""

from __future__ import annotations

import datetime as _dt
import html
import json

from . import __version__
from .scanner import RISK_HIGH, RISK_LOW, RISK_MEDIUM, Finding
from .scorer import band_message, calculate_score, count_by_severity, risk_band

_RISK_ORDER = {RISK_HIGH: 0, RISK_MEDIUM: 1, RISK_LOW: 2}
_RISK_COLOR = {RISK_HIGH: "red", RISK_MEDIUM: "yellow", RISK_LOW: "green"}
_BAND_COLOR = {"Low": "green", "Medium": "yellow", "High": "red", "Critical": "red"}


def build_report(findings: list[Finding], target: str) -> dict:
    """Assemble the canonical report structure from real findings."""
    score = calculate_score(findings)
    band = risk_band(score)
    counts = count_by_severity(findings)
    ordered = sorted(
        findings,
        key=lambda f: (_RISK_ORDER.get(f.risk_level, 9), f.file_path, f.line_number),
    )
    return {
        "tool": "quantumsafe",
        "version": __version__,
        "target": target,
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "risk_score": score,
        "risk_band": band,
        "risk_message": band_message(band),
        "summary": {
            "total_findings": len(findings),
            "high": counts[RISK_HIGH],
            "medium": counts[RISK_MEDIUM],
            "low": counts[RISK_LOW],
        },
        "findings": [f.to_dict() for f in ordered],
    }


# --------------------------------------------------------------------------- #
# Terminal
# --------------------------------------------------------------------------- #


def print_terminal(report: dict) -> None:
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
    except ImportError:  # graceful fallback if rich is unavailable
        _print_plain(report)
        return

    console = Console()
    score = report["risk_score"]
    band = report["risk_band"]
    color = _BAND_COLOR.get(band, "white")

    console.print(
        Panel(
            f"[bold {color}]Quantum Risk Score: {score}/100  ({band})[/bold {color}]\n"
            f"{report['risk_message']}\n\n"
            f"Target: {report['target']}\n"
            f"[red]HIGH: {report['summary']['high']}[/red]   "
            f"[yellow]MEDIUM: {report['summary']['medium']}[/yellow]   "
            f"[green]LOW: {report['summary']['low']}[/green]   "
            f"Total: {report['summary']['total_findings']}",
            title="QuantumSafe Scan",
            border_style=color,
        )
    )

    if not report["findings"]:
        console.print("[green]No quantum-vulnerable cryptography detected.[/green]")
        return

    table = Table(show_lines=False, header_style="bold")
    table.add_column("File", style="cyan", no_wrap=False, max_width=40)
    table.add_column("Line", justify="right")
    table.add_column("Algorithm")
    table.add_column("Risk")
    table.add_column("Recommendation", max_width=44)

    for f in report["findings"]:
        rc = _RISK_COLOR.get(f["risk_level"], "white")
        table.add_row(
            f["file_path"],
            str(f["line_number"]),
            f["algorithm"],
            f"[{rc}]{f['risk_level']}[/{rc}]",
            f["recommendation"],
        )
    console.print(table)


def _print_plain(report: dict) -> None:
    print(f"QuantumSafe Scan — {report['target']}")
    print(f"Quantum Risk Score: {report['risk_score']}/100 ({report['risk_band']}) — {report['risk_message']}")
    print(f"HIGH={report['summary']['high']} MEDIUM={report['summary']['medium']} "
          f"LOW={report['summary']['low']} TOTAL={report['summary']['total_findings']}")
    print("-" * 80)
    for f in report["findings"]:
        print(f"{f['risk_level']:<6} {f['file_path']}:{f['line_number']}  "
              f"{f['algorithm']} -> {f['recommendation']}")


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #


_CBOM_PRIMITIVE = {
    "rsa": "pke", "ecc": "signature", "dsa": "signature", "dh": "key-agree",
    "md5": "hash", "sha1": "hash", "sha256": "hash",
    "3des": "block-cipher", "rc4": "stream-cipher", "aes128": "block-cipher",
    "tls_old": "other", "tls12": "other",
}


def to_cbom(report: dict) -> str:
    """Render findings as a CycloneDX 1.6 Cryptography Bill of Materials (CBOM).

    Groups detected algorithms into ``cryptographic-asset`` components with the
    file/line occurrences as evidence. This is the format enterprises are
    beginning to require for post-quantum readiness reporting.
    """
    # Group findings by algorithm so each component lists all its occurrences.
    groups: dict[str, dict] = {}
    for f in report["findings"]:
        g = groups.setdefault(f["algorithm"], {"finding": f, "occ": []})
        g["occ"].append({"location": f["file_path"], "line": f["line_number"]})

    components = []
    for i, (algo, g) in enumerate(groups.items()):
        f = g["finding"]
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-{i}",
            "name": algo,
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": _CBOM_PRIMITIVE.get(f["family"], "other"),
                    "nistQuantumSecurityLevel": 0 if f["risk_level"] == RISK_HIGH else 1,
                },
            },
            "evidence": {"occurrences": g["occ"]},
            "properties": [
                {"name": "quantumsafe:risk", "value": f["risk_level"]},
                {"name": "quantumsafe:recommendation", "value": f["recommendation"]},
                {"name": "quantumsafe:nist", "value": f["nist_reference"]},
            ],
        })

    cbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": report.get("generated_at", ""),
            "tools": {"components": [{"type": "application", "name": "QuantumSafe",
                                      "version": report.get("version", "")}]},
            "component": {"type": "application", "name": report.get("target", "scan")},
            "properties": [{"name": "quantumsafe:riskScore",
                            "value": str(report.get("risk_score", 0))}],
        },
        "components": components,
    }
    return json.dumps(cbom, indent=2)


def to_badge_svg(report: dict) -> str:
    """Render a shields-style SVG badge of the quantum risk score (embeddable)."""
    score = report["risk_score"]
    band = report["risk_band"]
    color = {"Low": "#00FF88", "Medium": "#FFB800", "High": "#FF4444", "Critical": "#FF4444"}.get(band, "#888")
    label = "quantum risk"
    value = f"{score}/100 {band}"
    # Approximate text widths (~6.5px/char + padding).
    lw = int(len(label) * 6.5) + 12
    vw = int(len(value) * 6.5) + 14
    total = lw + vw
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{label}: {value}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <rect width="{total}" height="20" rx="3" fill="#1c1c26"/>
  <rect x="{lw}" width="{vw}" height="20" rx="3" fill="{color}"/>
  <rect x="{lw}" width="6" height="20" fill="{color}"/>
  <rect width="{total}" height="20" rx="3" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,sans-serif" font-size="11">
    <text x="{lw/2}" y="14" fill="#E0E0E0">{label}</text>
    <text x="{lw + vw/2}" y="14" fill="#0A0A0F" font-weight="bold">{value}</text>
  </g>
</svg>'''


def to_sarif(report: dict) -> str:
    """Render findings as SARIF 2.1.0 — the format GitHub code scanning ingests.

    Uploading this (e.g. via github/codeql-action/upload-sarif) makes QuantumSafe
    findings appear in a repository's Security tab.
    """
    level_map = {RISK_HIGH: "error", RISK_MEDIUM: "warning", RISK_LOW: "note"}
    severity_map = {RISK_HIGH: "9.0", RISK_MEDIUM: "5.0", RISK_LOW: "3.0"}

    # One SARIF rule per detection family.
    rules: list[dict] = []
    seen: set[str] = set()
    for f in report["findings"]:
        if f["family"] in seen:
            continue
        seen.add(f["family"])
        rules.append({
            "id": f["family"],
            "name": f["algorithm"],
            "shortDescription": {"text": f["algorithm"]},
            "fullDescription": {"text": f["why"]},
            "helpUri": "https://csrc.nist.gov/projects/post-quantum-cryptography",
            "help": {"text": f"{f['why']} Recommended replacement: {f['recommendation']} ({f['nist_reference']})."},
            "defaultConfiguration": {"level": level_map.get(f["risk_level"], "warning")},
            "properties": {"security-severity": severity_map.get(f["risk_level"], "5.0")},
        })

    results = []
    for f in report["findings"]:
        results.append({
            "ruleId": f["family"],
            "level": level_map.get(f["risk_level"], "warning"),
            "message": {"text": f"{f['algorithm']}: {f['why']} Replace with {f['recommendation']}."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file_path"]},
                    "region": {"startLine": max(1, f["line_number"])},
                }
            }],
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "QuantumSafe",
                "version": report.get("version", ""),
                "informationUri": "https://github.com/Danny-397/Quantum-Safe",
                "rules": rules,
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


def to_html(report: dict) -> str:
    e = html.escape
    band = report["risk_band"]
    band_hex = {"Low": "#00FF88", "Medium": "#FFB800", "High": "#FF4444", "Critical": "#FF4444"}
    risk_hex = {RISK_HIGH: "#FF4444", RISK_MEDIUM: "#FFB800", RISK_LOW: "#00FF88"}
    accent = band_hex.get(band, "#E0E0E0")

    rows = []
    for f in report["findings"]:
        rc = risk_hex.get(f["risk_level"], "#E0E0E0")
        rows.append(f"""
        <tr>
          <td class="mono">{e(f['file_path'])}</td>
          <td class="mono num">{f['line_number']}</td>
          <td>{e(f['algorithm'])}</td>
          <td><span class="badge" style="color:{rc};border-color:{rc}">{e(f['risk_level'])}</span></td>
          <td>{e(f['why'])}</td>
          <td>{e(f['recommendation'])}<br><span class="muted mono">{e(f['nist_reference'])} · Complexity: {e(f['complexity'])}</span></td>
        </tr>""")
    rows_html = "".join(rows) or '<tr><td colspan="6" class="muted">No quantum-vulnerable cryptography detected.</td></tr>'

    s = report["summary"]
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QuantumSafe Report — {e(report['target'])}</title>
<style>
  :root {{ color-scheme: dark; }}
  body {{ background:#0A0A0F; color:#E0E0E0; font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif; margin:0; padding:32px; }}
  .mono {{ font-family:"SFMono-Regular",ui-monospace,Consolas,Menlo,monospace; }}
  .num {{ text-align:right; }}
  .muted {{ color:#7a7a8c; font-size:12px; }}
  h1 {{ font-size:20px; margin:0 0 4px; }}
  .score {{ font-size:56px; font-weight:700; color:{accent}; font-family:"SFMono-Regular",ui-monospace,Consolas,monospace; }}
  .card {{ background:#12121a; border:1px solid #23232f; border-radius:10px; padding:24px; margin-bottom:24px; }}
  .pills span {{ display:inline-block; margin-right:16px; font-family:ui-monospace,monospace; }}
  .high {{ color:#FF4444; }} .medium {{ color:#FFB800; }} .low {{ color:#00FF88; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #23232f; vertical-align:top; }}
  th {{ color:#9a9aae; font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.05em; }}
  .badge {{ border:1px solid; border-radius:4px; padding:2px 8px; font-size:12px; font-family:ui-monospace,monospace; }}
  .footer {{ color:#7a7a8c; font-size:12px; margin-top:24px; }}
</style>
</head>
<body>
  <div class="card">
    <h1>QuantumSafe Scan Report</h1>
    <div class="muted mono">Target: {e(report['target'])} · Generated {e(report['generated_at'])} · v{e(report['version'])}</div>
    <div class="score">{report['risk_score']}/100</div>
    <div style="color:{accent};font-weight:600;">{e(band)} risk — {e(report['risk_message'])}</div>
    <div class="pills" style="margin-top:16px;">
      <span class="high">HIGH: {s['high']}</span>
      <span class="medium">MEDIUM: {s['medium']}</span>
      <span class="low">LOW: {s['low']}</span>
      <span>TOTAL: {s['total_findings']}</span>
    </div>
  </div>
  <div class="card">
    <table>
      <thead>
        <tr><th>File</th><th>Line</th><th>Algorithm</th><th>Risk</th><th>Why</th><th>Recommendation</th></tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>
  <div class="footer">
    Based on NIST Post-Quantum Cryptography Standards (FIPS 203, 204, 205).
    This report is for awareness and is not a substitute for a professional cryptographic audit.
  </div>
</body>
</html>"""
