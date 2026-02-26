"""Report generator — PDF, HTML, JSON export."""

import json
import logging
import os
from datetime import datetime
from pathlib import Path

from core.device import Device

logger = logging.getLogger("netscanner.report")

REPORTS_DIR = Path(__file__).parent.parent / "reports"


def generate_json_report(devices: list[Device], filename: str = "") -> str:
    """Export scan results as JSON."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.json"
    path = REPORTS_DIR / filename

    data = {
        "scan_report": {
            "generated": datetime.now().isoformat(),
            "total_devices": len(devices),
            "cameras": sum(1 for d in devices if d.is_camera),
            "vulnerable": sum(1 for d in devices if d.is_vulnerable),
            "compromised": sum(1 for d in devices if d.has_default_creds),
        },
        "devices": [d.to_dict() for d in devices],
    }

    with open(path, "w") as f:
        json.dump(data, f, indent=2)

    logger.info(f"JSON report saved to {path}")
    return str(path)


def generate_html_report(devices: list[Device], filename: str = "") -> str:
    """Generate interactive HTML report."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.html"
    path = REPORTS_DIR / filename

    # Statistics
    total = len(devices)
    cameras = sum(1 for d in devices if d.is_camera)
    vulnerable = sum(1 for d in devices if d.is_vulnerable)
    compromised = sum(1 for d in devices if d.has_default_creds)
    critical_cves = sum(1 for d in devices for v in d.vulnerabilities if v.severity == "critical")

    # Build device rows
    device_rows = ""
    for dev in sorted(devices, key=lambda d: d.risk_score, reverse=True):
        risk_class = dev.risk_level
        cve_badges = ""
        for v in dev.vulnerabilities[:3]:
            badge_class = v.severity
            cve_badges += f'<span class="badge {badge_class}">{v.cve_id} ({v.cvss_score})</span> '

        cred_info = ""
        for c in dev.default_creds:
            if c.success:
                cred_info += f'<span class="badge warning">{c.protocol}: {c.username}:{c.password}</span> '

        device_rows += f"""
        <tr class="risk-{risk_class}">
            <td>{dev.ip}</td>
            <td>{dev.mac}</td>
            <td>{dev.vendor or dev.brand}</td>
            <td><span class="type-badge {dev.device_type}">{dev.device_type}</span></td>
            <td>{dev.brand} {dev.model}</td>
            <td>{', '.join(str(p) for p in dev.open_ports[:8])}</td>
            <td>{dev.risk_score}</td>
            <td>{cve_badges}</td>
            <td>{cred_info}</td>
        </tr>"""

    # Detail sections for each device
    detail_sections = ""
    for dev in sorted(devices, key=lambda d: d.risk_score, reverse=True):
        if not dev.is_vulnerable and not dev.has_default_creds:
            continue

        vuln_list = ""
        for v in dev.vulnerabilities:
            vuln_list += f"""
            <div class="vuln-item {v.severity}">
                <strong>{v.cve_id}</strong> — CVSS: {v.cvss_score} ({v.severity})
                <p>{v.description}</p>
                {'<span class="badge critical">Exploit Available</span>' if v.exploit_available else ''}
            </div>"""

        cred_list = ""
        for c in dev.default_creds:
            if c.success:
                cred_list += f"<li>{c.protocol}: {c.username} / {c.password} — {c.url}</li>"

        screenshots_html = ""
        for s in dev.screenshots:
            screenshots_html += f'<img src="{s}" class="screenshot" alt="Camera snapshot">'

        detail_sections += f"""
        <div class="device-detail" id="dev-{dev.ip.replace('.', '-')}">
            <h3>{dev.ip} — {dev.brand} {dev.model}</h3>
            <p>Type: {dev.device_type} | Vendor: {dev.vendor} | OS: {dev.os_guess} | FW: {dev.firmware_version}</p>
            <p>Risk Score: <strong class="{dev.risk_level}">{dev.risk_score}/10</strong></p>
            {f'<h4>Vulnerabilities ({len(dev.vulnerabilities)})</h4>{vuln_list}' if dev.vulnerabilities else ''}
            {f'<h4>Default Credentials</h4><ul>{cred_list}</ul>' if cred_list else ''}
            {f'<h4>RTSP Streams</h4><ul>{"".join(f"<li>{u}</li>" for u in dev.rtsp_urls)}</ul>' if dev.rtsp_urls else ''}
            {screenshots_html}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetScanner Report — {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Courier New', monospace; background: #0a0a0a; color: #e0e0e0; padding: 20px; }}
    h1 {{ color: #00ff00; border-bottom: 2px solid #00ff00; padding-bottom: 10px; margin-bottom: 20px; }}
    h2 {{ color: #00cc00; margin: 20px 0 10px; }}
    h3 {{ color: #00ff00; margin: 15px 0 8px; }}
    h4 {{ color: #00dd00; margin: 10px 0 5px; }}
    .summary {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
    .stat-card {{ background: #1a1a2e; border: 1px solid #333; border-radius: 8px; padding: 20px; min-width: 150px; text-align: center; }}
    .stat-card .number {{ font-size: 2.5em; font-weight: bold; }}
    .stat-card .label {{ color: #888; margin-top: 5px; }}
    .stat-card.danger .number {{ color: #ff4444; }}
    .stat-card.warning .number {{ color: #ffaa00; }}
    .stat-card.info .number {{ color: #00aaff; }}
    .stat-card.success .number {{ color: #00ff00; }}
    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 0.9em; }}
    th {{ background: #1a1a2e; color: #00ff00; padding: 10px; text-align: left; border: 1px solid #333; }}
    td {{ padding: 8px 10px; border: 1px solid #222; }}
    tr:hover {{ background: #1a1a2e; }}
    .risk-critical {{ border-left: 4px solid #ff0000; }}
    .risk-high {{ border-left: 4px solid #ff6600; }}
    .risk-medium {{ border-left: 4px solid #ffaa00; }}
    .risk-low {{ border-left: 4px solid #00aaff; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; margin: 2px; }}
    .badge.critical {{ background: #ff0000; color: white; }}
    .badge.high {{ background: #ff6600; color: white; }}
    .badge.medium {{ background: #ffaa00; color: black; }}
    .badge.low {{ background: #00aaff; color: white; }}
    .badge.warning {{ background: #ff8800; color: black; }}
    .type-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; }}
    .type-badge.camera {{ background: #cc0000; color: white; }}
    .type-badge.iot {{ background: #0066cc; color: white; }}
    .type-badge.router {{ background: #006600; color: white; }}
    .type-badge.pc {{ background: #666; color: white; }}
    .device-detail {{ background: #111; border: 1px solid #333; border-radius: 8px; padding: 15px; margin: 15px 0; }}
    .vuln-item {{ background: #1a0000; border-left: 3px solid #ff0000; padding: 8px; margin: 5px 0; }}
    .vuln-item.high {{ border-color: #ff6600; background: #1a0a00; }}
    .vuln-item.medium {{ border-color: #ffaa00; background: #1a1a00; }}
    .critical {{ color: #ff4444; }}
    .high {{ color: #ff6600; }}
    .medium {{ color: #ffaa00; }}
    .screenshot {{ max-width: 320px; border: 1px solid #333; margin: 5px; }}
    .footer {{ margin-top: 30px; padding-top: 10px; border-top: 1px solid #333; color: #666; }}
</style>
</head>
<body>
<h1>NetScanner — Penetration Test Report</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>

<h2>Executive Summary</h2>
<div class="summary">
    <div class="stat-card info"><div class="number">{total}</div><div class="label">Total Devices</div></div>
    <div class="stat-card warning"><div class="number">{cameras}</div><div class="label">Cameras</div></div>
    <div class="stat-card danger"><div class="number">{vulnerable}</div><div class="label">Vulnerable</div></div>
    <div class="stat-card danger"><div class="number">{compromised}</div><div class="label">Compromised</div></div>
    <div class="stat-card danger"><div class="number">{critical_cves}</div><div class="label">Critical CVEs</div></div>
</div>

<h2>All Devices</h2>
<table>
<thead>
<tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Type</th><th>Brand/Model</th><th>Ports</th><th>Risk</th><th>CVEs</th><th>Credentials</th></tr>
</thead>
<tbody>
{device_rows}
</tbody>
</table>

<h2>Detailed Findings</h2>
{detail_sections}

<div class="footer">
    <p>Report generated by NetScanner | For authorized security testing only</p>
</div>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)

    logger.info(f"HTML report saved to {path}")
    return str(path)


def generate_pdf_report(devices: list[Device], filename: str = "") -> str:
    """Generate PDF report using reportlab."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{timestamp}.pdf"
    path = REPORTS_DIR / filename

    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Table, TableStyle)

        doc = SimpleDocTemplate(str(path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle("Title", parent=styles["Title"],
                                      textColor=colors.HexColor("#00aa00"))
        story.append(Paragraph("NetScanner — Penetration Test Report", title_style))
        story.append(Spacer(1, 5 * mm))
        story.append(Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            styles["Normal"]
        ))
        story.append(Spacer(1, 10 * mm))

        # Summary
        story.append(Paragraph("Executive Summary", styles["Heading2"]))
        total = len(devices)
        cameras = sum(1 for d in devices if d.is_camera)
        vulnerable = sum(1 for d in devices if d.is_vulnerable)
        compromised = sum(1 for d in devices if d.has_default_creds)

        summary_data = [
            ["Total Devices", str(total)],
            ["Cameras Found", str(cameras)],
            ["Vulnerable Devices", str(vulnerable)],
            ["Compromised (Default Creds)", str(compromised)],
        ]
        t = Table(summary_data, colWidths=[120 * mm, 50 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#1a1a2e")),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
        ]))
        story.append(t)
        story.append(Spacer(1, 10 * mm))

        # Device table
        story.append(Paragraph("Discovered Devices", styles["Heading2"]))
        table_data = [["IP", "Type", "Brand", "Risk", "CVEs", "Creds"]]
        for dev in sorted(devices, key=lambda d: d.risk_score, reverse=True):
            creds_str = "YES" if dev.has_default_creds else ""
            table_data.append([
                dev.ip,
                dev.device_type,
                f"{dev.brand} {dev.model}".strip(),
                str(dev.risk_score),
                str(len(dev.vulnerabilities)),
                creds_str,
            ])

        if len(table_data) > 1:
            t = Table(table_data, colWidths=[30 * mm, 20 * mm, 40 * mm, 15 * mm, 15 * mm, 15 * mm])
            header_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#00aa00")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#0a0a0a")),
                ("TEXTCOLOR", (0, 1), (-1, -1), colors.white),
            ]
            t.setStyle(TableStyle(header_style))
            story.append(t)

        # Detailed findings for vulnerable devices
        story.append(Spacer(1, 10 * mm))
        story.append(Paragraph("Detailed Findings", styles["Heading2"]))

        for dev in sorted(devices, key=lambda d: d.risk_score, reverse=True):
            if not dev.is_vulnerable and not dev.has_default_creds:
                continue

            story.append(Spacer(1, 5 * mm))
            story.append(Paragraph(
                f"{dev.ip} — {dev.brand} {dev.model} (Risk: {dev.risk_score}/10)",
                styles["Heading3"]
            ))

            for vuln in dev.vulnerabilities:
                story.append(Paragraph(
                    f"<b>{vuln.cve_id}</b> — CVSS {vuln.cvss_score} ({vuln.severity}): "
                    f"{vuln.description[:150]}",
                    styles["Normal"]
                ))

            for cred in dev.default_creds:
                if cred.success:
                    story.append(Paragraph(
                        f"Default Creds: {cred.protocol} — {cred.username}:{cred.password}",
                        styles["Normal"]
                    ))

        # Footer
        story.append(Spacer(1, 15 * mm))
        story.append(Paragraph(
            "Report generated by NetScanner | For authorized security testing only",
            styles["Normal"]
        ))

        doc.build(story)
        logger.info(f"PDF report saved to {path}")
        return str(path)

    except ImportError:
        logger.warning("reportlab not installed — falling back to HTML report")
        return generate_html_report(devices, filename.replace(".pdf", ".html"))
