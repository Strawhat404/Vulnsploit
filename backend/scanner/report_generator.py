"""
PDF report generator using WeasyPrint + Jinja2.
"""

import os
import logging
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
from django.conf import settings

logger = logging.getLogger('scanner')

# Tools metadata for the scope table
TOOL_META = {
    'subfinder':      {'name': 'Subfinder',  'category': 'Reconnaissance',      'purpose': 'Passive subdomain enumeration'},
    'whatweb':        {'name': 'WhatWeb',    'category': 'Fingerprinting',       'purpose': 'Web technology identification'},
    'quick':          {'name': 'Nmap',       'category': 'Port Scanning',        'purpose': 'Fast port scan of common ports'},
    'full':           {'name': 'Nmap',       'category': 'Port Scanning',        'purpose': 'Full TCP port scan with service detection'},
    'stealth':        {'name': 'Nmap',       'category': 'Port Scanning',        'purpose': 'Stealth SYN scan'},
    'aggressive':     {'name': 'Nmap',       'category': 'Port Scanning',        'purpose': 'Aggressive scan with OS and version detection'},
    'vuln':           {'name': 'Nmap',       'category': 'Vulnerability Scan',   'purpose': 'NSE vulnerability scripts'},
    'os_detection':   {'name': 'Nmap',       'category': 'Reconnaissance',       'purpose': 'Operating system detection'},
    'nikto':          {'name': 'Nikto',      'category': 'Web Vulnerability',    'purpose': 'Web server vulnerability scanning'},
    'gobuster':       {'name': 'Gobuster',   'category': 'Directory Discovery',  'purpose': 'Directory and file brute-forcing'},
    'nuclei':         {'name': 'Nuclei',     'category': 'Vulnerability Scan',   'purpose': 'Template-based vulnerability detection'},
    'sqlmap':         {'name': 'SQLMap',     'category': 'Exploitation',         'purpose': 'SQL injection detection and exploitation'},
    'wpscan':         {'name': 'WPScan',     'category': 'CMS Security',         'purpose': 'WordPress vulnerability scanning'},
    'udp':            {'name': 'Nmap',       'category': 'Port Scanning',        'purpose': 'UDP port scanning'},
    'ping_sweep':     {'name': 'Nmap',       'category': 'Reconnaissance',       'purpose': 'Host discovery'},
    'service_version':{'name': 'Nmap',       'category': 'Fingerprinting',       'purpose': 'Service version detection'},
    'testssl':        {'name': 'TestSSL',    'category': 'SSL/TLS Analysis',     'purpose': 'SSL/TLS misconfiguration and vulnerability detection'},
    'headers':        {'name': 'HeadersCheck', 'category': 'HTTP Security',      'purpose': 'HTTP security headers misconfiguration check'},
}


def render_pdf(report_id: int, target: str, interpreted: dict,
               user=None, scan_results=None) -> str:
    """
    Render the HTML report template and convert to PDF using WeasyPrint.

    Returns the relative path to the saved PDF file (relative to MEDIA_ROOT).
    """
    from weasyprint import HTML, CSS

    # ── Prepare output directory ──────────────────────────────────────────────
    media_root   = Path(settings.MEDIA_ROOT)
    reports_dir  = media_root / 'reports'
    reports_dir.mkdir(parents=True, exist_ok=True)

    filename     = f"vulnsploit_report_{report_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf_path     = reports_dir / filename
    relative_path = f"reports/{filename}"

    # ── Load Jinja2 template ──────────────────────────────────────────────────
    template_dir = Path(__file__).parent / 'templates' / 'reports'
    env          = Environment(loader=FileSystemLoader(str(template_dir)))
    template     = env.get_template('report.html')

    # ── Build tools used list ─────────────────────────────────────────────────
    tools_used = []
    seen_tools = set()
    if scan_results:
        for scan in scan_results:
            meta = TOOL_META.get(scan.scan_type, {
                'name':     scan.scan_type,
                'category': 'Security Tool',
                'purpose':  'Security assessment',
            })
            key = meta['name']
            if key not in seen_tools:
                tools_used.append(meta)
                seen_tools.add(key)

    if not tools_used:
        # Default for full recon
        tools_used = [TOOL_META[t] for t in
                      ['subfinder', 'whatweb', 'quick', 'nikto', 'gobuster', 'nuclei', 'sqlmap']
                      if t in TOOL_META]

    # ── Build raw outputs for appendix ───────────────────────────────────────
    raw_outputs = []
    if scan_results:
        for scan in scan_results:
            if scan.result and scan.result not in ('Scan in progress...', 'Scan queued...'):
                raw_outputs.append({
                    'tool':      TOOL_META.get(scan.scan_type, {}).get('name', scan.scan_type),
                    'scan_type': scan.scan_type,
                    'output':    scan.result or '',
                })

    # ── Render HTML ───────────────────────────────────────────────────────────
    html_content = template.render(
        target            = target,
        date              = datetime.now().strftime('%B %d, %Y'),
        assessor          = getattr(user, 'username', 'VulnSploit') if user else 'VulnSploit',
        report_id         = report_id,
        risk_level        = interpreted.get('risk_level', 'UNKNOWN'),
        executive_summary = interpreted.get('executive_summary', ''),
        severity_counts   = interpreted.get('severity_counts', {}),
        findings          = interpreted.get('findings', []),
        total_findings    = interpreted.get('total_findings', 0),
        tools_used        = tools_used,
        raw_outputs       = raw_outputs,
        cve_components    = interpreted.get('cve_components', []),
        total_cves        = interpreted.get('total_cves', 0),
    )

    # ── Convert to PDF ────────────────────────────────────────────────────────
    logger.info("Rendering PDF | report=%s target=%s", report_id, target)

    HTML(string=html_content).write_pdf(
        str(pdf_path),
        stylesheets=[],
        presentational_hints=True,
    )

    logger.info("PDF saved | path=%s size=%d bytes", pdf_path, pdf_path.stat().st_size)
    return relative_path
