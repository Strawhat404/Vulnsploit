"""
AI interpretation layer.
Takes structured parser output and returns human-readable security findings
using OpenAI GPT-4o. Falls back to rule-based templates if AI is unavailable.
"""

import json
import logging
from decouple import config

logger = logging.getLogger('scanner')

# ─── Severity helpers ──────────────────────────────────────────────────────────

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

DANGEROUS_PORTS = {
    21:   ('FTP Service Exposed',          'high',     'FTP transmits credentials in plaintext.'),
    22:   ('SSH Service Exposed',          'info',     'SSH is exposed. Ensure key-based auth only.'),
    23:   ('Telnet Service Exposed',       'critical', 'Telnet transmits all data in plaintext.'),
    25:   ('SMTP Service Exposed',         'medium',   'Mail server exposed. Check for open relay.'),
    80:   ('HTTP Service (Unencrypted)',   'info',     'HTTP traffic is unencrypted.'),
    443:  ('HTTPS Service',               'info',     'HTTPS is running.'),
    445:  ('SMB Service Exposed',          'critical', 'SMB is exposed. High risk of ransomware/lateral movement.'),
    1433: ('MSSQL Database Exposed',       'critical', 'Database port exposed to internet.'),
    3306: ('MySQL Database Exposed',       'critical', 'Database port exposed to internet.'),
    3389: ('RDP Service Exposed',          'critical', 'Remote Desktop exposed. Brute-force risk.'),
    5432: ('PostgreSQL Database Exposed',  'critical', 'Database port exposed to internet.'),
    5900: ('VNC Service Exposed',          'high',     'VNC remote access exposed.'),
    6379: ('Redis Service Exposed',        'critical', 'Redis with no auth exposed to internet.'),
    8080: ('HTTP Alternate Port',          'medium',   'Alternate HTTP port may expose admin panels.'),
    8443: ('HTTPS Alternate Port',         'low',      'Alternate HTTPS port detected.'),
    27017:('MongoDB Exposed',              'critical', 'MongoDB port exposed. Often unauthenticated.'),
}


# ─── Rule-based fallback ───────────────────────────────────────────────────────

def _rule_based_interpret(parsed: dict) -> list:
    """
    Generate findings from structured data without AI.
    Returns list of finding dicts.
    """
    findings = []
    tool = parsed.get('tool', '')

    if tool == 'nmap':
        for port_info in parsed.get('open_ports', []):
            port = port_info['port']
            service = port_info.get('service', 'unknown')
            version = port_info.get('version', '')

            if port in DANGEROUS_PORTS:
                title, severity, desc = DANGEROUS_PORTS[port]
            else:
                title    = f'Port {port}/{port_info["protocol"]} Open ({service})'
                severity = 'info'
                desc     = f'Service {service} is running on port {port}.'

            findings.append({
                'title':          title,
                'severity':       severity,
                'description':    desc + (f' Version detected: {version}.' if version else ''),
                'impact':         _default_impact(severity),
                'recommendation': _default_recommendation(service, port),
                'evidence':       f'Port {port}/{port_info["protocol"]} {port_info["state"]} {service} {version}',
                'tool':           'nmap',
            })

    elif tool == 'nikto':
        for vuln in parsed.get('vulnerabilities', []):
            findings.append({
                'title':          'Web Server Vulnerability',
                'severity':       'medium',
                'description':    vuln['description'],
                'impact':         'May allow attackers to exploit web server weaknesses.',
                'recommendation': 'Review and remediate the identified web server configuration issue.',
                'evidence':       vuln['description'],
                'tool':           'nikto',
            })

    elif tool == 'nuclei':
        for f in parsed.get('findings', []):
            findings.append({
                'title':          f['name'],
                'severity':       f['severity'],
                'description':    f.get('description') or f['name'],
                'impact':         _default_impact(f['severity']),
                'recommendation': 'Apply the vendor patch or configuration fix for this vulnerability.',
                'evidence':       f'Matched at: {f["matched_url"]}',
                'tool':           'nuclei',
            })

    elif tool == 'gobuster':
        interesting = parsed.get('interesting', [])
        if interesting:
            paths = [d['path'] for d in interesting[:10]]
            findings.append({
                'title':          'Exposed Web Directories/Files',
                'severity':       'medium',
                'description':    f'Directory brute-forcing revealed {len(interesting)} accessible paths.',
                'impact':         'Exposed directories may contain sensitive files or admin interfaces.',
                'recommendation': 'Restrict access to sensitive directories. Review each path.',
                'evidence':       'Accessible paths: ' + ', '.join(paths),
                'tool':           'gobuster',
            })

    elif tool == 'sqlmap':
        if parsed.get('injectable'):
            findings.append({
                'title':          'SQL Injection Vulnerability',
                'severity':       'critical',
                'description':    f'SQL injection detected. DBMS: {parsed.get("dbms", "Unknown")}. '
                                  f'Injectable parameters: {", ".join(parsed.get("parameters", []))}.',
                'impact':         'Attacker can read, modify, or delete database contents. '
                                  'May lead to full system compromise.',
                'recommendation': 'Use parameterized queries/prepared statements. '
                                  'Implement input validation and WAF.',
                'evidence':       f'Parameters: {parsed.get("parameters")} | DBMS: {parsed.get("dbms")}',
                'tool':           'sqlmap',
            })

    elif tool == 'subfinder':
        count = parsed.get('count', 0)
        if count > 0:
            findings.append({
                'title':          f'Attack Surface: {count} Subdomains Discovered',
                'severity':       'info',
                'description':    f'Passive reconnaissance identified {count} subdomains.',
                'impact':         'Each subdomain is a potential attack vector.',
                'recommendation': 'Review all subdomains. Decommission unused ones.',
                'evidence':       'Subdomains: ' + ', '.join(parsed.get('subdomains', [])[:10]),
                'tool':           'subfinder',
            })

    elif tool == 'whatweb':
        techs = parsed.get('technologies', [])
        if techs:
            tech_list = ', '.join(
                f"{t['name']}{' ' + t['version'] if t['version'] else ''}"
                for t in techs[:10]
            )
            findings.append({
                'title':          'Technology Stack Identified',
                'severity':       'info',
                'description':    f'Web technology fingerprinting revealed: {tech_list}.',
                'impact':         'Known technologies may have public CVEs.',
                'recommendation': 'Keep all identified technologies updated to latest versions.',
                'evidence':       tech_list,
                'tool':           'whatweb',
            })

    elif tool == 'wpscan':
        for vuln in parsed.get('vulnerabilities', []):
            findings.append({
                'title':          vuln['title'],
                'severity':       'high',
                'description':    f'WordPress vulnerability in {vuln["component"]}.',
                'impact':         'May allow remote code execution or data theft.',
                'recommendation': 'Update WordPress core, plugins, and themes immediately.',
                'evidence':       f'CVE: {", ".join(vuln.get("cve", []))}',
                'tool':           'wpscan',
            })
        if parsed.get('users'):
            findings.append({
                'title':          'WordPress User Enumeration',
                'severity':       'medium',
                'description':    f'WordPress users discovered: {", ".join(parsed["users"])}.',
                'impact':         'Usernames can be used for brute-force attacks.',
                'recommendation': 'Disable user enumeration. Use security plugins.',
                'evidence':       f'Users: {", ".join(parsed["users"])}',
                'tool':           'wpscan',
            })

    return findings


def _default_impact(severity: str) -> str:
    impacts = {
        'critical': 'Could lead to full system compromise or data breach.',
        'high':     'Significant risk of unauthorized access or data exposure.',
        'medium':   'Moderate risk that could be exploited under certain conditions.',
        'low':      'Limited risk but should be addressed as part of security hardening.',
        'info':     'Informational finding for awareness.',
    }
    return impacts.get(severity, 'Risk level requires further assessment.')


def _default_recommendation(service: str, port: int) -> str:
    recs = {
        'ssh':   'Disable password authentication. Use SSH keys only. Consider non-standard port.',
        'ftp':   'Replace FTP with SFTP or FTPS. Disable anonymous access.',
        'http':  'Redirect all HTTP to HTTPS. Implement HSTS.',
        'mysql': 'Restrict database access to localhost or VPN only. Use firewall rules.',
        'rdp':   'Restrict RDP to VPN only. Enable NLA. Use strong passwords.',
        'smb':   'Disable SMBv1. Restrict to internal network only.',
    }
    return recs.get(service.lower(), f'Review whether port {port} needs to be publicly accessible.')


# ─── OpenAI interpreter ────────────────────────────────────────────────────────

def _ai_interpret(parsed: dict, target: str) -> list:
    """Use OpenAI to generate professional security findings."""
    try:
        from openai import OpenAI

        api_key = config('OPENAI_API_KEY', default=None)
        if not api_key:
            logger.warning("OPENAI_API_KEY not set — using rule-based fallback")
            return _rule_based_interpret(parsed)

        client = OpenAI(api_key=api_key)

        # Limit data size sent to API
        data_str = json.dumps(parsed, indent=2)[:4000]

        prompt = f"""You are a senior penetration tester writing a professional security assessment report.

Target: {target}
Tool: {parsed.get('tool', 'unknown')}
Scan Data:
{data_str}

Analyze this security scan data and return a JSON array of findings.
Each finding must have these exact fields:
- title: Short, clear finding title (e.g. "MySQL Database Port Exposed to Internet")
- severity: One of: critical, high, medium, low, info
- description: 2-3 sentences explaining what was found in plain English
- impact: 1-2 sentences on what an attacker could do
- recommendation: 1-3 specific actionable remediation steps
- evidence: The specific data that proves this finding

Return ONLY a valid JSON array. No markdown, no explanation, just the JSON array.
If there are no significant findings, return an empty array [].
"""

        response = client.chat.completions.create(
            model='gpt-4o-mini',
            messages=[
                {'role': 'system', 'content': 'You are a cybersecurity expert. Return only valid JSON.'},
                {'role': 'user',   'content': prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
        )

        content = response.choices[0].message.content.strip()

        # Strip markdown code blocks if present
        if content.startswith('```'):
            content = re.sub(r'^```(?:json)?\n?', '', content)
            content = re.sub(r'\n?```$', '', content)

        findings = json.loads(content)

        # Add tool field to each finding
        for f in findings:
            f['tool'] = parsed.get('tool', 'unknown')

        logger.info("AI interpreted %d findings for tool=%s", len(findings), parsed.get('tool'))
        return findings

    except Exception as e:
        logger.warning("AI interpretation failed (%s) — using rule-based fallback", str(e))
        return _rule_based_interpret(parsed)


import re  # needed for _ai_interpret


# ─── Public API ────────────────────────────────────────────────────────────────

def interpret_scan(scan_type: str, parsed_data: dict, target: str) -> list:
    """
    Main entry point.
    Returns list of finding dicts with: title, severity, description, impact,
    recommendation, evidence, tool.
    """
    api_key = config('OPENAI_API_KEY', default=None)

    if api_key:
        return _ai_interpret(parsed_data, target)
    else:
        return _rule_based_interpret(parsed_data)


def interpret_all_scans(scan_results: list, target: str) -> dict:
    """
    Interpret multiple scan results and return aggregated findings.
    scan_results: list of dicts with {scan_type, parsed_data}
    Returns: {findings: [...], severity_counts: {...}, executive_summary: str}
    """
    all_findings = []

    for scan in scan_results:
        findings = interpret_scan(
            scan['scan_type'],
            scan['parsed_data'],
            target
        )
        all_findings.extend(findings)

    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'info'), 5))

    # Count by severity
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in all_findings:
        sev = f.get('severity', 'info').lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Executive summary
    total = len(all_findings)
    crit  = severity_counts['critical']
    high  = severity_counts['high']

    if crit > 0:
        risk_level = 'CRITICAL'
        summary = (
            f"The security assessment of {target} identified {total} findings, "
            f"including {crit} critical and {high} high severity issues that require "
            f"immediate attention. The target presents significant security risks."
        )
    elif high > 0:
        risk_level = 'HIGH'
        summary = (
            f"The security assessment of {target} identified {total} findings, "
            f"including {high} high severity issues. Prompt remediation is recommended."
        )
    elif total > 0:
        risk_level = 'MEDIUM'
        summary = (
            f"The security assessment of {target} identified {total} findings "
            f"of medium to low severity. Standard remediation procedures apply."
        )
    else:
        risk_level = 'LOW'
        summary = f"The security assessment of {target} identified no significant vulnerabilities."

    return {
        'findings':          all_findings,
        'severity_counts':   severity_counts,
        'total_findings':    total,
        'risk_level':        risk_level,
        'executive_summary': summary,
    }
