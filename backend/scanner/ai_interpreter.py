"""
AI interpretation layer.
Uses Google Gemini (free tier) to convert structured scan data into
professional security findings. Falls back to rule-based templates if
GEMINI_API_KEY is not set or the API call fails.
"""

import re
import json
import logging
from decouple import config

logger = logging.getLogger('scanner')

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

DANGEROUS_PORTS = {
    21:    ('FTP Service Exposed',           'high',     'FTP transmits credentials in plaintext.'),
    22:    ('SSH Service Exposed',           'info',     'SSH is exposed. Ensure key-based auth only.'),
    23:    ('Telnet Service Exposed',        'critical', 'Telnet transmits all data in plaintext.'),
    25:    ('SMTP Service Exposed',          'medium',   'Mail server exposed. Check for open relay.'),
    80:    ('HTTP Service (Unencrypted)',    'info',     'HTTP traffic is unencrypted.'),
    443:   ('HTTPS Service',                'info',     'HTTPS is running.'),
    445:   ('SMB Service Exposed',          'critical', 'SMB exposed. High risk of ransomware/lateral movement.'),
    1433:  ('MSSQL Database Exposed',       'critical', 'Database port exposed to internet.'),
    3306:  ('MySQL Database Exposed',       'critical', 'Database port exposed to internet.'),
    3389:  ('RDP Service Exposed',          'critical', 'Remote Desktop exposed. Brute-force risk.'),
    5432:  ('PostgreSQL Database Exposed',  'critical', 'Database port exposed to internet.'),
    5900:  ('VNC Service Exposed',          'high',     'VNC remote access exposed.'),
    6379:  ('Redis Service Exposed',        'critical', 'Redis with no auth exposed to internet.'),
    8080:  ('HTTP Alternate Port',          'medium',   'Alternate HTTP port may expose admin panels.'),
    8443:  ('HTTPS Alternate Port',         'low',      'Alternate HTTPS port detected.'),
    27017: ('MongoDB Exposed',              'critical', 'MongoDB port exposed. Often unauthenticated.'),
}


# ─── Rule-based fallback ───────────────────────────────────────────────────────

def _rule_based_interpret(parsed: dict) -> list:
    findings = []
    tool = parsed.get('tool', '')

    if tool == 'nmap':
        for p in parsed.get('open_ports', []):
            port, service, version = p['port'], p.get('service', 'unknown'), p.get('version', '')
            if port in DANGEROUS_PORTS:
                title, severity, desc = DANGEROUS_PORTS[port]
            else:
                title    = f'Port {port}/{p["protocol"]} Open ({service})'
                severity = 'info'
                desc     = f'Service {service} is running on port {port}.'
            findings.append({
                'title':          title,
                'severity':       severity,
                'description':    desc + (f' Version: {version}.' if version else ''),
                'impact':         _default_impact(severity),
                'recommendation': _default_recommendation(service, port),
                'evidence':       f'Port {port}/{p["protocol"]} {p["state"]} {service} {version}',
                'tool':           'nmap',
            })

    elif tool == 'nikto':
        for v in parsed.get('vulnerabilities', []):
            findings.append({
                'title':          'Web Server Vulnerability',
                'severity':       'medium',
                'description':    v['description'],
                'impact':         'May allow attackers to exploit web server weaknesses.',
                'recommendation': 'Review and remediate the identified web server configuration issue.',
                'evidence':       v['description'],
                'tool':           'nikto',
            })

    elif tool == 'nuclei':
        for f in parsed.get('findings', []):
            findings.append({
                'title':          f['name'],
                'severity':       f['severity'],
                'description':    f.get('description') or f['name'],
                'impact':         _default_impact(f['severity']),
                'recommendation': 'Apply the vendor patch or configuration fix.',
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
                'impact':         'Attacker can read, modify, or delete database contents.',
                'recommendation': 'Use parameterized queries. Implement input validation and WAF.',
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
                f"{t['name']}{' ' + t['version'] if t['version'] else ''}" for t in techs[:10]
            )
            findings.append({
                'title':          'Technology Stack Identified',
                'severity':       'info',
                'description':    f'Web technology fingerprinting revealed: {tech_list}.',
                'impact':         'Known technologies may have public CVEs.',
                'recommendation': 'Keep all identified technologies updated.',
                'evidence':       tech_list,
                'tool':           'whatweb',
            })

    elif tool == 'wpscan':
        for v in parsed.get('vulnerabilities', []):
            findings.append({
                'title':          v['title'],
                'severity':       'high',
                'description':    f'WordPress vulnerability in {v["component"]}.',
                'impact':         'May allow remote code execution or data theft.',
                'recommendation': 'Update WordPress core, plugins, and themes immediately.',
                'evidence':       f'CVE: {", ".join(v.get("cve", []))}',
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

    elif tool == 'testssl':
        # Certificate issues
        cert = parsed.get('certificate', {})
        if cert.get('cert_notAfter') and 'expired' in cert.get('cert_notAfter', '').lower():
            findings.append({
                'title':          'SSL Certificate Expired',
                'severity':       'critical',
                'description':    f'The SSL/TLS certificate has expired: {cert["cert_notAfter"]}.',
                'impact':         'Browsers will show security warnings. Encrypted connections may be rejected.',
                'recommendation': 'Renew the SSL certificate immediately.',
                'evidence':       cert['cert_notAfter'],
                'tool':           'testssl',
            })

        if cert.get('cert_trust') and 'untrusted' in cert.get('cert_trust', '').lower():
            findings.append({
                'title':          'SSL Certificate Not Trusted',
                'severity':       'high',
                'description':    'The SSL certificate is not trusted by major browsers.',
                'impact':         'Users will see security warnings. Attackers can conduct MITM attacks.',
                'recommendation': 'Replace with a certificate from a trusted Certificate Authority.',
                'evidence':       cert.get('cert_trust', ''),
                'tool':           'testssl',
            })

        # Weak/deprecated protocols
        proto_names = {'SSLv2': 'SSL 2.0', 'SSLv3': 'SSL 3.0', 'TLS1': 'TLS 1.0', 'TLS1_1': 'TLS 1.1'}
        for proto in parsed.get('protocols', []):
            proto_id = proto.get('protocol', '')
            findings.append({
                'title':          f'Deprecated Protocol Enabled: {proto_names.get(proto_id, proto_id)}',
                'severity':       proto.get('severity', 'high'),
                'description':    f'{proto_names.get(proto_id, proto_id)} is enabled. This protocol is deprecated and insecure.',
                'impact':         'Attackers can downgrade connections and decrypt traffic.',
                'recommendation': f'Disable {proto_names.get(proto_id, proto_id)}. Support TLS 1.2 and TLS 1.3 only.',
                'evidence':       proto.get('finding', ''),
                'tool':           'testssl',
            })

        # Known vulnerabilities (Heartbleed, POODLE, etc.)
        vuln_titles = {
            'heartbleed':   ('Heartbleed Vulnerability (CVE-2014-0160)', 'critical',
                             'Heartbleed allows attackers to read server memory, exposing private keys and passwords.'),
            'POODLE_SSL':   ('POODLE Vulnerability (CVE-2014-3566)', 'high',
                             'POODLE allows decryption of SSL 3.0 traffic via padding oracle attacks.'),
            'ROBOT':        ('ROBOT Attack Vulnerability', 'high',
                             'ROBOT allows RSA decryption and signing with the server\'s private key.'),
            'SWEET32':      ('SWEET32 Birthday Attack', 'medium',
                             '64-bit block ciphers (3DES, Blowfish) are vulnerable to birthday attacks.'),
            'FREAK':        ('FREAK Attack Vulnerability', 'high',
                             'FREAK allows attackers to force weak RSA export keys.'),
            'LOGJAM':       ('Logjam Attack Vulnerability', 'high',
                             'Logjam allows attackers to downgrade connections to weak Diffie-Hellman.'),
            'BEAST':        ('BEAST Attack Vulnerability', 'medium',
                             'BEAST exploits CBC mode in TLS 1.0 to decrypt HTTPS cookies.'),
            'RC4':          ('RC4 Cipher Suite Enabled', 'medium',
                             'RC4 is a broken cipher that allows statistical attacks on encrypted data.'),
        }
        for vuln in parsed.get('vulnerabilities', []):
            vid = vuln.get('id', '').lower()
            if vid in vuln_titles:
                vtitle, vsev, vdesc = vuln_titles[vid]
                findings.append({
                    'title':          vtitle,
                    'severity':       vsev,
                    'description':    vdesc,
                    'impact':         _default_impact(vsev),
                    'recommendation': 'Patch OpenSSL/TLS library. Disable affected cipher suites and protocols.',
                    'evidence':       vuln.get('finding', ''),
                    'tool':           'testssl',
                })
            elif vuln.get('severity') in ('critical', 'high'):
                findings.append({
                    'title':          f'SSL/TLS Vulnerability: {vuln.get("id", "Unknown")}',
                    'severity':       vuln.get('severity', 'high'),
                    'description':    vuln.get('finding', 'SSL/TLS vulnerability detected.'),
                    'impact':         _default_impact(vuln.get('severity', 'high')),
                    'recommendation': 'Update TLS configuration and patch SSL library.',
                    'evidence':       vuln.get('finding', ''),
                    'tool':           'testssl',
                })

        # Cipher issues
        for cipher in parsed.get('cipher_issues', []):
            findings.append({
                'title':          'Weak Cipher Suite Enabled',
                'severity':       cipher.get('severity', 'medium'),
                'description':    f'Weak cipher suite detected: {cipher.get("finding", "")}',
                'impact':         'Weak ciphers can be exploited to decrypt intercepted traffic.',
                'recommendation': 'Disable weak cipher suites. Use only AES-GCM and ChaCha20-Poly1305.',
                'evidence':       cipher.get('finding', ''),
                'tool':           'testssl',
            })

    return findings


def _default_impact(severity):
    return {
        'critical': 'Could lead to full system compromise or data breach.',
        'high':     'Significant risk of unauthorized access or data exposure.',
        'medium':   'Moderate risk that could be exploited under certain conditions.',
        'low':      'Limited risk but should be addressed as part of security hardening.',
        'info':     'Informational finding for awareness.',
    }.get(severity, 'Risk level requires further assessment.')


def _default_recommendation(service, port):
    return {
        'ssh':   'Disable password authentication. Use SSH keys only.',
        'ftp':   'Replace FTP with SFTP or FTPS. Disable anonymous access.',
        'http':  'Redirect all HTTP to HTTPS. Implement HSTS.',
        'mysql': 'Restrict database access to localhost or VPN only.',
        'rdp':   'Restrict RDP to VPN only. Enable NLA. Use strong passwords.',
        'smb':   'Disable SMBv1. Restrict to internal network only.',
    }.get(service.lower(), f'Review whether port {port} needs to be publicly accessible.')


# ─── Gemini interpreter ────────────────────────────────────────────────────────

def _gemini_interpret(parsed: dict, target: str) -> list:
    """Use Google Gemini to generate professional security findings."""
    try:
        import google.generativeai as genai

        api_key = config('GEMINI_API_KEY', default=None)
        if not api_key:
            logger.warning("GEMINI_API_KEY not set — using rule-based fallback")
            return _rule_based_interpret(parsed)

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')

        data_str = json.dumps(parsed, indent=2)[:4000]

        prompt = f"""You are a senior penetration tester writing a professional security assessment report.

Target: {target}
Tool: {parsed.get('tool', 'unknown')}
Scan Data:
{data_str}

Analyze this security scan data and return a JSON array of findings.
Each finding must have these exact fields:
- title: Short clear finding title (e.g. "MySQL Database Port Exposed to Internet")
- severity: One of: critical, high, medium, low, info
- description: 2-3 sentences explaining what was found in plain English
- impact: 1-2 sentences on what an attacker could do
- recommendation: 1-3 specific actionable remediation steps
- evidence: The specific data that proves this finding

Return ONLY a valid JSON array. No markdown, no explanation, just the JSON array.
If there are no significant findings, return an empty array [].
"""

        response = model.generate_content(prompt)
        content  = response.text.strip()

        # Strip markdown code blocks if present
        content = re.sub(r'^```(?:json)?\n?', '', content)
        content = re.sub(r'\n?```$', '', content)

        findings = json.loads(content)

        for f in findings:
            f['tool'] = parsed.get('tool', 'unknown')

        logger.info("Gemini interpreted %d findings for tool=%s", len(findings), parsed.get('tool'))
        return findings

    except Exception as e:
        logger.warning("Gemini interpretation failed (%s) — using rule-based fallback", str(e))
        return _rule_based_interpret(parsed)


# ─── Public API ────────────────────────────────────────────────────────────────

def interpret_scan(scan_type: str, parsed_data: dict, target: str) -> list:
    api_key = config('GEMINI_API_KEY', default=None)
    if api_key:
        return _gemini_interpret(parsed_data, target)
    return _rule_based_interpret(parsed_data)


def interpret_all_scans(scan_results: list, target: str) -> dict:
    all_findings = []

    for scan in scan_results:
        findings = interpret_scan(scan['scan_type'], scan['parsed_data'], target)
        all_findings.extend(findings)

    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get('severity', 'info'), 5))

    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for f in all_findings:
        sev = f.get('severity', 'info').lower()
        if sev in severity_counts:
            severity_counts[sev] += 1

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
