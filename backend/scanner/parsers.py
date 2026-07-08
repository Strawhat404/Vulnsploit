"""
Tool output parsers.
Each parser takes raw string output (or parsed JSON) and returns
a clean structured dict that the AI interpreter and report template can use.
"""

import re
import json
import logging

logger = logging.getLogger('scanner')


# ─── Nmap ──────────────────────────────────────────────────────────────────────

def parse_nmap(raw: str) -> dict:
    """Parse nmap text output into structured port/service data."""
    result = {
        'tool': 'nmap',
        'host': None,
        'open_ports': [],
        'filtered_ports': [],
        'os_guess': None,
        'scan_type': None,
    }

    if not raw:
        return result

    for line in raw.splitlines():
        line = line.strip()

        # Host line
        host_match = re.search(r'Nmap scan report for (.+)', line)
        if host_match:
            result['host'] = host_match.group(1).strip()

        # Open port line: 80/tcp  open  http  Apache httpd 2.4.41
        port_match = re.match(
            r'(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?', line
        )
        if port_match:
            port_info = {
                'port':     int(port_match.group(1)),
                'protocol': port_match.group(2),
                'state':    port_match.group(3),
                'service':  port_match.group(4),
                'version':  (port_match.group(5) or '').strip(),
            }
            if port_info['state'] == 'open':
                result['open_ports'].append(port_info)
            elif port_info['state'] == 'filtered':
                result['filtered_ports'].append(port_info)

        # OS detection
        os_match = re.search(r'OS details: (.+)', line)
        if os_match:
            result['os_guess'] = os_match.group(1).strip()

        # Aggressive OS guess
        os_guess = re.search(r'Aggressive OS guesses: (.+)', line)
        if os_guess and not result['os_guess']:
            result['os_guess'] = os_guess.group(1).split(',')[0].strip()

    return result


# ─── Nikto ─────────────────────────────────────────────────────────────────────

def parse_nikto(raw: str) -> dict:
    """Parse nikto text output."""
    result = {
        'tool': 'nikto',
        'target': None,
        'vulnerabilities': [],
        'server': None,
    }

    if not raw:
        return result

    for line in raw.splitlines():
        line = line.strip()

        # Target line
        target_match = re.search(r'Target IP:\s+(.+)', line)
        if target_match:
            result['target'] = target_match.group(1).strip()

        # Server header
        server_match = re.search(r'Server: (.+)', line)
        if server_match:
            result['server'] = server_match.group(1).strip()

        # Finding lines start with +
        if line.startswith('+ ') and 'OSVDB' not in line[:5]:
            finding = line[2:].strip()
            if finding and len(finding) > 10:
                # Try to extract OSVDB ID
                osvdb = re.search(r'OSVDB-(\d+)', finding)
                result['vulnerabilities'].append({
                    'description': finding,
                    'osvdb_id': osvdb.group(1) if osvdb else None,
                })

    return result


# ─── Nuclei ────────────────────────────────────────────────────────────────────

def parse_nuclei(raw_json: list) -> dict:
    """Parse nuclei JSON lines output."""
    result = {
        'tool': 'nuclei',
        'findings': [],
        'severity_counts': {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        },
    }

    if not raw_json:
        return result

    items = raw_json if isinstance(raw_json, list) else []

    for item in items:
        if not isinstance(item, dict):
            continue

        severity = item.get('info', {}).get('severity', 'info').lower()
        finding = {
            'template_id':   item.get('template-id', ''),
            'name':          item.get('info', {}).get('name', ''),
            'severity':      severity,
            'description':   item.get('info', {}).get('description', ''),
            'matched_url':   item.get('matched-at', ''),
            'tags':          item.get('info', {}).get('tags', []),
            'reference':     item.get('info', {}).get('reference', []),
        }
        result['findings'].append(finding)
        if severity in result['severity_counts']:
            result['severity_counts'][severity] += 1

    # Sort by severity
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    result['findings'].sort(key=lambda x: severity_order.get(x['severity'], 5))

    return result


# ─── Gobuster ──────────────────────────────────────────────────────────────────

def parse_gobuster(raw: str) -> dict:
    """Parse gobuster directory brute-force output."""
    result = {
        'tool': 'gobuster',
        'directories': [],
        'interesting': [],  # 200, 301, 302 responses
    }

    if not raw:
        return result

    for line in raw.splitlines():
        line = line.strip()
        # Lines look like: /admin                (Status: 200) [Size: 1234]
        match = re.match(r'(/\S*)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?', line)
        if match:
            entry = {
                'path':        match.group(1),
                'status_code': int(match.group(2)),
                'size':        int(match.group(3)) if match.group(3) else None,
            }
            result['directories'].append(entry)
            if entry['status_code'] in (200, 301, 302, 403):
                result['interesting'].append(entry)

    return result


# ─── SQLMap ────────────────────────────────────────────────────────────────────

def parse_sqlmap(raw: str) -> dict:
    """Parse sqlmap output."""
    result = {
        'tool': 'sqlmap',
        'injectable': False,
        'parameters': [],
        'databases': [],
        'dbms': None,
        'techniques': [],
    }

    if not raw:
        return result

    for line in raw.splitlines():
        line = line.strip()

        # Injectable parameter
        if 'is vulnerable' in line.lower() or 'parameter' in line.lower() and 'injectable' in line.lower():
            result['injectable'] = True
            param_match = re.search(r"parameter '(.+?)' is", line)
            if param_match:
                result['parameters'].append(param_match.group(1))

        # DBMS
        dbms_match = re.search(r'back-end DBMS: (.+)', line)
        if dbms_match:
            result['dbms'] = dbms_match.group(1).strip()

        # Databases
        db_match = re.search(r'\[\*\] (.+)', line)
        if db_match and result['injectable']:
            result['databases'].append(db_match.group(1).strip())

        # Injection techniques
        tech_match = re.search(r'Type: (.+)', line)
        if tech_match:
            result['techniques'].append(tech_match.group(1).strip())

    return result


# ─── Subfinder ─────────────────────────────────────────────────────────────────

def parse_subfinder(raw: str) -> dict:
    """Parse subfinder subdomain enumeration output."""
    result = {
        'tool': 'subfinder',
        'subdomains': [],
        'count': 0,
    }

    if not raw:
        return result

    for line in raw.splitlines():
        line = line.strip()
        if line and '.' in line and not line.startswith('['):
            result['subdomains'].append(line)

    result['count'] = len(result['subdomains'])
    return result


# ─── WhatWeb ───────────────────────────────────────────────────────────────────

def parse_whatweb(raw: str) -> dict:
    """Parse whatweb technology fingerprinting output."""
    result = {
        'tool': 'whatweb',
        'target': None,
        'technologies': [],
        'http_status': None,
    }

    if not raw:
        return result

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # First part is the URL
        url_match = re.match(r'(https?://\S+)\s+\[(\d+)', line)
        if url_match:
            result['target'] = url_match.group(1)
            result['http_status'] = int(url_match.group(2))

        # Technologies are comma-separated items like: Apache[2.4.41], PHP[7.4]
        tech_matches = re.findall(r'([A-Za-z][A-Za-z0-9\-\.]+)\[([^\]]+)\]', line)
        for name, version in tech_matches:
            if name not in ('http', 'https', 'Status'):
                result['technologies'].append({
                    'name': name,
                    'version': version,
                })

        # Technologies without version
        bare_matches = re.findall(r',\s*([A-Za-z][A-Za-z0-9\-\.]+)(?=[,\s])', line)
        for name in bare_matches:
            if name not in ('http', 'https') and not any(
                t['name'] == name for t in result['technologies']
            ):
                result['technologies'].append({'name': name, 'version': None})

    return result


# ─── WPScan ────────────────────────────────────────────────────────────────────

def parse_wpscan(raw_json) -> dict:
    """Parse wpscan JSON output."""
    result = {
        'tool': 'wpscan',
        'target_url': None,
        'wordpress_version': None,
        'vulnerabilities': [],
        'plugins': [],
        'themes': [],
        'users': [],
    }

    if not raw_json:
        return result

    data = raw_json if isinstance(raw_json, dict) else {}

    result['target_url'] = data.get('target_url')

    # WordPress version
    wp_version = data.get('version', {})
    if wp_version:
        result['wordpress_version'] = wp_version.get('number')
        for vuln in wp_version.get('vulnerabilities', []):
            result['vulnerabilities'].append({
                'title':     vuln.get('title', ''),
                'severity':  vuln.get('cvss', {}).get('score', 'Unknown'),
                'cve':       vuln.get('references', {}).get('cve', []),
                'component': 'WordPress Core',
            })

    # Plugins
    for plugin_name, plugin_data in data.get('plugins', {}).items():
        plugin_info = {
            'name':            plugin_name,
            'version':         plugin_data.get('version', {}).get('number'),
            'vulnerabilities': [],
        }
        for vuln in plugin_data.get('vulnerabilities', []):
            plugin_info['vulnerabilities'].append({
                'title':    vuln.get('title', ''),
                'severity': vuln.get('cvss', {}).get('score', 'Unknown'),
                'cve':      vuln.get('references', {}).get('cve', []),
            })
            result['vulnerabilities'].append({
                'title':     vuln.get('title', ''),
                'severity':  vuln.get('cvss', {}).get('score', 'Unknown'),
                'cve':       vuln.get('references', {}).get('cve', []),
                'component': f'Plugin: {plugin_name}',
            })
        result['plugins'].append(plugin_info)

    # Users
    for user_name in data.get('users', {}).keys():
        result['users'].append(user_name)

    return result


# ─── TestSSL ───────────────────────────────────────────────────────────────────

def parse_testssl(raw_json) -> dict:
    """
    Parse testssl.sh JSON output into structured SSL/TLS findings.
    testssl outputs a list of finding objects with id, severity, finding fields.
    """
    result = {
        'tool': 'testssl',
        'target': None,
        'certificate': {},
        'protocols': [],
        'vulnerabilities': [],
        'cipher_issues': [],
        'findings': [],
    }

    if not raw_json:
        return result

    # testssl JSON structure: { "scanResult": [ { "ip": ..., "findings": [...] } ] }
    scan_results = []
    if isinstance(raw_json, dict):
        scan_results = raw_json.get('scanResult', [])
    elif isinstance(raw_json, list):
        scan_results = raw_json

    # Severity mapping from testssl to our scale
    severity_map = {
        'CRITICAL': 'critical',
        'HIGH':     'high',
        'MEDIUM':   'medium',
        'LOW':      'low',
        'INFO':     'info',
        'OK':       'info',
        'WARN':     'medium',
        'NOT OK':   'high',
    }

    # IDs that indicate deprecated/weak protocols
    weak_protocol_ids = {
        'SSLv2', 'SSLv3', 'TLS1', 'TLS1_1',
    }

    # IDs that indicate known SSL/TLS vulnerabilities
    vuln_ids = {
        'heartbleed', 'CCS', 'ticketbleed', 'ROBOT',
        'secure_renego', 'secure_client_renego',
        'CRIME_TLS', 'BREACH', 'POODLE_SSL', 'fallback_SCSV',
        'SWEET32', 'FREAK', 'DROWN', 'LOGJAM', 'LOGJAM-common_primes',
        'BEAST_CBC_TLS1', 'BEAST', 'LUCKY13', 'RC4',
    }

    for scan in scan_results:
        if not isinstance(scan, dict):
            continue

        result['target'] = scan.get('ip') or scan.get('hostname')

        for finding in scan.get('findings', []):
            if not isinstance(finding, dict):
                continue

            fid      = finding.get('id', '')
            severity = finding.get('severity', 'INFO').upper()
            finding_text = finding.get('finding', '')

            normalized_sev = severity_map.get(severity, 'info')

            entry = {
                'id':       fid,
                'severity': normalized_sev,
                'finding':  finding_text,
            }

            # Certificate findings
            if fid.startswith('cert_'):
                result['certificate'][fid] = finding_text
                if normalized_sev in ('critical', 'high', 'medium'):
                    result['findings'].append(entry)

            # Weak protocol findings
            elif fid in weak_protocol_ids:
                if 'offered' in finding_text.lower() or 'enabled' in finding_text.lower():
                    result['protocols'].append({
                        'protocol': fid,
                        'status':   'weak/deprecated',
                        'finding':  finding_text,
                        'severity': normalized_sev,
                    })
                    result['findings'].append(entry)

            # Known vulnerability findings
            elif fid.lower() in {v.lower() for v in vuln_ids}:
                if normalized_sev not in ('info',) or 'vulnerable' in finding_text.lower():
                    result['vulnerabilities'].append({
                        'id':       fid,
                        'finding':  finding_text,
                        'severity': normalized_sev,
                    })
                    result['findings'].append(entry)

            # Cipher suite issues
            elif 'cipher' in fid.lower() and normalized_sev in ('critical', 'high', 'medium'):
                result['cipher_issues'].append({
                    'id':       fid,
                    'finding':  finding_text,
                    'severity': normalized_sev,
                })
                result['findings'].append(entry)

            # Catch all other high/critical findings
            elif normalized_sev in ('critical', 'high'):
                result['findings'].append(entry)

    return result


# ─── HTTP Security Headers ─────────────────────────────────────────────────────

def parse_headers(raw_json) -> dict:
    """
    Parse HTTP security headers check result.
    The result_json is already structured from _run_headers_check().
    Just pass it through with tool key set.
    """
    if not raw_json:
        return {'tool': 'headers', 'findings': [], 'missing_count': 0}

    result = dict(raw_json)
    result['tool'] = 'headers'
    return result


# ─── Master dispatcher ─────────────────────────────────────────────────────────

def parse_scan_result(scan_type: str, result_text: str, result_json=None) -> dict:
    """
    Dispatch to the correct parser based on scan_type.
    Returns structured dict ready for AI interpretation and report rendering.
    """
    try:
        if scan_type in ('quick', 'full', 'os_detection', 'aggressive',
                         'udp', 'ping_sweep', 'service_version', 'stealth', 'vuln'):
            return parse_nmap(result_text)
        elif scan_type == 'nikto':
            return parse_nikto(result_text)
        elif scan_type == 'nuclei':
            return parse_nuclei(result_json or [])
        elif scan_type == 'gobuster':
            return parse_gobuster(result_text)
        elif scan_type == 'sqlmap':
            return parse_sqlmap(result_text)
        elif scan_type == 'subfinder':
            return parse_subfinder(result_text)
        elif scan_type == 'whatweb':
            return parse_whatweb(result_text)
        elif scan_type == 'wpscan':
            return parse_wpscan(result_json or {})
        elif scan_type == 'testssl':
            return parse_testssl(result_json or {})
        elif scan_type == 'headers':
            return parse_headers(result_json or {})
        else:
            return {'tool': scan_type, 'raw': result_text}
    except Exception as e:
        logger.error("Parser error for %s: %s", scan_type, str(e))
        return {'tool': scan_type, 'raw': result_text, 'parse_error': str(e)}
