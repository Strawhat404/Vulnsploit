"""
CVE Enrichment Layer — Feature 2
Extracts software/version pairs from scan results and queries the
NVD (National Vulnerability Database) API v2 to find known CVEs.

NVD API v2 docs: https://nvd.nist.gov/developers/vulnerabilities
Free tier: 5 requests/30s without API key, 50/30s with key.
No API key required for basic use.
"""

import re
import time
import logging
import requests
from decouple import config

logger = logging.getLogger('scanner')

# NVD API v2 base URL
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Request timeout
REQUEST_TIMEOUT = 10

# Max CVEs to return per software component
MAX_CVES_PER_COMPONENT = 5

# CVSS score → severity mapping
def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:  return 'critical'
    if score >= 7.0:  return 'high'
    if score >= 4.0:  return 'medium'
    if score >= 0.1:  return 'low'
    return 'info'


# ─── Version string extractors ────────────────────────────────────────────────

# Maps common software name variants to their NVD CPE vendor:product format
SOFTWARE_MAP = {
    # Web servers
    'apache':        'apache:http_server',
    'nginx':         'nginx:nginx',
    'iis':           'microsoft:internet_information_services',
    'lighttpd':      'lighttpd:lighttpd',
    'tomcat':        'apache:tomcat',

    # Languages & runtimes
    'php':           'php:php',
    'python':        'python:python',
    'ruby':          'ruby-lang:ruby',
    'node':          'nodejs:node.js',
    'nodejs':        'nodejs:node.js',
    'java':          'oracle:jdk',
    'perl':          'perl:perl',

    # Databases
    'mysql':         'oracle:mysql',
    'mariadb':       'mariadb:mariadb',
    'postgresql':    'postgresql:postgresql',
    'mongodb':       'mongodb:mongodb',
    'redis':         'redis:redis',
    'elasticsearch': 'elastic:elasticsearch',

    # CMS
    'wordpress':     'wordpress:wordpress',
    'drupal':        'drupal:drupal',
    'joomla':        'joomla:joomla',

    # SSH / network
    'openssh':       'openbsd:openssh',
    'openssl':       'openssl:openssl',
    'vsftpd':        'vsftpd:vsftpd',
    'proftpd':       'proftpd:proftpd',
    'postfix':       'postfix:postfix',
    'exim':          'exim:exim',

    # Frameworks
    'django':        'djangoproject:django',
    'rails':         'rubyonrails:ruby_on_rails',
    'laravel':       'laravel:laravel',
    'express':       'expressjs:express',
    'spring':        'vmware:spring_framework',
    'jquery':        'jquery:jquery',
    'bootstrap':     'getbootstrap:bootstrap',
}


def extract_software_versions(scan_data_list: list) -> list:
    """
    Extract (software_name, version, source_tool) tuples from parsed scan results.
    Handles nmap, whatweb, and wpscan output formats.
    """
    components = []
    seen = set()

    for scan in scan_data_list:
        scan_type   = scan.get('scan_type', '')
        parsed_data = scan.get('parsed_data', {})

        # ── Nmap service versions ──────────────────────────────────────────
        if scan_type in ('quick', 'full', 'aggressive', 'service_version',
                         'stealth', 'vuln', 'os_detection'):
            for port in parsed_data.get('open_ports', []):
                version_str = port.get('version', '')
                service     = port.get('service', '').lower()
                if not version_str:
                    continue

                # Extract software name + version from nmap version string
                # e.g. "Apache httpd 2.4.41" → ("apache", "2.4.41")
                # e.g. "OpenSSH 8.2p1 Ubuntu" → ("openssh", "8.2p1")
                extracted = _parse_nmap_version_string(service, version_str)
                for name, version in extracted:
                    key = (name, version)
                    if key not in seen:
                        seen.add(key)
                        components.append({
                            'name':    name,
                            'version': version,
                            'source':  f'nmap port {port["port"]}',
                            'tool':    'nmap',
                        })

        # ── WhatWeb technologies ───────────────────────────────────────────
        elif scan_type == 'whatweb':
            for tech in parsed_data.get('technologies', []):
                name    = tech.get('name', '').lower()
                version = tech.get('version', '')
                if not version or not name:
                    continue

                # Normalize name
                normalized = _normalize_software_name(name)
                if not normalized:
                    continue

                key = (normalized, version)
                if key not in seen:
                    seen.add(key)
                    components.append({
                        'name':    normalized,
                        'version': version,
                        'source':  'whatweb',
                        'tool':    'whatweb',
                    })

        # ── WPScan WordPress version ───────────────────────────────────────
        elif scan_type == 'wpscan':
            wp_version = parsed_data.get('wordpress_version')
            if wp_version:
                key = ('wordpress', wp_version)
                if key not in seen:
                    seen.add(key)
                    components.append({
                        'name':    'wordpress',
                        'version': wp_version,
                        'source':  'wpscan',
                        'tool':    'wpscan',
                    })

            for plugin in parsed_data.get('plugins', []):
                pname    = plugin.get('name', '').lower()
                pversion = plugin.get('version')
                if pname and pversion:
                    key = (pname, pversion)
                    if key not in seen:
                        seen.add(key)
                        components.append({
                            'name':    pname,
                            'version': pversion,
                            'source':  f'wpscan plugin: {pname}',
                            'tool':    'wpscan',
                        })

    return components


def _normalize_software_name(name: str) -> str:
    """Map a raw software name to a known key in SOFTWARE_MAP."""
    name = name.lower().strip()
    # Direct match
    if name in SOFTWARE_MAP:
        return name
    # Partial match
    for key in SOFTWARE_MAP:
        if key in name or name in key:
            return key
    return None


def _parse_nmap_version_string(service: str, version_str: str) -> list:
    """
    Parse nmap version string into (software_name, version) pairs.
    Examples:
      service='http', version_str='Apache httpd 2.4.41 ((Ubuntu))'
      → [('apache', '2.4.41')]

      service='ssh', version_str='OpenSSH 8.2p1 Ubuntu 4ubuntu0.5'
      → [('openssh', '8.2')]
    """
    results = []

    # Version number pattern: digits.digits (optionally more segments)
    version_re = re.compile(r'\b(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)\b')

    # Try to identify the software name
    version_str_lower = version_str.lower()

    for keyword, _ in SOFTWARE_MAP.items():
        if keyword in version_str_lower or keyword in service:
            versions = version_re.findall(version_str)
            if versions:
                # Take the first version number found
                results.append((keyword, versions[0]))
                break

    # Fallback: if we have a service name match and a version, use service directly
    if not results:
        normalized = _normalize_software_name(service)
        if normalized:
            versions = version_re.findall(version_str)
            if versions:
                results.append((normalized, versions[0]))

    return results


# ─── NVD API client ────────────────────────────────────────────────────────────

def query_nvd_for_component(name: str, version: str) -> list:
    """
    Query NVD API v2 for CVEs affecting a specific software version.
    Returns list of CVE dicts sorted by CVSS score descending.
    """
    cpe_vendor_product = SOFTWARE_MAP.get(name)
    if not cpe_vendor_product:
        return []

    vendor, product = cpe_vendor_product.split(':')

    # Build CPE match string for this exact version
    cpe_match = f'cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*'

    headers = {}
    nvd_api_key = config('NVD_API_KEY', default=None)
    if nvd_api_key:
        headers['apiKey'] = nvd_api_key

    try:
        resp = requests.get(
            NVD_API_URL,
            params={
                'cpeName':    cpe_match,
                'resultsPerPage': MAX_CVES_PER_COMPONENT,
            },
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )

        if resp.status_code == 403:
            logger.warning("NVD API rate limit hit — add NVD_API_KEY env var for higher limits")
            return []

        if resp.status_code != 200:
            logger.warning("NVD API returned %d for %s %s", resp.status_code, name, version)
            return []

        data = resp.json()
        cves = []

        for vuln in data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})
            cve_id   = cve_data.get('id', '')

            # Get CVSS score (try v3.1 first, fall back to v2)
            cvss_score    = None
            cvss_vector   = None
            cvss_severity = 'info'

            metrics = cve_data.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                m = metrics['cvssMetricV31'][0]['cvssData']
                cvss_score    = m.get('baseScore')
                cvss_vector   = m.get('vectorString')
                cvss_severity = _cvss_to_severity(cvss_score or 0)
            elif 'cvssMetricV30' in metrics:
                m = metrics['cvssMetricV30'][0]['cvssData']
                cvss_score    = m.get('baseScore')
                cvss_vector   = m.get('vectorString')
                cvss_severity = _cvss_to_severity(cvss_score or 0)
            elif 'cvssMetricV2' in metrics:
                m = metrics['cvssMetricV2'][0]['cvssData']
                cvss_score    = m.get('baseScore')
                cvss_vector   = m.get('vectorString')
                cvss_severity = _cvss_to_severity(cvss_score or 0)

            # Get description
            descriptions = cve_data.get('descriptions', [])
            description  = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available.'
            )

            # Get references
            refs = [
                r['url'] for r in cve_data.get('references', [])[:3]
                if r.get('url')
            ]

            # Published date
            published = cve_data.get('published', '')[:10]  # YYYY-MM-DD

            cves.append({
                'cve_id':       cve_id,
                'cvss_score':   cvss_score,
                'cvss_vector':  cvss_vector,
                'severity':     cvss_severity,
                'description':  description[:300],  # truncate for report
                'references':   refs,
                'published':    published,
                'nvd_url':      f'https://nvd.nist.gov/vuln/detail/{cve_id}',
                'software':     f'{name} {version}',
            })

        # Sort by CVSS score descending
        cves.sort(key=lambda x: x.get('cvss_score') or 0, reverse=True)
        return cves[:MAX_CVES_PER_COMPONENT]

    except requests.exceptions.Timeout:
        logger.warning("NVD API timeout for %s %s", name, version)
        return []
    except Exception as e:
        logger.error("NVD API error for %s %s: %s", name, version, str(e))
        return []


# ─── Public API ────────────────────────────────────────────────────────────────

def enrich_with_cves(scan_data_list: list) -> dict:
    """
    Main entry point. Takes a list of scan result dicts, extracts software
    versions, queries NVD for CVEs, and returns enrichment data.

    Returns:
        {
            'components': [{ name, version, source, cves: [...] }],
            'total_cves': int,
            'findings': [{ title, severity, description, ... }]   # ready for report
        }
    """
    components = extract_software_versions(scan_data_list)

    if not components:
        logger.info("CVE enrichment: no software versions extracted from scan data")
        return {'components': [], 'total_cves': 0, 'findings': []}

    logger.info("CVE enrichment: checking %d components against NVD", len(components))

    enriched   = []
    findings   = []
    total_cves = 0

    for i, component in enumerate(components):
        # Rate limit — NVD allows 5 requests per 30s without API key
        if i > 0 and i % 4 == 0:
            time.sleep(6)

        cves = query_nvd_for_component(component['name'], component['version'])
        component['cves'] = cves
        total_cves += len(cves)
        enriched.append(component)

        # Convert CVEs to findings format
        for cve in cves:
            if cve.get('severity') in ('critical', 'high', 'medium'):
                findings.append({
                    'title':          f'{cve["cve_id"]}: {component["name"].title()} {component["version"]} Vulnerable',
                    'severity':       cve['severity'],
                    'description':    f'{cve["description"]} (CVSS: {cve["cvss_score"]})',
                    'impact':         _get_cve_impact(cve['severity']),
                    'recommendation': (
                        f'Update {component["name"].title()} to the latest stable version. '
                        f'See {cve["nvd_url"]} for patch information.'
                    ),
                    'evidence':       (
                        f'{component["name"].title()} {component["version"]} detected via {component["source"]}. '
                        f'CVE: {cve["cve_id"]} | CVSS: {cve["cvss_score"]} | Vector: {cve.get("cvss_vector", "N/A")}'
                    ),
                    'tool':           'cve_enricher',
                    'cve_id':         cve['cve_id'],
                    'cvss_score':     cve['cvss_score'],
                    'nvd_url':        cve['nvd_url'],
                })

    logger.info(
        "CVE enrichment complete: %d components, %d CVEs found, %d findings generated",
        len(enriched), total_cves, len(findings)
    )

    return {
        'components': enriched,
        'total_cves': total_cves,
        'findings':   findings,
    }


def _get_cve_impact(severity: str) -> str:
    return {
        'critical': 'This vulnerability could allow remote code execution or full system compromise.',
        'high':     'Exploitation could lead to unauthorized access or significant data exposure.',
        'medium':   'Could be exploited under certain conditions to cause moderate damage.',
        'low':      'Limited impact but should be patched as part of routine maintenance.',
    }.get(severity, 'Impact assessment requires further review.')
