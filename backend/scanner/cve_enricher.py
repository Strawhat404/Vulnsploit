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

# EPSS API (Exploit Prediction Scoring System) — FIRST.org
EPSS_API_URL = 'https://api.first.org/data/v1/epss'

# CISA Known Exploited Vulnerabilities (KEV) catalog feed
CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'

# Exploit-DB search URL — checks if a public exploit/PoC exists for a CVE
EXPLOITDB_API_URL = 'https://www.exploit-db.com/search'

# Request timeout
REQUEST_TIMEOUT = 10

# Max CVEs to fetch from NVD per component (before false-positive filtering).
# NVD returns many results for cpeName queries; we post-filter to only keep
# CVEs where the software is listed as VULNERABLE. Fetch more than we need
# so real CVEs aren't lost to pagination.
NVD_FETCH_PER_PAGE = 50

# Max CVEs to return per software component AFTER filtering
MAX_CVES_PER_COMPONENT = 5

# In-process cache of the CISA KEV catalog (set of CVE IDs)
_kev_cache = None

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

def _cpe_matches_target(cpe_string: str, vendor: str, product: str, version: str) -> bool:
    """
    Check if a CPE match string refers to our target software.
    CPE format: cpe:2.3:a:VENDOR:PRODUCT:VERSION:...
    """
    parts = cpe_string.split(':')
    if len(parts) < 6:
        return False
    cpe_vendor  = parts[3]
    cpe_product = parts[4]
    cpe_version = parts[5]
    if cpe_vendor != vendor or cpe_product != product:
        return False
    # Version match: exact, wildcard, or prefix
    if cpe_version == '*' or cpe_version == version:
        return True
    if cpe_version.endswith('*') and version.startswith(cpe_version[:-1]):
        return True
    return False


def _version_in_range(version: str, cpe_match: dict) -> bool:
    """
    Check if our version falls within the NVD cpeMatch version bounds.
    NVD uses versionStartIncluding / versionStartExcluding /
    versionEndIncluding / versionEndExcluding fields.
    """
    import re
    # If no version bounds on the match, it's a catch-all
    has_start = any(k in cpe_match for k in
                    ('versionStartIncluding', 'versionStartExcluding'))
    has_end   = any(k in cpe_match for k in
                    ('versionEndIncluding', 'versionEndExcluding'))
    if not has_start and not has_end:
        return True

    def _normalize(v):
        """Extract leading numeric version for comparison."""
        m = re.match(r'(\d+(?:\.\d+)*)(.*)', v or '')
        return tuple(int(x) for x in m.group(1).split('.')) if m and m.group(1) else (0,)

    our_v = _normalize(version)

    if has_start:
        start_inc = cpe_match.get('versionStartIncluding')
        start_exc = cpe_match.get('versionStartExcluding')
        if start_inc:
            if our_v < _normalize(start_inc):
                return False
        if start_exc:
            if our_v <= _normalize(start_exc):
                return False

    if has_end:
        end_inc = cpe_match.get('versionEndIncluding')
        end_exc = cpe_match.get('versionEndExcluding')
        if end_inc:
            if our_v > _normalize(end_inc):
                return False
        if end_exc:
            if our_v >= _normalize(end_exc):
                return False

    return True


def _cve_affects_software(cve_data: dict, vendor: str, product: str, version: str) -> bool:
    """
    Check if a CVE actually lists our target software+version as VULNERABLE
    in its CPE configurations. This filters out false positives where the
    software appears only as a non-vulnerable environment requirement.
    """
    for config in cve_data.get('configurations', []):
        for node in config.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if not cpe_match.get('vulnerable'):
                    continue
                criteria = cpe_match.get('criteria', '')
                if not _cpe_matches_target(criteria, vendor, product, version):
                    continue
                if not _version_in_range(version, cpe_match):
                    continue
                return True
    return False


def query_nvd_for_component(name: str, version: str) -> list:
    """
    Query NVD API v2 for CVEs affecting a specific software version.
    Returns list of CVE dicts sorted by CVSS score descending.

    Post-filters NVD results to only include CVEs where the target
    software+version appears as a VULNERABLE CPE (not just an environment
    requirement), eliminating false positives like CVE-2007-4723 (Ragnarok
    Online Control Panel) being attributed to Apache httpd.
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
                'resultsPerPage': NVD_FETCH_PER_PAGE,
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

            # ── FALSE-POSITIVE FILTER ──────────────────────────────────────
            # Only keep CVEs where our target software+version is listed
            # as VULNERABLE in the CPE configurations. NVD's cpeName query
            # returns CVEs where the CPE appears anywhere — including as a
            # non-vulnerable environment (e.g. "runs on Apache"). This
            # filter ensures we only report real vulnerabilities.
            if not _cve_affects_software(cve_data, vendor, product, version):
                logger.debug("Filtering false positive: %s does not affect %s %s",
                             cve_id, name, version)
                continue

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

            # ── CWE extraction ─────────────────────────────────────────────
            # NVD provides CWE IDs in the 'weaknesses' array — we extract
            # them so the report can map findings to OWASP/CWE categories.
            cwe_ids = []
            for weakness in cve_data.get('weaknesses', []):
                for desc in weakness.get('description', []):
                    cwe = desc.get('value', '')
                    if cwe.startswith('CWE-'):
                        cwe_ids.append(cwe)
            # Deduplicate
            cwe_ids = list(dict.fromkeys(cwe_ids))[:5]

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
                'cwe_ids':      cwe_ids,
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


# ─── EPSS batch enrichment ─────────────────────────────────────────────────────

def query_epss_batch(cve_ids: list) -> dict:
    """
    Query the EPSS API for a list of CVE IDs in batches of 100.
    Returns a mapping: { cve_id: {'epss': float, 'percentile': float} }
    Silently returns partial or empty results on error.
    """
    out = {}
    if not cve_ids:
        return out

    for i in range(0, len(cve_ids), EPSS_BATCH_SIZE):
        batch = cve_ids[i:i + EPSS_BATCH_SIZE]
        params = [('cve', cid) for cid in batch]
        try:
            resp = requests.get(EPSS_API_URL, params=params, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                logger.warning("EPSS API returned %d", resp.status_code)
                continue
            for row in resp.json().get('data', []):
                cid = row.get('cve')
                if not cid:
                    continue
                try:
                    out[cid] = {
                        'epss':       float(row.get('epss', 0) or 0),
                        'percentile': float(row.get('percentile', 0) or 0),
                    }
                except (TypeError, ValueError):
                    continue
        except requests.exceptions.Timeout:
            logger.warning("EPSS API timeout for batch starting at %d", i)
        except Exception as e:
            logger.warning("EPSS API error: %s", str(e))

    return out


# ─── CISA KEV catalog ──────────────────────────────────────────────────────────

def load_kev_catalog() -> set:
    """
    Download and cache the CISA Known Exploited Vulnerabilities catalog.
    Returns a set of CVE IDs that are known to be actively exploited in the wild.
    Cached in-process for the worker's lifetime.
    """
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    try:
        resp = requests.get(CISA_KEV_URL, timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("CISA KEV feed returned %d", resp.status_code)
            _kev_cache = set()
        else:
            data = resp.json()
            _kev_cache = {
                v.get('cveID') for v in data.get('vulnerabilities', [])
                if v.get('cveID')
            }
            logger.info("CISA KEV catalog loaded: %d entries", len(_kev_cache))
    except Exception as e:
        logger.warning("Failed to load CISA KEV catalog: %s", str(e))
        _kev_cache = set()

    return _kev_cache


# ─── Exploit-DB availability check ─────────────────────────────────────────────

def check_exploit_db(cve_ids: list) -> dict:
    """
    Check Exploit-DB for public exploits / proof-of-concept code for
    the given CVE IDs. Returns a mapping: { cve_id: True/False }.

    Uses the Exploit-DB search API. If the API is unreachable or returns
    an error, all CVEs are marked as 'unknown' (None) rather than False
    so we don't give false confidence.
    """
    out = {cid: None for cid in cve_ids}
    if not cve_ids:
        return out

    headers = {
        'Accept': 'application/json',
        'User-Agent': 'VulnSploit/1.0',
    }

    for cve_id in cve_ids:
        try:
            resp = requests.get(
                EXPLOITDB_API_URL,
                params={'q': cve_id, 'cve': cve_id},
                headers=headers,
                timeout=REQUEST_TIMEOUT,
            )
            if resp.status_code == 200:
                data = resp.json()
                # Exploit-DB returns a list of exploits in 'data'
                exploits = data.get('data', [])
                if isinstance(exploits, list) and len(exploits) > 0:
                    out[cve_id] = True
                else:
                    out[cve_id] = False
            else:
                logger.debug("Exploit-DB returned %d for %s", resp.status_code, cve_id)
        except Exception as e:
            logger.debug("Exploit-DB check failed for %s: %s", cve_id, str(e))

    found = sum(1 for v in out.values() if v is True)
    if found:
        logger.info("Exploit-DB: %d/%d CVEs have public exploits", found, len(cve_ids))

    return out


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

    # ── Batch enrich with EPSS exploit-prediction scores ──────────────────────
    all_cve_ids = [c['cve_id'] for comp in enriched for c in comp['cves'] if c.get('cve_id')]
    epss_map    = query_epss_batch(all_cve_ids)
    kev_set     = load_kev_catalog()
    exploit_map = check_exploit_db(all_cve_ids)

    for comp in enriched:
        for cve in comp['cves']:
            cid = cve.get('cve_id')
            ep = epss_map.get(cid)
            if ep:
                cve['epss']             = ep['epss']
                cve['epss_percentile']  = ep['percentile']
            if cid in kev_set:
                cve['known_exploited'] = True
                cve['kev_url'] = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'
            if exploit_map.get(cid) is True:
                cve['public_exploit'] = True

    # Convert CVEs to findings format
    for component in enriched:
        for cve in component['cves']:
            if cve.get('severity') in ('critical', 'high', 'medium'):
                epss_str = ''
                if cve.get('epss') is not None:
                    epss_str = (
                        f" EPSS: {cve['epss']:.4f} "
                        f"(percentile: {cve.get('epss_percentile', 0):.2%})"
                    )
                kev_str = ''
                if cve.get('known_exploited'):
                    kev_str = ' [CISA KEV — actively exploited in the wild]'
                exploit_str = ''
                if cve.get('public_exploit'):
                    exploit_str = ' [Public exploit available on Exploit-DB]'

                findings.append({
                    'title':          f'{cve["cve_id"]}: {component["name"].title()} {component["version"]} Vulnerable{kev_str}{exploit_str}',
                    'severity':       cve['severity'],
                    'description':    f'{cve["description"]} (CVSS: {cve["cvss_score"]}){epss_str}{kev_str}{exploit_str}',
                    'impact':         _get_cve_impact(cve['severity']),
                    'recommendation': (
                        f'Update {component["name"].title()} to the latest stable version. '
                        f'See {cve["nvd_url"]} for patch information.'
                        + (f' CISA KEV listing: {cve["kev_url"]}' if cve.get('known_exploited') else '')
                    ),
                    'evidence':       (
                        f'{component["name"].title()} {component["version"]} detected via {component["source"]}. '
                        f'CVE: {cve["cve_id"]} | CVSS: {cve["cvss_score"]} | Vector: {cve.get("cvss_vector", "N/A")}'
                        + epss_str + kev_str + exploit_str
                    ),
                    'tool':           'cve_enricher',
                    'cve_id':         cve['cve_id'],
                    'cvss_score':     cve['cvss_score'],
                    'epss':           cve.get('epss'),
                    'epss_percentile': cve.get('epss_percentile'),
                    'known_exploited': cve.get('known_exploited', False),
                    'public_exploit':  cve.get('public_exploit', False),
                    'cwe_ids':         cve.get('cwe_ids', []),
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
