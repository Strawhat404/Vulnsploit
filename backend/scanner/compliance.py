"""
Compliance framework mapping.
Maps security findings to OWASP Top 10 (2021) categories and CWE IDs
so reports can reference specific compliance requirements.
"""


# OWASP Top 10 (2021) categories
OWASP_2021 = {
    'A01': 'Broken Access Control',
    'A02': 'Cryptographic Failures',
    'A03': 'Injection',
    'A04': 'Insecure Design',
    'A05': 'Security Misconfiguration',
    'A06': 'Vulnerable and Outdated Components',
    'A07': 'Identification and Authentication Failures',
    'A08': 'Software and Data Integrity Failures',
    'A09': 'Security Logging and Monitoring Failures',
    'A10': 'Server-Side Request Forgery (SSRF)',
}

# Map finding patterns to OWASP categories.
# Keys are matched against finding title/description/tool (case-insensitive).
FINDING_TO_OWASP = {
    # Injection
    'sql injection':           'A03',
    'sqli':                    'A03',
    'command injection':       'A03',
    'code injection':          'A03',
    # Cryptographic failures
    'ssl':                     'A02',
    'tls':                     'A02',
    'certificate':             'A02',
    'heartbleed':              'A02',
    'poodle':                  'A02',
    'freak':                   'A02',
    'logjam':                  'A02',
    'rc4':                     'A02',
    'weak cipher':             'A02',
    'deprecated protocol':     'A02',
    'unencrypted http':        'A02',
    # Security misconfiguration
    'missing hsts':            'A05',
    'missing content-security': 'A05',
    'missing x-frame':         'A05',
    'missing x-content-type':  'A05',
    'missing referrer':        'A05',
    'missing permissions':     'A05',
    'directory traversal':     'A05',
    'directory listing':       'A05',
    'exposed directory':       'A05',
    'server version disclosure': 'A05',
    # Vulnerable components
    'cve':                     'A06',
    'vulnerable component':     'A06',
    'outdated software':       'A06',
    'outdated version':        'A06',
    # Auth failures
    'ftp service exposed':    'A07',
    'telnet service exposed': 'A07',
    'ssh':                     'A07',
    'rdp service exposed':     'A07',
    'vnc service exposed':     'A07',
    'brute':                   'A07',
}


# CWE → OWASP mapping (subset of most common CWEs)
CWE_TO_OWASP = {
    'CWE-22':   'A01',   # Path Traversal
    'CWE-78':   'A03',   # OS Command Injection
    'CWE-79':   'A03',   # XSS
    'CWE-89':   'A03',   # SQL Injection
    'CWE-94':   'A03',   # Code Injection
    'CWE-200':  'A05',   # Information Exposure
    'CWE-269':  'A01',   # Improper Privilege Management
    'CWE-287':  'A07',   # Improper Authentication
    'CWE-306':  'A07',   # Missing Authentication for Critical Function
    'CWE-311':  'A02',   # Missing Encryption of Sensitive Data
    'CWE-312':  'A02',   # Cleartext Storage of Sensitive Information
    'CWE-319':  'A02',   # Cleartext Transmission of Sensitive Information
    'CWE-327':  'A02',   # Use of a Broken or Risky Cryptographic Algorithm
    'CWE-352':  'A01',   # CSRF
    'CWE-400':  'A04',   # Uncontrolled Resource Consumption
    'CWE-502':  'A08',   # Deserialization of Untrusted Data
    'CWE-532':  'A09',   # Insertion of Sensitive Info into Log File
    'CWE-693':  'A05',   # Protection Mechanism Failure
    'CWE-732':  'A05',   # Incorrect Permission Assignment for Critical Resource
    'CWE-918':  'A10',   # SSRF
    'CWE-1021': 'A05',   # Improper Restriction of Rendered UI Layers/Frames (clickjacking)
    'CWE-1035': 'A05',   # Missing Security Headers
    'CWE-1104': 'A06',   # Use of Unmaintained Third-Party Components
    'CWE-1333': 'A05',   # Inefficient Regular Expression Complexity (ReDoS)
}


def map_finding_to_owasp(finding: dict) -> str | None:
    """
    Map a finding dict to an OWASP Top 10 (2021) category code (e.g. 'A06')
    or None if no mapping is known.
    """
    # 1. If the finding has CWE IDs, use the CWE → OWASP table first
    for cwe in finding.get('cwe_ids', []):
        if cwe in CWE_TO_OWASP:
            return CWE_TO_OWASP[cwe]

    # 2. Match against finding title/description text
    text = ' '.join([
        finding.get('title', ''),
        finding.get('description', ''),
    ]).lower()

    for pattern, owasp_code in FINDING_TO_OWASP.items():
        if pattern in text:
            return owasp_code

    # 3. Match by tool
    tool = finding.get('tool', '')
    if tool in ('nikto', 'nuclei'):
        return 'A05'  # Most web vuln findings map to misconfiguration
    if tool == 'testssl':
        return 'A02'
    if tool == 'sqlmap':
        return 'A03'

    return None


def enrich_findings_with_compliance(findings: list) -> list:
    """
    Add 'owasp' field to each finding dict. Returns the same list
    (mutated in place) so it can be chained in the report pipeline.
    """
    for finding in findings:
        owasp_code = map_finding_to_owasp(finding)
        if owasp_code:
            finding['owasp'] = owasp_code
            finding['owasp_name'] = OWASP_2021.get(owasp_code, '')
    return findings


def get_compliance_summary(findings: list) -> dict:
    """
    Return a summary of OWASP categories covered by the findings.
    { 'A01': {'name': '...', 'count': 3}, ... }
    """
    summary = {}
    for f in findings:
        code = f.get('owasp')
        if not code:
            continue
        if code not in summary:
            summary[code] = {'name': OWASP_2021.get(code, code), 'count': 0}
        summary[code]['count'] += 1
    # Sort by OWASP code
    return dict(sorted(summary.items()))