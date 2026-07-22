import subprocess
import json
import os
import requests as http_requests
from decouple import config

# Per-tool subprocess timeouts in seconds
TOOL_TIMEOUTS = {
    'quick':          300,
    'full':           3600,
    'os_detection':   300,
    'aggressive':     600,
    'udp':            600,
    'ping_sweep':     60,
    'service_version':300,
    'stealth':        300,
    'vuln':           600,
    'nikto':          600,
    'sqlmap':         1800,
    'subfinder':      120,
    'whatweb':        60,
    'gobuster':       600,
    'nuclei':         900,
    'wpscan':         300,
    'testssl':        300,
    'headers':        30,
}

# ─── Security headers check — pure Python, no subprocess ──────────────────────

# All security headers we check with their descriptions and severity if missing
SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'severity':       'high',
        'missing_title':  'Missing HTTP Strict Transport Security (HSTS)',
        'description':    'HSTS header is not set. The browser is not instructed to always use HTTPS.',
        'impact':         'Attackers can perform SSL stripping attacks to downgrade HTTPS to HTTP.',
        'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    'Content-Security-Policy': {
        'severity':       'high',
        'missing_title':  'Missing Content Security Policy (CSP)',
        'description':    'No Content-Security-Policy header found. The browser has no restrictions on content sources.',
        'impact':         'Cross-Site Scripting (XSS) attacks are significantly easier without CSP.',
        'recommendation': "Add a Content-Security-Policy header. Start with: Content-Security-Policy: default-src 'self'",
    },
    'X-Frame-Options': {
        'severity':       'medium',
        'missing_title':  'Missing X-Frame-Options Header',
        'description':    'X-Frame-Options header is absent. The page can be embedded in an iframe.',
        'impact':         'Clickjacking attacks can trick users into clicking hidden malicious elements.',
        'recommendation': 'Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN',
    },
    'X-Content-Type-Options': {
        'severity':       'low',
        'missing_title':  'Missing X-Content-Type-Options Header',
        'description':    'X-Content-Type-Options header is not set.',
        'impact':         'Browsers may attempt MIME-type sniffing, enabling content injection attacks.',
        'recommendation': 'Add: X-Content-Type-Options: nosniff',
    },
    'Referrer-Policy': {
        'severity':       'low',
        'missing_title':  'Missing Referrer-Policy Header',
        'description':    'No Referrer-Policy header. Full URLs may be leaked in the Referer header.',
        'impact':         'Sensitive URL parameters may be exposed to third-party sites.',
        'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
    },
    'Permissions-Policy': {
        'severity':       'low',
        'missing_title':  'Missing Permissions-Policy Header',
        'description':    'No Permissions-Policy header. Browser features like camera and geolocation are unrestricted.',
        'impact':         'Malicious scripts may access browser features without restriction.',
        'recommendation': 'Add: Permissions-Policy: geolocation=(), camera=(), microphone=()',
    },
    'X-XSS-Protection': {
        'severity':       'info',
        'missing_title':  'Missing X-XSS-Protection Header',
        'description':    'X-XSS-Protection header not set (legacy header, mostly superseded by CSP).',
        'impact':         'Minimal risk on modern browsers. Relevant for legacy IE/Edge browsers.',
        'recommendation': 'Add: X-XSS-Protection: 1; mode=block (for legacy browser support)',
    },
}

# Headers that are dangerous if present with weak values
DANGEROUS_HEADER_VALUES = {
    'Server': {
        'severity':       'info',
        'title':          'Server Version Disclosure',
        'description':    'Server header reveals software version: {value}',
        'recommendation': 'Configure the server to suppress version information from the Server header.',
    },
    'X-Powered-By': {
        'severity':       'info',
        'title':          'Technology Disclosure via X-Powered-By',
        'description':    'X-Powered-By header reveals technology stack: {value}',
        'recommendation': 'Remove the X-Powered-By header from server responses.',
    },
    'X-AspNet-Version': {
        'severity':       'low',
        'title':          'ASP.NET Version Disclosure',
        'description':    'X-AspNet-Version header reveals .NET version: {value}',
        'recommendation': 'Disable this header in web.config: <httpRuntime enableVersionHeader="false" />',
    },
}


def _run_headers_check(target: str):
    """
    Run HTTP security headers check using the requests library.
    Makes a single HEAD request (falls back to GET) and checks for
    presence/absence and correctness of security headers.
    Returns (result_text, result_json) matching the run_scan() return format.
    """
    # Ensure target has a scheme
    if not target.startswith(('http://', 'https://')):
        url = f'https://{target}'
    else:
        url = target

    findings  = []
    headers_found = {}
    error_msg = None

    try:
        resp = http_requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False,   # some targets have self-signed certs
            headers={'User-Agent': 'VulnSploit-HeadersCheck/1.0'},
        )
        headers_found = dict(resp.headers)
        final_url     = resp.url
        status_code   = resp.status_code

    except http_requests.exceptions.SSLError:
        # Try HTTP if HTTPS fails
        try:
            http_url = url.replace('https://', 'http://')
            resp         = http_requests.get(http_url, timeout=10, allow_redirects=True,
                                              headers={'User-Agent': 'VulnSploit-HeadersCheck/1.0'})
            headers_found = dict(resp.headers)
            final_url     = resp.url
            status_code   = resp.status_code
        except Exception as e:
            error_msg = str(e)
            headers_found = {}
            final_url     = url
            status_code   = None

    except Exception as e:
        error_msg   = str(e)
        headers_found = {}
        final_url     = url
        status_code   = None

    # Normalize header keys to title-case for consistent lookup
    normalized = {k.title(): v for k, v in headers_found.items()}

    # Check for missing security headers
    for header_name, meta in SECURITY_HEADERS.items():
        is_present = header_name.title() in normalized
        value      = normalized.get(header_name.title(), '')

        findings.append({
            'header':    header_name,
            'present':   is_present,
            'value':     value if is_present else None,
            'severity':  'info' if is_present else meta['severity'],
            'status':    'present' if is_present else 'missing',
            'title':     f'{header_name} Present' if is_present else meta['missing_title'],
            'description': f'{header_name}: {value}' if is_present else meta['description'],
            'recommendation': None if is_present else meta['recommendation'],
        })

    # Check for dangerous disclosure headers
    for header_name, meta in DANGEROUS_HEADER_VALUES.items():
        value = normalized.get(header_name.title())
        if value:
            findings.append({
                'header':        header_name,
                'present':       True,
                'value':         value,
                'severity':      meta['severity'],
                'status':        'dangerous',
                'title':         meta['title'],
                'description':   meta['description'].format(value=value),
                'recommendation': meta['recommendation'],
            })

    # Build result_json
    result_json = {
        'tool':         'headers',
        'target':       final_url,
        'status_code':  status_code,
        'headers_found': normalized,
        'findings':     findings,
        'missing_count': sum(1 for f in findings if f['status'] == 'missing'),
        'error':        error_msg,
    }

    # Build human-readable text output
    lines = [
        f"HTTP Security Headers Check — {final_url}",
        f"Status: {status_code}",
        "=" * 60,
    ]
    if error_msg:
        lines.append(f"ERROR: {error_msg}")
    else:
        for f in findings:
            status_icon = '✓' if f['present'] else '✗'
            lines.append(f"[{status_icon}] {f['header']}: {f['status'].upper()}"
                         + (f" — {f['value']}" if f['value'] else ''))

    result_text = '\n'.join(lines)

    return result_text, result_json

def run_scan(target, scan_type):
    try:
        if scan_type == "nikto":
            command = ["nikto", "-h", target]
        elif scan_type == "sqlmap":
            command = ["sqlmap", "-u", target,
                "--batch",
                "--forms",
                "--crawl=2",
                "--smart",
                "--random-agent",
                "--level=1",
                "--risk=1"
            ]
        elif scan_type == "subfinder":
            command = ["subfinder", "-d", target, "-silent"]
        elif scan_type == "whatweb":
            command = ["whatweb", "--no-errors", "--color=never", "--", target]
        elif scan_type == "gobuster":
            wordlist = config('GOBUSTER_WORDLIST', default='/usr/share/wordlists/common.txt')
            command = ["gobuster", "dir", "-u", target, "-w", wordlist, "--no-error"]
        elif scan_type == "nuclei":
            command = ["nuclei", "-u", target, "-silent", "-jsonl"]
        elif scan_type == "wpscan":
            command = ["wpscan", "--url", target, "--no-update", "--format", "json", "--disable-tls-checks"]
        elif scan_type == "testssl":
            # testssl.sh outputs structured JSON — use --jsonfile to capture it
            command = [
                "bash", "/opt/testssl/testssl.sh",
                "--severity", "LOW",
                "--quiet",
                "--nodns", "min",
                "--jsonfile", "/tmp/testssl_output.json",
                "--warnings", "off",
                "--color", "0",
                target,
            ]
        elif scan_type == "headers":
            # Pure Python — handled separately, no subprocess needed
            return _run_headers_check(target)
        else:
            # Nmap modes
            nmap_modes = {
                "quick":          ["nmap", "-T4", "-F", "--", target],
                "full":           ["nmap", "-sV", "-p-", "--", target],
                "os_detection":   ["nmap", "-O", "--", target],
                "aggressive":     ["nmap", "-A", "--", target],
                "udp":            ["nmap", "-sU", "--", target],
                "ping_sweep":     ["nmap", "-sn", "--", target],
                "service_version":["nmap", "-sV", "--", target],
                "stealth":        ["nmap", "-sS", "--", target],
                "vuln":           ["nmap", "--script", "vuln", "--", target],
            }
            command = nmap_modes.get(scan_type, ["nmap", "--", target])

        timeout = TOOL_TIMEOUTS.get(scan_type, 600)

        result = subprocess.check_output(
            command,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
        )

        json_result = None

        if scan_type == "nuclei":
            json_result = [json.loads(line) for line in result.splitlines() if line.strip()]

        elif scan_type == "wpscan":
            try:
                json_result = json.loads(result)
            except json.JSONDecodeError:
                pass

        elif scan_type == "testssl":
            # Read the JSON file testssl wrote
            try:
                json_path = "/tmp/testssl_output.json"
                if os.path.exists(json_path):
                    with open(json_path, "r") as f:
                        json_result = json.load(f)
                    os.remove(json_path)   # clean up
            except (json.JSONDecodeError, IOError):
                pass

        return result, json_result

    except subprocess.TimeoutExpired:
        raise RuntimeError(f"{scan_type} scan timed out after {TOOL_TIMEOUTS.get(scan_type, 600)}s")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Tool exited with code {e.returncode}:\n{e.output}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error: {str(e)}")
