import subprocess
import json
import os
import ssl
import socket
from datetime import datetime, timezone as dt_tz
from urllib.parse import urlparse, urljoin
from decouple import config
import requests as http_requests

from .netguard import UnsafeTarget, assert_public_host, assert_public_target, assert_public_url

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


def _check_ssl_cert(hostname: str, port: int = 443) -> dict:
    """
    Connect to hostname:port and retrieve the SSL certificate.
    Returns a dict with:
      - not_before:   str (ISO date)
      - not_after:    str (ISO date)
      - days_remaining: int
      - expired:      bool
      - self_signed:  bool
      - issuer:       str
      - subject:      str
    Returns None if the connection fails or no cert is available.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            # Self-signed certs may not be returned by getpeercert()
            # when verify_mode is CERT_NONE. Try the binary form.
            try:
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    return {
                        'not_before':     '',
                        'not_after':      '',
                        'days_remaining': None,
                        'expired':        False,
                        'self_signed':    True,
                        'issuer':         'Self-signed',
                        'subject':        hostname,
                    }
            except Exception:
                pass
            return None

        # Parse cert dates (format: 'Jul 22 12:00:00 2026 GMT')
        not_before_str = cert.get('notBefore', '')
        not_after_str  = cert.get('notAfter', '')

        not_after  = _parse_ssl_date(not_after_str)
        not_before = _parse_ssl_date(not_before_str)

        now = datetime.now(dt_tz.utc)

        days_remaining = None
        expired = False
        if not_after:
            days_remaining = (not_after - now).days
            expired = days_remaining < 0

        # Check if self-signed (issuer == subject)
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        subject = dict(x[0] for x in cert.get('subject', ()))
        self_signed = issuer == subject

        return {
            'not_before':     not_before.strftime('%Y-%m-%d') if not_before else not_before_str,
            'not_after':      not_after.strftime('%Y-%m-%d') if not_after else not_after_str,
            'days_remaining': days_remaining,
            'expired':        expired,
            'self_signed':    self_signed,
            'issuer':         issuer.get('organizationName', str(issuer))[:100],
            'subject':        subject.get('commonName', hostname)[:100],
        }

    except Exception as e:
        # Connection failed — not an HTTPS host or port closed
        return None


def _parse_ssl_date(date_str: str):
    """Parse SSL date format: 'Jul 22 12:00:00 2026 GMT' → datetime."""
    try:
        return datetime.strptime(date_str, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt_tz.utc)
    except (ValueError, TypeError):
        return None


MAX_REDIRECTS = 5
_REDIRECT_CODES = (301, 302, 303, 307, 308)


def _fetch_validated(url: str, verify: bool, close: bool = True):
    """
    GET ``url`` following redirects ourselves so every hop is checked against
    the SSRF guard. A public site must not be able to bounce us to an
    internal address.
    """
    for _ in range(MAX_REDIRECTS + 1):
        assert_public_url(url)
        resp = http_requests.get(
            url,
            timeout=10,
            allow_redirects=False,
            verify=verify,
            stream=True,  # headers only; never buffer a hostile body
            headers={'User-Agent': 'VulnSploit-HeadersCheck/1.0'},
        )
        location = resp.headers.get('Location')
        if resp.status_code in _REDIRECT_CODES and location:
            url = urljoin(resp.url or url, location)
            try:
                resp.close()
            except Exception:
                pass
            continue
        if close:
            try:
                resp.close()
            except Exception:
                pass
        return resp
    raise RuntimeError(f'Too many redirects (more than {MAX_REDIRECTS})')


def _run_headers_check(target: str):
    """
    Run HTTP security headers check using the requests library.
    Makes a single HEAD request (falls back to GET) and checks for
    presence/absence and correctness of security headers.
    Also extracts SSL certificate expiration info when HTTPS is used.
    Returns (result_text, result_json) matching the run_scan() return format.
    """
    import ssl
    import socket
    from urllib.parse import urlparse
    from datetime import datetime, timezone as dt_tz

    # Ensure target has a scheme
    if not target.startswith(('http://', 'https://')):
        url = f'https://{target}'
    else:
        url = target

    findings  = []
    headers_found = {}
    error_msg = None
    cert_info = None

    try:
        resp = _fetch_validated(url, verify=False)  # some targets have self-signed certs
        headers_found = dict(resp.headers)
        final_url     = resp.url
        status_code   = resp.status_code

    except http_requests.exceptions.SSLError:
        # Try HTTP if HTTPS fails
        try:
            http_url = url.replace('https://', 'http://')
            resp         = _fetch_validated(http_url, verify=True)
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

    # ── SSL certificate expiration check ──────────────────────────────
    # Extract the hostname from the URL and connect to retrieve the cert.
    # This runs independently of the HTTP request above so we still get
    # cert info even if the HTTP request failed due to SSL errors.
    parsed = urlparse(final_url or url)
    hostname = parsed.hostname
    cert_host_ok = False
    if hostname:
        try:
            assert_public_host(hostname)
            cert_host_ok = True
        except UnsafeTarget:
            pass
    if cert_host_ok and (final_url or url).startswith('https://'):
        cert_info = _check_ssl_cert(hostname, 443)
        if cert_info:
            if cert_info.get('expired'):
                findings.append({
                    'header':        'SSL Certificate',
                    'present':       True,
                    'value':         f"expired: {cert_info.get('not_after', '')}",
                    'severity':      'critical',
                    'status':        'dangerous',
                    'title':         'SSL Certificate Expired',
                    'description':   f"The SSL/TLS certificate expired on {cert_info.get('not_after', 'unknown date')}. "
                                     f"Browsers will reject connections and display security warnings.",
                    'recommendation': 'Renew the SSL certificate immediately.',
                })
            elif cert_info.get('days_remaining') is not None and cert_info['days_remaining'] <= 30:
                days = cert_info['days_remaining']
                sev = 'high' if days <= 7 else 'medium' if days <= 14 else 'low'
                findings.append({
                    'header':        'SSL Certificate',
                    'present':       True,
                    'value':         f"expires in {days} days",
                    'severity':      sev,
                    'status':        'dangerous',
                    'title':         f'SSL Certificate Expiring Soon ({days} days)',
                    'description':   f"The SSL/TLS certificate will expire on {cert_info.get('not_after', '')}, "
                                     f"in {days} days. Action is needed to avoid service disruption.",
                    'recommendation': 'Renew the SSL certificate before it expires to avoid service interruption.',
                })
            elif cert_info.get('self_signed'):
                findings.append({
                    'header':        'SSL Certificate',
                    'present':       True,
                    'value':         'self-signed',
                    'severity':      'medium',
                    'status':        'dangerous',
                    'title':         'Self-Signed SSL Certificate',
                    'description':   'The SSL/TLS certificate is self-signed and not trusted by browsers.',
                    'recommendation': 'Replace with a certificate from a trusted Certificate Authority (Let\'s Encrypt, DigiCert, etc.).',
                })

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
        'cert_info':    cert_info,
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
    # Re-check at execution time: the target may have resolved differently
    # since it was validated at request time (DNS rebinding), or the job may
    # have been queued by an older code path. subfinder only queries passive
    # DNS sources and never contacts the target, so it is exempt.
    if scan_type != 'subfinder':
        try:
            assert_public_target(target)
        except UnsafeTarget as exc:
            raise RuntimeError(str(exc))

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
                "--", target,
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
