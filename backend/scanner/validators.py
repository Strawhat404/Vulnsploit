"""
Input validation for scan targets and scan types.
Prevents command injection and invalid inputs from reaching the tool layer.
"""

import re
from rest_framework.exceptions import ValidationError

# ─── Allowed scan types ────────────────────────────────────────────────────────

VALID_SCAN_TYPES = {
    # Nmap modes
    'quick', 'full', 'os_detection', 'aggressive',
    'udp', 'ping_sweep', 'service_version', 'stealth', 'vuln',
    # Web tools
    'nikto', 'gobuster', 'whatweb', 'wpscan',
    # Exploit
    'sqlmap',
    # Recon
    'subfinder', 'nuclei',
    # Full recon (runs all tools)
    'full_recon',
}

# ─── Target validation patterns ────────────────────────────────────────────────

# Valid IPv4 address
_IPV4_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)

# Valid IPv4 CIDR range (e.g. 192.168.1.0/24)
_CIDR_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
)

# Valid hostname / domain (e.g. example.com, sub.example.co.uk)
_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

# Valid URL (http/https prefix)
_URL_RE = re.compile(
    r'^https?://(?:[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+)$'
)

# Characters that are never valid in any target — shell metacharacters
_DANGEROUS_CHARS_RE = re.compile(r'[;&|`$<>\\\'"\n\r\t{}()\[\]]')


def validate_target(target: str) -> str:
    """
    Validate that the target is a safe domain, IP, CIDR, or URL.
    Raises ValidationError if invalid or potentially dangerous.
    Returns the cleaned target string.
    """
    if not target:
        raise ValidationError({'target': 'Target is required.'})

    if len(target) > 253:
        raise ValidationError({'target': 'Target is too long (max 253 characters).'})

    # Block any shell metacharacters immediately
    if _DANGEROUS_CHARS_RE.search(target):
        raise ValidationError({'target': 'Target contains invalid characters.'})

    # Strip http/https prefix for pattern matching (URL is still allowed)
    clean = target.strip()

    is_valid = (
        _IPV4_RE.match(clean)
        or _CIDR_RE.match(clean)
        or _HOSTNAME_RE.match(clean)
        or _URL_RE.match(clean)
    )

    if not is_valid:
        raise ValidationError({
            'target': (
                'Invalid target. Must be a valid domain (example.com), '
                'IP address (192.168.1.1), CIDR range (192.168.1.0/24), '
                'or URL (https://example.com).'
            )
        })

    # Extra IPv4 octet range check
    if _IPV4_RE.match(clean):
        octets = clean.split('.')
        if any(int(o) > 255 for o in octets):
            raise ValidationError({'target': 'Invalid IP address — octet out of range.'})

    return clean


def validate_scan_type(scan_type: str) -> str:
    """
    Validate that the scan type is one of the known allowed values.
    Raises ValidationError if not.
    """
    if not scan_type:
        raise ValidationError({'scan_type': 'Scan type is required.'})

    if scan_type not in VALID_SCAN_TYPES:
        raise ValidationError({
            'scan_type': (
                f"Invalid scan type '{scan_type}'. "
                f"Allowed types: {', '.join(sorted(VALID_SCAN_TYPES))}."
            )
        })

    return scan_type
