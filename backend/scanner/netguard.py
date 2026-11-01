"""
Outbound-network guard.

VulnSploit makes network requests to addresses that users supply (scan
targets, webhook URLs, verification URLs). Without a guard, any user could
point the worker at loopback, the private network, or a cloud metadata
service (SSRF), including this deployment's own Redis and database.

Everything here fails closed: a host is only allowed if it parses or
resolves, and *every* address it maps to is publicly routable.

Residual risk: a hostname can resolve differently between the check and the
actual connection (DNS rebinding). We re-check immediately before each use
and refuse redirects, which shrinks the window but does not remove it. Run
scan workers with network egress rules that block internal ranges as well.
"""

import ipaddress
import socket
from urllib.parse import urlparse

from django.conf import settings

# Largest IPv4 range a single target may cover (/24 = 256 addresses).
MIN_CIDR_PREFIX = 24

_NAT64 = ipaddress.ip_network('64:ff9b::/96')

GENERIC_REFUSAL = 'Target is not a publicly routable address.'


class UnsafeTarget(ValueError):
    """Raised when a host or URL must not be contacted."""


def _embedded_ipv4(ip):
    """IPv4 addresses hidden inside an IPv6 address (mapped, 6to4, Teredo, NAT64)."""
    found = []
    if ip.version == 6:
        if ip.ipv4_mapped:
            found.append(ip.ipv4_mapped)
        if ip.sixtofour:
            found.append(ip.sixtofour)
        if ip.teredo:
            found.extend(ip.teredo)
        if ip in _NAT64:
            found.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return found


def is_public_ip(ip) -> bool:
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    if any(not is_public_ip(e) for e in _embedded_ipv4(ip)):
        return False
    return ip.is_global and not ip.is_multicast


def literal_ip(host: str):
    """Return an IP object if ``host`` is an IP literal in any legacy encoding."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    try:
        # inet_aton also accepts 2130706433, 0x7f.0.0.1, 017700000001, 127.1
        return ipaddress.IPv4Address(socket.inet_aton(host))
    except (OSError, ValueError):
        return None


def assert_public_host(host: str, resolve: bool = True) -> None:
    """
    Raise UnsafeTarget unless ``host`` only maps to public addresses.

    With ``resolve=False`` only IP literals are checked; names are accepted
    without a DNS lookup (used when merely *saving* a target, which does not
    contact it).
    """
    if getattr(settings, 'ALLOW_PRIVATE_TARGETS', False):
        return

    host = (host or '').strip().strip('[]').lower()
    if not host:
        raise UnsafeTarget('Target host is empty.')

    literal = literal_ip(host)
    if literal is not None:
        if not is_public_ip(literal):
            raise UnsafeTarget(GENERIC_REFUSAL)
        return

    if not resolve:
        return

    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        raise UnsafeTarget('Could not resolve host.')

    addresses = {info[4][0].split('%')[0] for info in infos}
    if not addresses:
        raise UnsafeTarget('Could not resolve host.')
    for addr in addresses:
        if not is_public_ip(addr):
            raise UnsafeTarget(GENERIC_REFUSAL)


def host_of(target: str) -> str:
    """Hostname (lower-case) of a domain, IP, CIDR or URL target."""
    t = (target or '').strip()
    if '://' in t:
        return (urlparse(t).hostname or '').lower()
    return t.split('/')[0].lower()


def assert_public_url(url: str, resolve: bool = True) -> None:
    """Validate an http(s) URL: no credentials, public host only."""
    parsed = urlparse((url or '').strip())
    if parsed.scheme not in ('http', 'https'):
        raise UnsafeTarget('Only http and https URLs are allowed.')
    if parsed.username or parsed.password or '@' in parsed.netloc:
        raise UnsafeTarget('URLs with embedded credentials are not allowed.')
    if not parsed.hostname:
        raise UnsafeTarget('URL has no host.')
    assert_public_host(parsed.hostname, resolve=resolve)


def assert_public_target(target: str, resolve: bool = True) -> None:
    """Validate a scan target (domain, IP, CIDR range, or URL)."""
    t = (target or '').strip()

    if '://' in t:
        assert_public_url(t, resolve=resolve)
        return

    if '/' in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            raise UnsafeTarget('Invalid CIDR range.')
        if not getattr(settings, 'ALLOW_PRIVATE_TARGETS', False):
            if not (is_public_ip(net.network_address) and is_public_ip(net.broadcast_address)):
                raise UnsafeTarget(GENERIC_REFUSAL)
        if net.version == 4 and net.prefixlen < MIN_CIDR_PREFIX:
            raise UnsafeTarget(
                f'CIDR range too large; use /{MIN_CIDR_PREFIX} or smaller.'
            )
        return

    assert_public_host(t, resolve=resolve)
