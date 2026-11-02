"""
Proof-of-control checks for scan targets.

Two methods, both of which require the user to change something only the
real owner can:
  dns   a TXT record at _vulnsploit-challenge.<host> equal to the token
  http  a file at /.well-known/vulnsploit-verification.txt containing it

Every outbound request here goes through the SSRF guard, and redirects to a
different host are refused (a redirect would let a different site vouch for
this one).
"""

import logging
from urllib.parse import urlparse

from django.utils import timezone

from .models import Target
from .netguard import assert_public_url, host_of, literal_ip

logger = logging.getLogger('scanner')

CHALLENGE_LABEL = '_vulnsploit-challenge'
WELL_KNOWN_PATH = '/.well-known/vulnsploit-verification.txt'
MAX_PROOF_BYTES = 2048


def challenge_instructions(host: str, token: str) -> dict:
    """What the user must publish, per method, for this host."""
    out = {'http': {
        'url': f'http://{host}{WELL_KNOWN_PATH}',
        'content': token,
    }}
    if literal_ip(host) is None:
        out['dns'] = {
            'type': 'TXT',
            'name': f'{CHALLENGE_LABEL}.{host}',
            'value': token,
        }
    return out


def _lookup_txt(name: str) -> list:
    import dns.resolver

    answers = dns.resolver.resolve(name, 'TXT', lifetime=5)
    return [b''.join(r.strings).decode('utf-8', 'replace') for r in answers]


def check_dns(host: str, token: str):
    if literal_ip(host) is not None:
        return False, 'DNS verification needs a domain name, not an IP address. Use the file method.'
    name = f'{CHALLENGE_LABEL}.{host}'
    try:
        records = _lookup_txt(name)
    except Exception as exc:
        logger.info("TXT lookup failed for %s: %s", name, type(exc).__name__)
        return False, f'No TXT record found at {name}. DNS changes can take a few minutes to propagate.'
    if any(r.strip().strip('"') == token for r in records):
        return True, 'DNS record verified.'
    return False, f'A TXT record exists at {name} but its value does not match the token.'


def _fetch_text(url: str):
    """Fetch a small text file from a public host; None on any problem."""
    from .utils import _fetch_validated

    try:
        assert_public_url(url)
        resp = _fetch_validated(url, verify=True, close=False)
    except Exception as exc:
        logger.info("Verification fetch failed for %s: %s", url, type(exc).__name__)
        return None

    try:
        if resp.status_code != 200:
            return None
        # A different final host would mean someone else is vouching for us.
        if (urlparse(resp.url).hostname or '').lower() != (urlparse(url).hostname or '').lower():
            return None
        body = next(resp.iter_content(MAX_PROOF_BYTES), b'')
        return body.decode('utf-8', 'replace')
    except Exception:
        return None
    finally:
        try:
            resp.close()
        except Exception:
            pass


def check_http(host: str, token: str):
    for scheme in ('http', 'https'):
        text = _fetch_text(f'{scheme}://{host}{WELL_KNOWN_PATH}')
        # Exact match only: a token buried in a page would let anyone who can
        # reflect text on the site (search box, error page) "prove" ownership.
        if text is not None and text.strip() == token:
            return True, 'File verified.'
    return False, f'Could not find the token at http://{host}{WELL_KNOWN_PATH}.'


def verify_target(target: Target, method: str):
    """Run the chosen check. Returns (ok, message); does not save."""
    if target.target_type == Target.TargetType.CIDR or ('/' in target.value and '://' not in target.value):
        return False, 'CIDR ranges cannot be verified yet. Add and verify individual hosts instead.'

    host = host_of(target.value)
    if not host:
        return False, 'Target has no host.'

    if method == Target.VerificationMethod.DNS:
        return check_dns(host, target.verification_token)
    if method == Target.VerificationMethod.HTTP:
        return check_http(host, target.verification_token)
    return False, "Method must be 'dns' or 'http'."


def mark_verified(target: Target, method: str):
    now = timezone.now()
    target.verification_method = method
    target.verified_at = now
    target.authorization_confirmed_at = now
    target.expiry_notice_sent = None
    target.save(update_fields=[
        'verification_method', 'verified_at', 'authorization_confirmed_at', 'expiry_notice_sent',
    ])
