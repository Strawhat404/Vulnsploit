"""
Authorization to scan.

A target may only be scanned if the requesting user (or their organization)
holds an unexpired, verified Target that covers its host. This is checked
when a scan is requested *and* again when the job runs, because proof can
expire or be revoked in between.
"""

from datetime import timedelta

from django.conf import settings
from django.db.models import Q
from django.utils import timezone
from rest_framework.exceptions import PermissionDenied

from .models import Target
from .netguard import host_of, literal_ip


class TargetNotVerified(PermissionDenied):
    default_code = 'target_not_verified'


def _scope(user, organization):
    org_id = getattr(organization, 'id', organization)
    if org_id is not None:
        return Q(organization_id=org_id)
    return Q(organization__isnull=True, user=user)


def target_covers(candidate: Target, host: str) -> bool:
    """Does this verified Target authorize scanning ``host``?"""
    chost = host_of(candidate.value)
    if not chost:
        return False
    if host == chost:
        return True
    # DNS proof is control of the whole zone, so it extends to subdomains.
    # A file on one web server proves nothing about its siblings.
    return (
        candidate.verification_method == Target.VerificationMethod.DNS
        and literal_ip(chost) is None
        and host.endswith('.' + chost)
    )


def authorize_target(user, organization, target: str):
    """
    Return the verified Target that authorizes scanning ``target``, or raise
    TargetNotVerified. Returns None when enforcement is disabled (lab mode).
    """
    if not getattr(settings, 'REQUIRE_TARGET_VERIFICATION', True):
        return None

    if user is None:
        raise TargetNotVerified('This scan has no owner, so its target cannot be verified.')

    t = (target or '').strip()
    if '/' in t and '://' not in t:
        raise TargetNotVerified(
            'CIDR ranges cannot be verified yet. Add and verify individual hosts instead.'
        )

    host = host_of(t)
    if not host:
        raise TargetNotVerified('Target has no host.')

    cutoff = timezone.now() - timedelta(days=getattr(settings, 'TARGET_VERIFICATION_TTL_DAYS', 90))
    candidates = (
        Target.objects.filter(_scope(user, organization), verified_at__isnull=False)
        .exclude(target_type=Target.TargetType.CIDR)
    )

    expired = False
    for cand in candidates:
        if not target_covers(cand, host):
            continue
        if cand.verified_at < cutoff:
            expired = True
            continue
        return cand

    if expired:
        raise TargetNotVerified(
            f"Ownership verification for '{host}' has expired. Verify it again under Targets."
        )
    raise TargetNotVerified(
        f"'{host}' is not a verified target. Add it under Targets and verify "
        f"that you control it before scanning."
    )


def is_currently_verified(target: Target) -> bool:
    if not target.verified_at:
        return False
    ttl = getattr(settings, 'TARGET_VERIFICATION_TTL_DAYS', 90)
    return target.verified_at >= timezone.now() - timedelta(days=ttl)


def verification_expires_at(target: Target):
    if not target.verified_at:
        return None
    return target.verified_at + timedelta(days=getattr(settings, 'TARGET_VERIFICATION_TTL_DAYS', 90))


def verification_status(target: Target) -> dict:
    """
    Effective authorization state of a saved Target, for display.

    A target is authorized either by its own unexpired proof, or because a
    DNS-verified parent domain in the same scope covers it (the same rule
    ``authorize_target`` enforces when a scan is requested).
    """
    own = is_currently_verified(target)
    if own:
        return {'verified': True, 'covered_by': None,
                'expires_at': verification_expires_at(target)}

    if target.target_type == Target.TargetType.CIDR or ('/' in target.value and '://' not in target.value):
        return {'verified': False, 'covered_by': None, 'expires_at': None}

    host = host_of(target.value)
    if not host:
        return {'verified': False, 'covered_by': None, 'expires_at': None}

    if target.organization_id is not None:
        scope = Q(organization_id=target.organization_id)
    else:
        scope = Q(organization__isnull=True, user_id=target.user_id)
    cutoff = timezone.now() - timedelta(days=getattr(settings, 'TARGET_VERIFICATION_TTL_DAYS', 90))
    candidates = (
        Target.objects.filter(scope, verified_at__isnull=False, verified_at__gte=cutoff)
        .exclude(pk=target.pk).exclude(target_type=Target.TargetType.CIDR)
    )
    for cand in candidates:
        if target_covers(cand, host):
            return {'verified': True, 'covered_by': cand.value,
                    'expires_at': verification_expires_at(cand)}
    return {'verified': False, 'covered_by': None, 'expires_at': None}
