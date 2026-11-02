"""
Finding suppression — applies FindingStatus decisions (false positive,
accepted risk, rememediated) to findings before they reach the report
or API. Suppressions persist across scans because they're keyed by
target + finding fingerprint, not by report ID.
"""

import logging
from django.db.models import Q
from .models import FindingStatus

logger = logging.getLogger('scanner')


def _finding_fingerprint(finding: dict) -> str:
    """
    Build a fingerprint matching the FindingStatus model's fingerprint
    field. Must match the fingerprint used when creating suppressions.
    """
    title = (finding.get('title') or '').strip().lower()[:200]
    tool = (finding.get('tool') or '').strip().lower()[:50]
    cve_id = (finding.get('cve_id') or '').strip().lower()[:30]
    return f"{title}|{tool}|{cve_id}"


def _scoped_statuses(target: str, user=None, organization=None):
    """
    FindingStatus rows visible to this report's owner: the organization's
    shared decisions for an org report, otherwise the user's own private
    ones. Never another tenant's.
    """
    if organization is not None:
        scope = Q(organization=organization)
    elif user is not None:
        scope = Q(organization__isnull=True, user=user)
    else:
        return FindingStatus.objects.none()
    return FindingStatus.objects.filter(scope, target=target)


def apply_suppressions(findings: list, target: str, user=None, organization=None) -> dict:
    """
    Apply suppressions to a list of findings for a given target.
    Mutates the findings list in place by adding a 'suppression' field
    to each finding that has a non-open FindingStatus.

    Returns stats dict:
    {
        'total_findings': int,
        'suppressed_count': int,
        'false_positive_count': int,
        'accepted_risk_count': int,
        'remediated_count': int,
    }
    """
    if not findings or not target:
        return {
            'total_findings': len(findings or []),
            'suppressed_count': 0,
            'false_positive_count': 0,
            'accepted_risk_count': 0,
            'remediated_count': 0,
        }

    # Load all suppressions for this target in one query
    suppressions = {}
    for fs in _scoped_statuses(target, user, organization).exclude(decision='open'):
        suppressions[fs.fingerprint] = fs.decision

    if not suppressions:
        return {
            'total_findings': len(findings),
            'suppressed_count': 0,
            'false_positive_count': 0,
            'accepted_risk_count': 0,
            'remediated_count': 0,
        }

    suppressed = 0
    fp_count = 0
    ar_count = 0
    rem_count = 0

    for finding in findings:
        fp = _finding_fingerprint(finding)
        if fp in suppressions:
            decision = suppressions[fp]
            finding['suppression'] = decision
            suppressed += 1
            if decision == 'false_positive':
                fp_count += 1
            elif decision == 'accepted_risk':
                ar_count += 1
            elif decision == 'remediated':
                rem_count += 1

    logger.info(
        "Suppression applied: %d/%d findings suppressed on %s (FP=%d, AR=%d, REM=%d)",
        suppressed, len(findings), target, fp_count, ar_count, rem_count,
    )

    return {
        'total_findings': len(findings),
        'suppressed_count': suppressed,
        'false_positive_count': fp_count,
        'accepted_risk_count': ar_count,
        'remediated_count': rem_count,
    }


def get_suppression_fingerprints(target: str, user=None, organization=None) -> set:
    """
    Return the set of fingerprints that should be suppressed
    (excluded from severity counts) for a given target and owner scope.
    Useful for filtering findings before posture score calculation.
    """
    return set(
        _scoped_statuses(target, user, organization)
        .exclude(decision='open')
        .values_list('fingerprint', flat=True)
    )
