"""Cross-tenant isolation: one user's data must never reach another user."""
from unittest import mock

import pytest

from scanner.models import (
    FindingStatus, Organization, OrganizationMember, ScanReport, ScanResult,
)
from scanner.suppression import apply_suppressions


def _scan(user, target='example.com', output='80/tcp open http', **kw):
    return ScanResult.objects.create(
        user=user, target=target, scan_type='quick',
        status=ScanResult.Status.COMPLETED, result=output, **kw,
    )


# ─── Report generation only uses scans the requester may see ──────────────────

@pytest.mark.django_db
def test_generate_view_passes_only_authorized_scan_ids(alice, bob, client_for):
    mine, theirs = _scan(alice), _scan(bob, output='SECRET bob output')

    with mock.patch('scanner.views.generate_report.delay') as delay:
        resp = client_for(alice).post(
            '/api/reports/generate/', {'scan_ids': [mine.id, theirs.id]}, format='json',
        )

    assert resp.status_code == 201
    assert delay.call_args.kwargs['scan_ids'] == [mine.id]
    report = ScanReport.objects.get(id=resp.json()['id'])
    assert list(report.scan_results.values_list('id', flat=True)) == [mine.id]


@pytest.mark.django_db
def test_generate_view_rejects_only_foreign_scan_ids(alice, bob, client_for):
    theirs = _scan(bob)
    with mock.patch('scanner.views.generate_report.delay') as delay:
        resp = client_for(alice).post(
            '/api/reports/generate/', {'scan_ids': [theirs.id]}, format='json',
        )
    assert resp.status_code == 400
    delay.assert_not_called()


@pytest.mark.django_db
@pytest.mark.parametrize('bad', ['abc', [1, 'x'], {'a': 1}, [None], 5])
def test_generate_view_rejects_malformed_scan_ids(alice, client_for, bad):
    resp = client_for(alice).post('/api/reports/generate/', {'scan_ids': bad}, format='json')
    assert resp.status_code == 400


@pytest.mark.django_db
def test_generate_task_ignores_foreign_scan_ids(alice, bob):
    """Defence in depth: even if a bad id list reaches the task, only the
    report's own scans may be read."""
    from scanner.tasks import generate_report

    mine, theirs = _scan(alice), _scan(bob, output='SECRET bob output')
    report = ScanReport.objects.create(user=alice, target='example.com')
    report.scan_results.set([mine])

    seen = {}

    def spy(scan_data):
        seen['ids'] = [s['scan_id'] for s in scan_data]
        raise RuntimeError('stop after capture')

    with mock.patch('scanner.cve_enricher.enrich_with_cves', side_effect=spy):
        generate_report(scan_ids=[mine.id, theirs.id], report_id=report.id)

    assert seen['ids'] == [mine.id]


# ─── Finding suppressions are scoped to their owner ───────────────────────────

FINDING = {'title': 'Open Port 22', 'tool': 'nmap', 'severity': 'info'}


def _fp(f=FINDING):
    return f"{f['title'].lower()}|{f['tool']}|"


@pytest.mark.django_db
def test_suppression_from_one_user_does_not_affect_another(alice, bob):
    FindingStatus.objects.create(
        user=alice, target='example.com', fingerprint=_fp(),
        decision=FindingStatus.Decision.FALSE_POSITIVE,
    )

    alice_findings, bob_findings = [dict(FINDING)], [dict(FINDING)]
    apply_suppressions(alice_findings, 'example.com', user=alice)
    apply_suppressions(bob_findings, 'example.com', user=bob)

    assert alice_findings[0].get('suppression') == 'false_positive'
    assert 'suppression' not in bob_findings[0]


@pytest.mark.django_db
def test_org_suppression_applies_to_org_reports_only(alice, bob):
    org = Organization.objects.create(name='Acme', slug='acme', owner=alice)
    OrganizationMember.objects.create(organization=org, user=alice, role='owner')
    FindingStatus.objects.create(
        user=alice, organization=org, target='example.com', fingerprint=_fp(),
        decision=FindingStatus.Decision.ACCEPTED_RISK,
    )

    in_org, private = [dict(FINDING)], [dict(FINDING)]
    apply_suppressions(in_org, 'example.com', user=alice, organization=org)
    apply_suppressions(private, 'example.com', user=alice)

    assert in_org[0].get('suppression') == 'accepted_risk'
    assert 'suppression' not in private[0]


@pytest.mark.django_db
def test_two_users_can_triage_same_target_and_fingerprint(alice, bob, client_for):
    body = {'target': 'example.com', 'fingerprint': _fp(), 'decision': 'false_positive'}
    assert client_for(alice).post('/api/finding-statuses/', body, format='json').status_code == 201
    assert client_for(bob).post('/api/finding-statuses/', body, format='json').status_code == 201


@pytest.mark.django_db
def test_same_user_duplicate_triage_is_a_clean_400(alice, client_for):
    body = {'target': 'example.com', 'fingerprint': _fp(), 'decision': 'false_positive'}
    c = client_for(alice)
    assert c.post('/api/finding-statuses/', body, format='json').status_code == 201
    assert c.post('/api/finding-statuses/', body, format='json').status_code == 400


@pytest.mark.django_db
def test_finding_status_cannot_be_moved_into_foreign_org(alice, bob, client_for):
    foreign = Organization.objects.create(name='Other', slug='other', owner=bob)
    OrganizationMember.objects.create(organization=foreign, user=bob, role='owner')
    fs = FindingStatus.objects.create(
        user=alice, target='example.com', fingerprint=_fp(), decision='false_positive',
    )

    client_for(alice).patch(
        f'/api/finding-statuses/{fs.id}/', {'organization': foreign.id}, format='json',
    )

    fs.refresh_from_db()
    assert fs.organization_id is None
