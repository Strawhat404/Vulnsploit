"""Scanning requires proof that the user controls the target."""
import socket
from datetime import timedelta
from unittest import mock

import pytest
from django.utils import timezone

from scanner import verification
from scanner.authorization import TargetNotVerified, authorize_target
from scanner.models import (
    Organization, OrganizationMember, ReconSession, ScanResult, ScheduledScan, Target,
)

PUBLIC = '93.184.216.34'


def dns(mapping=None, default=PUBLIC):
    mapping = mapping or {}

    def fake(host, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (mapping.get(host, default), 0))]
    return mock.patch('scanner.netguard.socket.getaddrinfo', side_effect=fake)


@pytest.fixture
def org(alice):
    o = Organization.objects.create(name='Acme', slug='acme', owner=alice)
    OrganizationMember.objects.create(organization=o, user=alice, role='owner')
    return o


# ─── authorize_target ─────────────────────────────────────────────────────────

@pytest.mark.django_db
def test_unverified_target_is_refused(alice):
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, None, 'example.com')


@pytest.mark.django_db
def test_target_saved_but_not_verified_is_refused(alice):
    Target.objects.create(user=alice, name='x', value='example.com', target_type='domain')
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, None, 'example.com')


@pytest.mark.django_db
def test_verified_exact_host_is_allowed(alice, verified_target):
    verified_target(alice, 'example.com')
    authorize_target(alice, None, 'example.com')
    authorize_target(alice, None, 'https://example.com:8443/app?x=1')
    authorize_target(alice, None, 'EXAMPLE.com')


@pytest.mark.django_db
def test_dns_verified_domain_covers_subdomains(alice, verified_target):
    verified_target(alice, 'example.com', method='dns')
    authorize_target(alice, None, 'api.example.com')
    authorize_target(alice, None, 'https://a.b.example.com/')


@pytest.mark.django_db
def test_http_verified_host_does_not_cover_subdomains(alice, verified_target):
    verified_target(alice, 'example.com', method='http')
    authorize_target(alice, None, 'example.com')
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, None, 'api.example.com')


@pytest.mark.django_db
@pytest.mark.parametrize('other', ['notexample.com', 'example.com.evil.net', 'example.org', 'xexample.com'])
def test_lookalike_hosts_are_not_covered(alice, verified_target, other):
    verified_target(alice, 'example.com', method='dns')
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, None, other)


@pytest.mark.django_db
def test_verified_ip_allows_that_ip_only(alice, verified_target):
    verified_target(alice, PUBLIC, method='http', target_type='ip')
    authorize_target(alice, None, PUBLIC)
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, None, '93.184.216.35')


@pytest.mark.django_db
def test_other_users_verification_does_not_help_me(alice, bob, verified_target):
    verified_target(bob, 'example.com')
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, None, 'example.com')


@pytest.mark.django_db
def test_scope_must_match_org_vs_private(alice, org, verified_target):
    verified_target(alice, 'private.example.com', organization=None)
    verified_target(alice, 'shared.example.com', organization=org)
    authorize_target(alice, org, 'shared.example.com')
    authorize_target(alice, None, 'private.example.com')
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, org, 'private.example.com')
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, None, 'shared.example.com')


@pytest.mark.django_db
def test_verification_expires(alice, verified_target, settings):
    settings.TARGET_VERIFICATION_TTL_DAYS = 90
    verified_target(alice, 'old.example.com', verified_at=timezone.now() - timedelta(days=91))
    verified_target(alice, 'new.example.com', verified_at=timezone.now() - timedelta(days=89))
    authorize_target(alice, None, 'new.example.com')
    with pytest.raises(TargetNotVerified, match='expired|verify'):
        authorize_target(alice, None, 'old.example.com')


@pytest.mark.django_db
def test_cidr_ranges_cannot_be_authorized(alice, verified_target):
    verified_target(alice, '93.184.216.0/24', method='http', target_type='cidr')
    with pytest.raises(TargetNotVerified, match='CIDR'):
        authorize_target(alice, None, '93.184.216.0/24')


@pytest.mark.django_db
def test_enforcement_can_be_disabled_for_labs(alice, settings):
    settings.REQUIRE_TARGET_VERIFICATION = False
    authorize_target(alice, None, 'example.com')


# ─── enforced at the API ──────────────────────────────────────────────────────

@pytest.mark.django_db
def test_scan_api_requires_verified_target(alice, client_for, verified_target):
    c = client_for(alice)
    body = {'target': 'example.com', 'scan_type': 'quick'}
    with dns(), mock.patch('scanner.views.execute_scan.delay') as delay:
        resp = c.post('/api/scans/', body, format='json')
        assert resp.status_code == 403
        assert 'verif' in resp.json()['detail'].lower()
        delay.assert_not_called()
        assert ScanResult.objects.count() == 0

        verified_target(alice, 'example.com')
        delay.return_value.id = 't1'
        assert c.post('/api/scans/', body, format='json').status_code == 201


@pytest.mark.django_db
def test_recon_api_requires_verified_target(alice, client_for, verified_target):
    c = client_for(alice)
    with dns(), mock.patch('scanner.views.execute_full_recon.delay') as delay:
        assert c.post('/api/recon/', {'target': 'example.com'}, format='json').status_code == 403
        delay.assert_not_called()
        verified_target(alice, 'example.com')
        delay.return_value.id = 't1'
        assert c.post('/api/recon/', {'target': 'example.com'}, format='json').status_code == 201


@pytest.mark.django_db
def test_scheduled_scan_api_requires_verified_target(alice, client_for, verified_target):
    c = client_for(alice)
    body = {'target': 'example.com', 'scan_type': 'quick', 'cron': '0 2 * * 1'}
    with dns():
        assert c.post('/api/scheduled-scans/', body, format='json').status_code == 403
        assert ScheduledScan.objects.count() == 0
        verified_target(alice, 'example.com')
        assert c.post('/api/scheduled-scans/', body, format='json').status_code == 201


# ─── re-checked when the job actually runs ────────────────────────────────────

@pytest.mark.django_db
def test_execute_scan_refuses_if_verification_is_gone(alice):
    from scanner import tasks
    scan = ScanResult.objects.create(user=alice, target='example.com', scan_type='quick')
    with mock.patch.object(tasks, 'run_scan') as run:
        tasks.execute_scan(scan.id, 'example.com', 'quick')
    run.assert_not_called()
    scan.refresh_from_db()
    assert scan.status == 'failed'
    assert 'verif' in scan.result.lower()


@pytest.mark.django_db
def test_execute_scan_runs_when_verified(alice, verified_target):
    from scanner import tasks
    verified_target(alice, 'example.com')
    scan = ScanResult.objects.create(user=alice, target='example.com', scan_type='quick')
    with mock.patch.object(tasks, 'run_scan', return_value=('ok', None)) as run:
        tasks.execute_scan(scan.id, 'example.com', 'quick')
    run.assert_called_once()
    scan.refresh_from_db()
    assert scan.status == 'completed'


@pytest.mark.django_db
def test_execute_scan_uses_stored_target_not_task_arguments(alice, verified_target):
    """Queue arguments are not trusted: the DB row decides what is scanned."""
    from scanner import tasks
    verified_target(alice, 'example.com')
    scan = ScanResult.objects.create(user=alice, target='example.com', scan_type='quick')
    with mock.patch.object(tasks, 'run_scan', return_value=('ok', None)) as run:
        tasks.execute_scan(scan.id, 'victim.example.net', 'sqlmap')
    run.assert_called_once_with('example.com', 'quick')


@pytest.mark.django_db
def test_full_recon_refuses_if_verification_is_gone(alice):
    from scanner import tasks
    session = ReconSession.objects.create(user=alice, target='example.com')
    with mock.patch.object(tasks, 'run_scan') as run, mock.patch.object(tasks.generate_report, 'delay'):
        tasks.execute_full_recon(session.id)
    run.assert_not_called()
    session.refresh_from_db()
    assert session.status == 'failed'
    assert ScanResult.objects.filter(recon_session=session).count() == 0


@pytest.mark.django_db
def test_scheduled_scan_skipped_if_verification_is_gone(alice):
    from scanner import tasks
    s = ScheduledScan.objects.create(user=alice, target='example.com', scan_type='quick', cron='0 2 * * 1')
    with mock.patch.object(tasks.execute_scan, 'delay') as delay:
        tasks.run_scheduled_scan(s.id)
    delay.assert_not_called()
    assert ScanResult.objects.count() == 0


# ─── target API: challenge + verification ─────────────────────────────────────

def _create_target(client, value='example.com', **kw):
    body = {'name': value, 'value': value, 'target_type': kw.pop('target_type', 'domain'), **kw}
    return client.post('/api/targets/', body, format='json')


@pytest.mark.django_db
def test_new_target_gets_token_and_instructions(alice, client_for):
    resp = _create_target(client_for(alice))
    assert resp.status_code == 201
    data = resp.json()
    assert data['verified'] is False
    assert len(data['verification_token']) >= 32
    assert data['verification']['dns']['name'] == '_vulnsploit-challenge.example.com'
    assert data['verification']['dns']['value'] == data['verification_token']
    assert data['verification']['http']['url'] == 'http://example.com/.well-known/vulnsploit-verification.txt'


@pytest.mark.django_db
def test_targets_get_unique_tokens(alice, client_for):
    c = client_for(alice)
    tokens = {_create_target(c, f'a{i}.example.com').json()['verification_token'] for i in range(5)}
    assert len(tokens) == 5


@pytest.mark.django_db
def test_target_creation_rejects_internal_addresses_but_not_unresolved_names(alice, client_for):
    c = client_for(alice)
    assert _create_target(c, '127.0.0.1', target_type='ip').status_code == 400
    assert _create_target(c, '10.0.0.0/8', target_type='cidr').status_code == 400
    assert _create_target(c, 'http://169.254.169.254/', target_type='url').status_code == 400
    with mock.patch('scanner.netguard.socket.getaddrinfo', side_effect=socket.gaierror):
        assert _create_target(c, 'not-yet-live.example.com').status_code == 201


@pytest.mark.django_db
def test_verify_via_dns(alice, client_for):
    c = client_for(alice)
    t = _create_target(c).json()
    with dns(), mock.patch('scanner.verification._lookup_txt', return_value=[t['verification_token']]) as lookup:
        resp = c.post(f"/api/targets/{t['id']}/verify/",
                      {'method': 'dns', 'confirm_authorization': True}, format='json')
    assert resp.status_code == 200, resp.content
    lookup.assert_called_once_with('_vulnsploit-challenge.example.com')
    data = resp.json()
    assert data['verified'] is True and data['verification_method'] == 'dns'
    row = Target.objects.get(id=t['id'])
    assert row.verified_at and row.authorization_confirmed_at


@pytest.mark.django_db
def test_verify_via_http(alice, client_for):
    c = client_for(alice)
    t = _create_target(c).json()
    with dns(), mock.patch('scanner.verification._fetch_text', return_value=t['verification_token'] + '\n'):
        resp = c.post(f"/api/targets/{t['id']}/verify/",
                      {'method': 'http', 'confirm_authorization': True}, format='json')
    assert resp.status_code == 200
    assert resp.json()['verification_method'] == 'http'


@pytest.mark.django_db
def test_verify_requires_explicit_authorization_confirmation(alice, client_for):
    c = client_for(alice)
    t = _create_target(c).json()
    with dns(), mock.patch('scanner.verification._lookup_txt', return_value=[t['verification_token']]):
        for body in ({'method': 'dns'}, {'method': 'dns', 'confirm_authorization': False}):
            assert c.post(f"/api/targets/{t['id']}/verify/", body, format='json').status_code == 400
    assert Target.objects.get(id=t['id']).verified_at is None


@pytest.mark.django_db
@pytest.mark.parametrize('proof', [[], ['wrong-token'], ['x' * 5, 'also wrong']])
def test_verify_fails_without_the_right_token(alice, client_for, proof):
    c = client_for(alice)
    t = _create_target(c).json()
    with dns(), mock.patch('scanner.verification._lookup_txt', return_value=proof):
        resp = c.post(f"/api/targets/{t['id']}/verify/",
                      {'method': 'dns', 'confirm_authorization': True}, format='json')
    assert resp.status_code == 400
    assert Target.objects.get(id=t['id']).verified_at is None


@pytest.mark.django_db
def test_verify_http_fails_on_wrong_or_missing_content(alice, client_for):
    c = client_for(alice)
    t = _create_target(c).json()
    for body in ('nope', None, ''):
        with dns(), mock.patch('scanner.verification._fetch_text', return_value=body):
            resp = c.post(f"/api/targets/{t['id']}/verify/",
                          {'method': 'http', 'confirm_authorization': True}, format='json')
        assert resp.status_code == 400
    assert Target.objects.get(id=t['id']).verified_at is None


@pytest.mark.django_db
def test_token_hidden_in_longer_text_is_not_accepted(alice, client_for):
    c = client_for(alice)
    t = _create_target(c).json()
    sneaky = f"<html>{t['verification_token']}</html>"
    with dns(), mock.patch('scanner.verification._fetch_text', return_value=sneaky):
        resp = c.post(f"/api/targets/{t['id']}/verify/",
                      {'method': 'http', 'confirm_authorization': True}, format='json')
    assert resp.status_code == 400


@pytest.mark.django_db
def test_verify_rejects_bad_method_cidr_and_dns_for_ip(alice, client_for):
    c = client_for(alice)
    dom = _create_target(c).json()
    ip = _create_target(c, PUBLIC, target_type='ip').json()
    cidr = _create_target(c, '93.184.216.0/24', target_type='cidr').json()
    ok = {'confirm_authorization': True}
    assert c.post(f"/api/targets/{dom['id']}/verify/", {**ok, 'method': 'carrier-pigeon'}, format='json').status_code == 400
    assert c.post(f"/api/targets/{ip['id']}/verify/", {**ok, 'method': 'dns'}, format='json').status_code == 400
    assert c.post(f"/api/targets/{cidr['id']}/verify/", {**ok, 'method': 'http'}, format='json').status_code == 400


@pytest.mark.django_db
def test_cannot_verify_someone_elses_target(alice, bob, client_for):
    t = _create_target(client_for(alice)).json()
    with dns(), mock.patch('scanner.verification._lookup_txt', return_value=[t['verification_token']]):
        resp = client_for(bob).post(f"/api/targets/{t['id']}/verify/",
                                    {'method': 'dns', 'confirm_authorization': True}, format='json')
    assert resp.status_code == 404


@pytest.mark.django_db
def test_verification_fields_cannot_be_set_by_client(alice, client_for):
    c = client_for(alice)
    resp = _create_target(c, verified_at='2030-01-01T00:00:00Z', verification_token='mine',
                          verification_method='dns', authorization_confirmed_at='2030-01-01T00:00:00Z')
    assert resp.status_code == 201
    row = Target.objects.get(id=resp.json()['id'])
    assert row.verified_at is None and row.verification_method == ''
    assert row.verification_token != 'mine'
    c.patch(f'/api/targets/{row.id}/', {'verified_at': '2030-01-01T00:00:00Z', 'verification_token': 'x'}, format='json')
    row.refresh_from_db()
    assert row.verified_at is None and row.verification_token != 'x'


@pytest.mark.django_db
def test_editing_target_value_resets_verification(alice, client_for, verified_target):
    t = verified_target(alice, 'mine.example.com')
    old_token = t.verification_token
    resp = client_for(alice).patch(f'/api/targets/{t.id}/', {'value': 'victim.example.net'}, format='json')
    assert resp.status_code == 200
    t.refresh_from_db()
    assert t.value == 'victim.example.net'
    assert t.verified_at is None and t.verification_method == ''
    assert t.verification_token != old_token
    with pytest.raises(TargetNotVerified):
        authorize_target(alice, None, 'victim.example.net')


@pytest.mark.django_db
def test_editing_other_fields_keeps_verification(alice, client_for, verified_target):
    t = verified_target(alice, 'mine.example.com')
    client_for(alice).patch(f'/api/targets/{t.id}/', {'notes': 'hello'}, format='json')
    t.refresh_from_db()
    assert t.verified_at is not None


# ─── the verification fetch itself must be SSRF-safe ──────────────────────────

def test_http_verification_never_contacts_internal_hosts():
    with dns({'internal.example.com': '10.0.0.5'}), mock.patch('scanner.utils.http_requests.get') as get:
        assert verification._fetch_text('http://internal.example.com/.well-known/x') is None
    get.assert_not_called()


def test_dns_verification_never_resolves_for_ip_hosts():
    with mock.patch('scanner.verification._lookup_txt') as lookup:
        ok, msg = verification.check_dns(PUBLIC, 'tok')
    assert ok is False
    lookup.assert_not_called()
