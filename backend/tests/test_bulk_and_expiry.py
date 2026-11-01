"""Bulk target management, subdomain coverage, and verification-expiry handling."""
import socket
from datetime import timedelta
from unittest import mock

import pytest
from django.core import mail
from django.utils import timezone

from scanner.models import Organization, OrganizationMember, ScheduledScan, Target

pytestmark = pytest.mark.django_db

PUBLIC = '93.184.216.34'
TTL = 90


@pytest.fixture(autouse=True)
def _ttl(settings):
    settings.TARGET_VERIFICATION_TTL_DAYS = TTL


@pytest.fixture
def org(alice):
    o = Organization.objects.create(name='Acme', slug='acme', owner=alice)
    OrganizationMember.objects.create(organization=o, user=alice, role='owner')
    return o


def _member(org, user, role):
    return OrganizationMember.objects.create(organization=org, user=user, role=role)


def _age(target, days_left):
    """Make a verified target have ``days_left`` days of validity remaining."""
    # 5 minutes under the boundary, so 'N days left' means N days or slightly less.
    target.verified_at = timezone.now() - timedelta(days=TTL) + timedelta(days=days_left) - timedelta(minutes=5)
    target.save(update_fields=['verified_at'])
    return target


def _get(client, target):
    return client.get(f'/api/targets/{target.id}/').json()


# ─── subdomain coverage is visible, not just enforced ─────────────────────────

def test_subdomain_shows_verified_when_parent_is_dns_verified(alice, client_for, verified_target):
    verified_target(alice, 'example.com', method='dns')
    sub = Target.objects.create(user=alice, name='api', value='api.example.com', target_type='domain')
    data = _get(client_for(alice), sub)
    assert data['verified'] is True
    assert data['covered_by'] == 'example.com'
    assert data['verification_method'] == ''        # it has no proof of its own


def test_own_verification_is_not_reported_as_coverage(alice, client_for, verified_target):
    t = verified_target(alice, 'example.com', method='dns')
    data = _get(client_for(alice), t)
    assert data['verified'] is True and data['covered_by'] is None


def test_http_verified_parent_does_not_cover_subdomain(alice, client_for, verified_target):
    verified_target(alice, 'example.com', method='http')
    sub = Target.objects.create(user=alice, name='api', value='api.example.com', target_type='domain')
    data = _get(client_for(alice), sub)
    assert data['verified'] is False and data['covered_by'] is None


def test_expired_parent_does_not_cover(alice, client_for, verified_target):
    parent = verified_target(alice, 'example.com', method='dns')
    _age(parent, -1)
    sub = Target.objects.create(user=alice, name='api', value='api.example.com', target_type='domain')
    assert _get(client_for(alice), sub)['verified'] is False


def test_coverage_does_not_cross_users_or_scopes(alice, bob, org, client_for, verified_target):
    verified_target(bob, 'example.com', method='dns')
    verified_target(alice, 'corp.example.net', method='dns', organization=org)
    mine = Target.objects.create(user=alice, name='a', value='a.example.com', target_type='domain')
    private = Target.objects.create(user=alice, name='b', value='b.corp.example.net', target_type='domain')
    c = client_for(alice)
    assert _get(c, mine)['verified'] is False       # bob's proof is not mine
    assert _get(c, private)['verified'] is False    # org proof does not cover a private target


def test_cidr_targets_are_never_reported_as_covered(alice, client_for, verified_target):
    verified_target(alice, 'example.com', method='dns')
    cidr = Target.objects.create(user=alice, name='net', value='93.184.216.0/24', target_type='cidr')
    assert _get(client_for(alice), cidr)['verified'] is False


def test_covered_subdomain_target_can_actually_be_scanned(alice, client_for, verified_target, public_dns):
    verified_target(alice, 'example.com', method='dns')
    with mock.patch('scanner.views.execute_scan.delay') as delay:
        delay.return_value.id = 't'
        resp = client_for(alice).post(
            '/api/scans/', {'target': 'api.example.com', 'scan_type': 'quick'}, format='json')
    assert resp.status_code == 201


# ─── bulk add ─────────────────────────────────────────────────────────────────

def _bulk(client, values, **extra):
    return client.post('/api/targets/bulk/', {'values': values, **extra}, format='json')


def test_bulk_add_creates_many_and_guesses_types(alice, client_for):
    resp = _bulk(client_for(alice), [
        'example.com', 'api.example.com', PUBLIC, '93.184.216.0/24', 'https://shop.example.com/login',
    ])
    assert resp.status_code == 200
    data = resp.json()
    assert data['created'] == 5 and data['existing'] == 0 and data['invalid'] == 0
    types = dict(Target.objects.values_list('value', 'target_type'))
    assert types == {
        'example.com': 'domain', 'api.example.com': 'domain', PUBLIC: 'ip',
        '93.184.216.0/24': 'cidr', 'https://shop.example.com/login': 'url',
    }
    assert len({t.verification_token for t in Target.objects.all()}) == 5


def test_bulk_add_reports_each_item(alice, client_for):
    resp = _bulk(client_for(alice), ['example.com', '127.0.0.1', 'bad host!', 'http://169.254.169.254/'])
    data = resp.json()
    by_value = {r['value']: r for r in data['results']}
    assert by_value['example.com']['status'] == 'created' and by_value['example.com']['id']
    for bad in ('127.0.0.1', 'bad host!', 'http://169.254.169.254/'):
        assert by_value[bad]['status'] == 'invalid' and by_value[bad]['detail']
    assert (data['created'], data['invalid']) == (1, 3)
    assert Target.objects.count() == 1              # one bad line never blocks the rest


def test_bulk_add_skips_existing_and_duplicates_in_request(alice, client_for):
    Target.objects.create(user=alice, name='x', value='example.com', target_type='domain')
    resp = _bulk(client_for(alice), ['example.com', 'new.example.com', 'NEW.example.com', 'new.example.com'])
    data = resp.json()
    assert (data['created'], data['existing']) == (1, 1)
    assert Target.objects.filter(user=alice).count() == 2


def test_bulk_add_ignores_blank_lines_and_trims(alice, client_for):
    resp = _bulk(client_for(alice), ['  example.com  ', '', '   ', 'api.example.com\n'])
    assert resp.json()['created'] == 2


@pytest.mark.parametrize('payload', [None, 'example.com', {'a': 1}, 5])
def test_bulk_add_requires_a_list(alice, client_for, payload):
    assert _bulk(client_for(alice), payload).status_code == 400


def test_bulk_add_caps_request_size(alice, client_for):
    assert _bulk(client_for(alice), [f'h{i}.example.com' for i in range(101)]).status_code == 400
    assert Target.objects.count() == 0
    assert _bulk(client_for(alice), [f'h{i}.example.com' for i in range(100)]).status_code == 200


def test_bulk_add_marks_non_text_items_invalid(alice, client_for):
    data = _bulk(client_for(alice), ['example.com', 123, None, ['x']]).json()
    assert (data['created'], data['invalid']) == (1, 3)


def test_bulk_add_does_no_dns_lookups(alice, client_for):
    with mock.patch('scanner.netguard.socket.getaddrinfo', side_effect=AssertionError('DNS used')):
        assert _bulk(client_for(alice), ['not-live-yet.example.com']).json()['created'] == 1


@pytest.mark.parametrize('role,ok', [('viewer', False), ('analyst', False), ('admin', True), ('owner', True)])
def test_bulk_add_into_org_needs_admin(alice, bob, org, client_for, role, ok):
    _member(org, bob, role) if role != 'owner' else None
    user = alice if role == 'owner' else bob
    resp = _bulk(client_for(user), ['example.com'], organization=org.id)
    assert resp.status_code == (200 if ok else 403)
    assert Target.objects.filter(organization=org).count() == (1 if ok else 0)


def test_bulk_add_cannot_target_an_org_you_are_not_in(alice, bob, org, client_for):
    resp = _bulk(client_for(bob), ['example.com'], organization=org.id)
    assert resp.status_code == 400 and Target.objects.count() == 0


# ─── bulk verify ──────────────────────────────────────────────────────────────

def _bulk_verify(client, ids, method='dns', confirm=True):
    body = {'ids': ids, 'method': method}
    if confirm is not None:
        body['confirm_authorization'] = confirm
    return client.post('/api/targets/verify-bulk/', body, format='json')


def _mk(user, *values, **kw):
    return [Target.objects.create(user=user, name=v, value=v, target_type='domain', **kw) for v in values]


def test_bulk_verify_reports_per_target_results(alice, client_for):
    good, bad = _mk(alice, 'good.example.com', 'bad.example.com')

    def lookup(name):
        return [good.verification_token] if name == '_vulnsploit-challenge.good.example.com' else ['nope']

    with mock.patch('scanner.verification._lookup_txt', side_effect=lookup):
        resp = _bulk_verify(client_for(alice), [good.id, bad.id])
    assert resp.status_code == 200
    data = resp.json()
    by_id = {r['id']: r for r in data['results']}
    assert by_id[good.id]['verified'] is True
    assert by_id[bad.id]['verified'] is False and by_id[bad.id]['detail']
    assert (data['verified'], data['failed']) == (1, 1)
    good.refresh_from_db(); bad.refresh_from_db()
    assert good.verified_at and good.authorization_confirmed_at
    assert bad.verified_at is None


def test_bulk_verify_requires_confirmation_and_valid_method(alice, client_for):
    (t,) = _mk(alice, 'a.example.com')
    c = client_for(alice)
    assert _bulk_verify(c, [t.id], confirm=None).status_code == 400
    assert _bulk_verify(c, [t.id], confirm=False).status_code == 400
    assert _bulk_verify(c, [t.id], method='pigeon').status_code == 400


@pytest.mark.parametrize('ids', [None, 'x', [], [1, 'a'], list(range(1, 22))])
def test_bulk_verify_validates_ids_and_caps_size(alice, client_for, ids):
    assert _bulk_verify(client_for(alice), ids).status_code == 400


def test_bulk_verify_cannot_touch_other_peoples_targets(alice, bob, client_for):
    (mine,) = _mk(alice, 'mine.example.com')
    (theirs,) = _mk(bob, 'theirs.example.com')
    with mock.patch('scanner.verification._lookup_txt', return_value=[theirs.verification_token]):
        data = _bulk_verify(client_for(alice), [mine.id, theirs.id]).json()
    by_id = {r['id']: r for r in data['results']}
    assert by_id[theirs.id]['verified'] is False and 'not found' in by_id[theirs.id]['detail'].lower()
    theirs.refresh_from_db()
    assert theirs.verified_at is None


@pytest.mark.parametrize('role,ok', [('viewer', False), ('analyst', False), ('admin', True)])
def test_bulk_verify_org_targets_needs_admin(alice, bob, org, client_for, role, ok):
    _member(org, bob, role)
    (t,) = _mk(alice, 'org.example.com', organization=org)
    with mock.patch('scanner.verification._lookup_txt', return_value=[t.verification_token]):
        data = _bulk_verify(client_for(bob), [t.id]).json()
    assert data['results'][0]['verified'] is ok
    t.refresh_from_db()
    assert (t.verified_at is not None) == ok


def test_bulk_verify_handles_unverifiable_types(alice, client_for):
    ip = Target.objects.create(user=alice, name='ip', value=PUBLIC, target_type='ip')
    cidr = Target.objects.create(user=alice, name='net', value='93.184.216.0/24', target_type='cidr')
    data = _bulk_verify(client_for(alice), [ip.id, cidr.id], method='dns').json()
    assert [r['verified'] for r in data['results']] == [False, False]
    assert all(r['detail'] for r in data['results'])


# ─── expiry warnings ──────────────────────────────────────────────────────────

@pytest.fixture
def run_warnings():
    from scanner.tasks import warn_expiring_verifications
    return warn_expiring_verifications


def test_no_warning_far_from_expiry(alice, verified_target, run_warnings):
    alice.email = 'alice@example.com'; alice.save()
    _age(verified_target(alice, 'example.com'), 30)
    assert run_warnings() == 0 and mail.outbox == []


def test_warning_sequence_14_3_and_expired_each_sent_once(alice, verified_target, run_warnings):
    alice.email = 'alice@example.com'; alice.save()
    t = verified_target(alice, 'example.com')

    _age(t, 14)
    assert run_warnings() == 1 and len(mail.outbox) == 1
    assert run_warnings() == 0 and len(mail.outbox) == 1        # same day: no repeat

    _age(t, 13)
    assert run_warnings() == 0 and len(mail.outbox) == 1

    _age(t, 3)
    assert run_warnings() == 1 and len(mail.outbox) == 2

    _age(t, -1)                                                  # now expired
    assert run_warnings() == 1 and len(mail.outbox) == 3
    assert run_warnings() == 0 and len(mail.outbox) == 3

    subjects = [m.subject for m in mail.outbox]
    assert all('example.com' in s for s in subjects)
    assert 'expired' in mail.outbox[2].subject.lower()
    assert 'expire' in mail.outbox[0].body.lower()


def test_missed_runs_send_one_catch_up_not_several(alice, verified_target, run_warnings):
    alice.email = 'alice@example.com'; alice.save()
    _age(verified_target(alice, 'example.com'), 2)               # task was down for ages
    assert run_warnings() == 1 and len(mail.outbox) == 1
    assert 'expires in 2 days' in mail.outbox[0].subject         # real time left, not "3"
    assert 'expire in 2 days' in mail.outbox[0].body


def test_reverifying_re_arms_warnings(alice, verified_target, run_warnings):
    from scanner.verification import mark_verified
    alice.email = 'alice@example.com'; alice.save()
    t = verified_target(alice, 'example.com')
    _age(t, 2)
    run_warnings()
    assert len(mail.outbox) == 1

    mark_verified(t, 'dns')                                      # user re-verifies
    t.refresh_from_db()
    assert t.expiry_notice_sent is None
    _age(t, 14)
    run_warnings()
    assert len(mail.outbox) == 2


def test_unverified_and_cidr_targets_are_ignored(alice, run_warnings):
    alice.email = 'alice@example.com'; alice.save()
    Target.objects.create(user=alice, name='x', value='example.com', target_type='domain')
    assert run_warnings() == 0 and mail.outbox == []


def test_org_target_warns_creator_and_org_admins_only(alice, make_user, org, verified_target, run_warnings):
    users = {r: make_user(f'o_{r}') for r in ('viewer', 'analyst', 'admin')}
    for r, u in users.items():
        u.email = f'{r}@example.com'; u.save(); _member(org, u, r)
    alice.email = 'alice@example.com'; alice.save()
    _age(verified_target(alice, 'example.com', organization=org), 3)

    run_warnings()
    recipients = sorted(addr for m in mail.outbox for addr in m.to)
    assert recipients == ['admin@example.com', 'alice@example.com']


def test_users_without_email_are_skipped_quietly(alice, verified_target, run_warnings):
    _age(verified_target(alice, 'example.com'), 3)
    assert run_warnings() == 1 and mail.outbox == []


def test_no_warnings_when_verification_is_not_enforced(alice, verified_target, run_warnings, settings):
    settings.REQUIRE_TARGET_VERIFICATION = False
    alice.email = 'alice@example.com'; alice.save()
    _age(verified_target(alice, 'example.com'), 3)
    assert run_warnings() == 0


def test_warning_task_is_scheduled_daily_via_beat():
    from django_celery_beat.schedulers import DatabaseScheduler
    from django_celery_beat.models import PeriodicTask
    from Vulnsploit.celery import app

    assert 'scanner.tasks.warn_expiring_verifications' in app.tasks or app.loader.import_default_modules() is None
    entry = app.conf.beat_schedule['warn-expiring-verifications']
    assert entry['task'] == 'scanner.tasks.warn_expiring_verifications'

    DatabaseScheduler(app=app)                                   # syncs beat_schedule into the DB
    row = PeriodicTask.objects.get(name='warn-expiring-verifications')
    assert row.task == 'scanner.tasks.warn_expiring_verifications' and row.enabled


# ─── scheduled scans show why they are blocked ────────────────────────────────

def _schedule(user, target, **kw):
    return ScheduledScan.objects.create(
        user=user, target=target, scan_type='quick', cron='0 2 * * 1', **kw)


def test_schedule_not_blocked_while_verified(alice, client_for, verified_target):
    verified_target(alice, 'example.com')
    s = _schedule(alice, 'example.com')
    assert client_for(alice).get(f'/api/scheduled-scans/{s.id}/').json()['blocked_reason'] is None


def test_schedule_blocked_when_never_verified_or_expired(alice, client_for, verified_target):
    s1 = _schedule(alice, 'unverified.example.com')
    t = verified_target(alice, 'old.example.com')
    _age(t, -1)
    s2 = _schedule(alice, 'old.example.com')
    c = client_for(alice)
    assert 'verif' in c.get(f'/api/scheduled-scans/{s1.id}/').json()['blocked_reason'].lower()
    assert 'expired' in c.get(f'/api/scheduled-scans/{s2.id}/').json()['blocked_reason'].lower()


def test_schedule_covered_by_parent_domain_is_not_blocked(alice, client_for, verified_target):
    verified_target(alice, 'example.com', method='dns')
    s = _schedule(alice, 'api.example.com')
    assert client_for(alice).get(f'/api/scheduled-scans/{s.id}/').json()['blocked_reason'] is None
