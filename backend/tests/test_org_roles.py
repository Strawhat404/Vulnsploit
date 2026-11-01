"""Organization roles are enforced on every org-scoped endpoint."""
from unittest import mock

import pytest

from scanner.models import (
    AuditLog, FindingStatus, Organization, OrganizationMember, ScanResult,
    ScheduledScan, Target, WebhookEndpoint,
)

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures('public_dns')]

ROLES = ['viewer', 'analyst', 'admin', 'owner']


@pytest.fixture
def team(make_user):
    users = {r: make_user(f'u_{r}') for r in ROLES}
    users['outsider'] = make_user('u_outsider')
    org = Organization.objects.create(name='Acme', slug='acme', owner=users['owner'])
    for r in ROLES:
        OrganizationMember.objects.create(organization=org, user=users[r], role=r)
    return {**users, 'org': org}


def api(team, role, client_for):
    return client_for(team[role])


def allowed(*roles):
    """Parametrize helper: (role, expected_allowed)."""
    return [(r, r in roles) for r in ROLES]


def check(resp, ok, success=(200, 201, 204)):
    if ok:
        assert resp.status_code in success, (resp.status_code, resp.content)
    else:
        assert resp.status_code == 403, (resp.status_code, resp.content)


# ─── reads: any member, nobody else ───────────────────────────────────────────

@pytest.mark.parametrize('role', ROLES)
def test_every_member_can_read_org_data(team, client_for, role, verified_target):
    ScanResult.objects.create(user=team['owner'], organization=team['org'], target='example.com', scan_type='quick')
    verified_target(team['owner'], 'example.com', organization=team['org'])
    c = client_for(team[role])
    assert len(c.get('/api/scans/').json()['results']) == 1
    assert len(c.get('/api/targets/').json()['results'] if 'results' in c.get('/api/targets/').json() else c.get('/api/targets/').json()) == 1


def test_outsider_sees_nothing(team, client_for, verified_target):
    ScanResult.objects.create(user=team['owner'], organization=team['org'], target='example.com', scan_type='quick')
    verified_target(team['owner'], 'example.com', organization=team['org'])
    c = client_for(team['outsider'])
    assert c.get('/api/scans/').json()['results'] == []
    assert c.get(f"/api/scans/{ScanResult.objects.get().id}/").status_code == 404


# ─── analyst-level actions ────────────────────────────────────────────────────

@pytest.mark.parametrize('role,ok', allowed('analyst', 'admin', 'owner'))
def test_launch_scan(team, client_for, verified_target, role, ok):
    verified_target(team['owner'], 'example.com', organization=team['org'])
    with mock.patch('scanner.views.execute_scan.delay') as delay:
        delay.return_value.id = 't'
        resp = client_for(team[role]).post(
            '/api/scans/',
            {'target': 'example.com', 'scan_type': 'quick', 'organization': team['org'].id}, format='json')
    check(resp, ok)
    assert delay.called == ok


@pytest.mark.parametrize('role,ok', allowed('analyst', 'admin', 'owner'))
def test_launch_recon(team, client_for, verified_target, role, ok):
    verified_target(team['owner'], 'example.com', organization=team['org'])
    with mock.patch('scanner.views.execute_full_recon.delay') as delay:
        delay.return_value.id = 't'
        resp = client_for(team[role]).post(
            '/api/recon/', {'target': 'example.com', 'organization': team['org'].id}, format='json')
    check(resp, ok)


@pytest.mark.parametrize('role,ok', allowed('analyst', 'admin', 'owner'))
def test_generate_report(team, client_for, role, ok):
    scan = ScanResult.objects.create(
        user=team['owner'], organization=team['org'], target='example.com',
        scan_type='quick', status='completed', result='x')
    with mock.patch('scanner.views.generate_report.delay'):
        resp = client_for(team[role]).post(
            '/api/reports/generate/', {'scan_ids': [scan.id], 'organization': team['org'].id}, format='json')
    check(resp, ok)


@pytest.mark.parametrize('role,ok', allowed('analyst', 'admin', 'owner'))
def test_cancel_scan(team, client_for, role, ok):
    scan = ScanResult.objects.create(
        user=team['owner'], organization=team['org'], target='example.com',
        scan_type='quick', status='running', celery_task_id='abc')
    with mock.patch('celery.app.control.Control.revoke'):
        resp = client_for(team[role]).post(f'/api/scans/{scan.id}/cancel/')
    check(resp, ok)
    scan.refresh_from_db()
    assert (scan.status == 'failed') == ok


@pytest.mark.parametrize('role,ok', allowed('analyst', 'admin', 'owner'))
def test_triage_findings(team, client_for, role, ok):
    body = {'target': 'example.com', 'fingerprint': 'f', 'decision': 'false_positive',
            'organization': team['org'].id}
    check(client_for(team[role]).post('/api/finding-statuses/', body, format='json'), ok)


@pytest.mark.parametrize('role,ok', allowed('analyst', 'admin', 'owner'))
def test_edit_and_delete_triage(team, client_for, role, ok):
    fs = FindingStatus.objects.create(
        user=team['owner'], organization=team['org'], target='example.com',
        fingerprint='f', decision='false_positive')
    c = client_for(team[role])
    check(c.patch(f'/api/finding-statuses/{fs.id}/', {'note': 'x'}, format='json'), ok)
    check(c.delete(f'/api/finding-statuses/{fs.id}/'), ok)


# ─── admin-level actions ──────────────────────────────────────────────────────

@pytest.mark.parametrize('role,ok', allowed('admin', 'owner'))
def test_create_target(team, client_for, role, ok):
    body = {'name': 'x', 'value': 'example.com', 'target_type': 'domain', 'organization': team['org'].id}
    check(client_for(team[role]).post('/api/targets/', body, format='json'), ok)


@pytest.mark.parametrize('role,ok', allowed('admin', 'owner'))
def test_edit_delete_verify_target(team, client_for, verified_target, role, ok):
    t = verified_target(team['owner'], 'example.com', organization=team['org'])
    c = client_for(team[role])
    check(c.patch(f'/api/targets/{t.id}/', {'notes': 'x'}, format='json'), ok)
    with mock.patch('scanner.verification._lookup_txt', return_value=[t.verification_token]):
        check(c.post(f'/api/targets/{t.id}/verify/',
                     {'method': 'dns', 'confirm_authorization': True}, format='json'), ok)
    check(c.delete(f'/api/targets/{t.id}/'), ok)


@pytest.mark.parametrize('role,ok', allowed('admin', 'owner'))
def test_scheduled_scans(team, client_for, verified_target, role, ok):
    verified_target(team['owner'], 'example.com', organization=team['org'])
    c = client_for(team[role])
    body = {'target': 'example.com', 'scan_type': 'quick', 'cron': '0 2 * * 1', 'organization': team['org'].id}
    check(c.post('/api/scheduled-scans/', body, format='json'), ok)

    s = ScheduledScan.objects.create(user=team['owner'], organization=team['org'], target='example.com',
                                     scan_type='quick', cron='0 3 * * 1')
    check(c.patch(f'/api/scheduled-scans/{s.id}/', {'is_active': False}, format='json'), ok)
    check(c.delete(f'/api/scheduled-scans/{s.id}/'), ok)


@pytest.mark.parametrize('role,ok', allowed('admin', 'owner'))
def test_webhooks(team, client_for, role, ok):
    c = client_for(team[role])
    body = {'name': 'w', 'url': 'https://hooks.example.com/x', 'events': ['report.ready'],
            'organization': team['org'].id}
    check(c.post('/api/webhooks/', body, format='json'), ok)
    wh = WebhookEndpoint.objects.create(user=team['owner'], organization=team['org'], name='w',
                                        url='https://hooks.example.com/y', events=[])
    check(c.patch(f'/api/webhooks/{wh.id}/', {'name': 'n'}, format='json'), ok)
    check(c.delete(f'/api/webhooks/{wh.id}/'), ok)


@pytest.mark.parametrize('role,ok', allowed('admin', 'owner'))
def test_audit_log_visibility(team, client_for, role, ok):
    AuditLog.objects.create(user=team['owner'], organization=team['org'], action='ORG-SECRET-ACTION')
    AuditLog.objects.create(user=team[role], action='MY-PRIVATE-ACTION')
    actions = {e['action'] for e in client_for(team[role]).get('/api/audit-logs/').json()['results']}
    assert ('ORG-SECRET-ACTION' in actions) == ok
    assert 'MY-PRIVATE-ACTION' in actions


# ─── owner-only: the organization itself ──────────────────────────────────────

@pytest.mark.parametrize('role,ok', allowed('owner'))
def test_edit_and_delete_organization(team, client_for, role, ok):
    c = client_for(team[role])
    org = team['org']
    check(c.patch(f'/api/organizations/{org.id}/', {'name': 'Renamed'}, format='json'), ok)
    check(c.delete(f'/api/organizations/{org.id}/'), ok)
    assert Organization.objects.filter(id=org.id).exists() == (not ok)


def test_anyone_can_create_their_own_organization(make_user, client_for):
    u = make_user('newbie')
    resp = client_for(u).post('/api/organizations/', {'name': 'Mine', 'slug': 'mine'}, format='json')
    assert resp.status_code == 201
    assert OrganizationMember.objects.get(user=u).role == 'owner'


# ─── members ──────────────────────────────────────────────────────────────────

def _add(c, team, user, role):
    return c.post('/api/organization-members/',
                  {'organization': team['org'].id, 'user': user.id, 'role': role}, format='json')


@pytest.mark.parametrize('role', ['viewer', 'analyst'])
def test_low_roles_cannot_add_members(team, client_for, role):
    assert _add(client_for(team[role]), team, team['outsider'], 'viewer').status_code == 403


@pytest.mark.parametrize('new_role,ok', [('viewer', True), ('analyst', True), ('admin', False), ('owner', False)])
def test_admin_can_add_only_below_admin(team, client_for, new_role, ok):
    check(_add(client_for(team['admin']), team, team['outsider'], new_role), ok)


@pytest.mark.parametrize('new_role', ROLES)
def test_owner_can_add_any_role(team, client_for, new_role):
    assert _add(client_for(team['owner']), team, team['outsider'], new_role).status_code == 201


def test_cannot_add_members_to_org_you_are_not_in(team, client_for, make_user):
    other = make_user('someone')
    resp = _add(client_for(other), team, team['outsider'], 'viewer')
    assert resp.status_code in (400, 403)
    assert not OrganizationMember.objects.filter(user=team['outsider']).exists()


def _member(team, role):
    return OrganizationMember.objects.get(organization=team['org'], user=team[role])


def test_admin_cannot_escalate_anyone_to_admin_or_owner(team, client_for):
    c = client_for(team['admin'])
    for role in ('analyst', 'viewer'):
        for new in ('admin', 'owner'):
            resp = c.patch(f'/api/organization-members/{_member(team, role).id}/', {'role': new}, format='json')
            assert resp.status_code == 403
            assert _member(team, role).role == role


def test_admin_can_move_analyst_and_viewer_between_those_roles(team, client_for):
    c = client_for(team['admin'])
    assert c.patch(f'/api/organization-members/{_member(team, "viewer").id}/', {'role': 'analyst'}, format='json').status_code == 200
    assert _member(team, 'viewer').role == 'analyst'


def test_admin_cannot_touch_admins_or_owners(team, client_for):
    c = client_for(team['admin'])
    owner_m = _member(team, 'owner')
    assert c.patch(f'/api/organization-members/{owner_m.id}/', {'role': 'viewer'}, format='json').status_code == 403
    assert c.delete(f'/api/organization-members/{owner_m.id}/').status_code == 403
    assert _member(team, 'owner').role == 'owner'


@pytest.mark.parametrize('role', ['viewer', 'analyst'])
def test_low_roles_cannot_edit_or_remove_others(team, client_for, role):
    c = client_for(team[role])
    other = _member(team, 'analyst' if role == 'viewer' else 'viewer')
    assert c.patch(f'/api/organization-members/{other.id}/', {'role': 'admin'}, format='json').status_code == 403
    assert c.delete(f'/api/organization-members/{other.id}/').status_code == 403


def test_cannot_change_your_own_role(team, client_for):
    resp = client_for(team['analyst']).patch(
        f'/api/organization-members/{_member(team, "analyst").id}/', {'role': 'owner'}, format='json')
    assert resp.status_code == 403
    assert _member(team, 'analyst').role == 'analyst'
    resp = client_for(team['owner']).patch(
        f'/api/organization-members/{_member(team, "owner").id}/', {'role': 'viewer'}, format='json')
    assert resp.status_code == 403


def test_owner_can_promote_and_remove(team, client_for):
    c = client_for(team['owner'])
    m = _member(team, 'analyst')
    assert c.patch(f'/api/organization-members/{m.id}/', {'role': 'admin'}, format='json').status_code == 200
    assert c.delete(f'/api/organization-members/{m.id}/').status_code == 204


def test_last_owner_cannot_leave_but_others_can(team, client_for):
    own = _member(team, 'owner')
    assert client_for(team['owner']).delete(f'/api/organization-members/{own.id}/').status_code == 403
    assert OrganizationMember.objects.filter(id=own.id).exists()

    # a plain member can leave
    v = _member(team, 'viewer')
    assert client_for(team['viewer']).delete(f'/api/organization-members/{v.id}/').status_code == 204


def test_second_owner_can_be_demoted_by_the_first(team, client_for):
    second = OrganizationMember.objects.create(
        organization=team['org'], user=team['outsider'], role='owner')
    resp = client_for(team['owner']).patch(
        f'/api/organization-members/{second.id}/', {'role': 'viewer'}, format='json')
    assert resp.status_code == 200


def test_membership_cannot_be_moved_to_another_org_or_user(team, client_for, make_user):
    other_owner = make_user('other_owner')
    other_org = Organization.objects.create(name='Other', slug='other', owner=other_owner)
    OrganizationMember.objects.create(organization=other_org, user=other_owner, role='owner')
    m = _member(team, 'viewer')
    client_for(team['owner']).patch(
        f'/api/organization-members/{m.id}/',
        {'organization': other_org.id, 'user': team['outsider'].id}, format='json')
    m.refresh_from_db()
    assert m.organization_id == team['org'].id and m.user_id == team['viewer'].id


# ─── roles are per organization ───────────────────────────────────────────────

def test_admin_in_one_org_is_only_viewer_in_another(team, make_user, client_for):
    u = make_user('dual')
    org_b = Organization.objects.create(name='B', slug='b', owner=team['owner'])
    OrganizationMember.objects.create(organization=team['org'], user=u, role='admin')
    OrganizationMember.objects.create(organization=org_b, user=u, role='viewer')
    c = client_for(u)
    mk = lambda org: c.post('/api/targets/', {'name': 'x', 'value': 'example.com',
                                                'target_type': 'domain', 'organization': org.id}, format='json')
    assert mk(team['org']).status_code == 201
    assert mk(org_b).status_code == 403


def test_objects_cannot_be_moved_between_orgs(team, client_for, verified_target, make_user):
    other_owner = make_user('oo')
    other_org = Organization.objects.create(name='Other', slug='other2', owner=other_owner)
    OrganizationMember.objects.create(organization=other_org, user=team['admin'], role='admin')
    t = verified_target(team['owner'], 'example.com', organization=team['org'])
    client_for(team['admin']).patch(f'/api/targets/{t.id}/', {'organization': other_org.id}, format='json')
    t.refresh_from_db()
    assert t.organization_id == team['org'].id


def test_private_objects_stay_fully_under_their_owner(make_user, client_for):
    u = make_user('solo')
    c = client_for(u)
    r = c.post('/api/targets/', {'name': 'x', 'value': 'example.com', 'target_type': 'domain'}, format='json')
    assert r.status_code == 201
    tid = r.json()['id']
    assert c.patch(f'/api/targets/{tid}/', {'notes': 'n'}, format='json').status_code == 200
    assert c.delete(f'/api/targets/{tid}/').status_code == 204
    assert Target.objects.count() == 0
