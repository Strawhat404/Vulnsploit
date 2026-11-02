"""The guard must be applied everywhere user-supplied hosts are contacted."""
import socket
from unittest import mock

import pytest
from requests import Response

from scanner import utils
from scanner.models import (
    Organization, OrganizationMember, ReconSession, ScanResult, ScheduledScan,
    WebhookEndpoint,
)

PUBLIC = '93.184.216.34'


def dns(mapping=None, default=PUBLIC):
    """Patch name resolution: mapping of host->ip, everything else -> default."""
    mapping = mapping or {}

    def fake(host, *a, **kw):
        if default is None and host not in mapping:
            raise socket.gaierror
        ip = mapping.get(host, default)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0))]
    return mock.patch('scanner.netguard.socket.getaddrinfo', side_effect=fake)


# ─── API endpoints ────────────────────────────────────────────────────────────

@pytest.mark.django_db
@pytest.mark.parametrize('target', [
    '127.0.0.1', '10.0.0.5', 'http://169.254.169.254/latest/meta-data/',
    '192.168.1.0/24', 'http://2130706433/',
])
def test_scan_api_refuses_internal_targets(alice, client_for, target):
    with dns(), mock.patch('scanner.views.execute_scan.delay') as delay:
        resp = client_for(alice).post(
            '/api/scans/', {'target': target, 'scan_type': 'quick'}, format='json',
        )
    assert resp.status_code == 400
    delay.assert_not_called()
    assert ScanResult.objects.count() == 0


@pytest.mark.django_db
def test_scan_api_refuses_hostname_that_resolves_internally(alice, client_for):
    with dns({'sneaky.example.com': '127.0.0.1'}), mock.patch('scanner.views.execute_scan.delay') as delay:
        resp = client_for(alice).post(
            '/api/scans/', {'target': 'sneaky.example.com', 'scan_type': 'quick'}, format='json',
        )
    assert resp.status_code == 400
    delay.assert_not_called()


@pytest.mark.django_db
def test_recon_api_refuses_internal_targets(alice, client_for):
    with dns(), mock.patch('scanner.views.execute_full_recon.delay') as delay:
        resp = client_for(alice).post('/api/recon/', {'target': '10.0.0.5'}, format='json')
    assert resp.status_code == 400
    delay.assert_not_called()


# ─── Re-check at execution time (DNS rebinding) ───────────────────────────────

def test_run_scan_rechecks_target_and_never_spawns_tool():
    with dns({'rebind.example.com': '127.0.0.1'}), \
         mock.patch('scanner.utils.subprocess.check_output') as run:
        with pytest.raises(RuntimeError, match='publicly routable'):
            utils.run_scan('rebind.example.com', 'quick')
    run.assert_not_called()


@pytest.mark.parametrize('scan_type', ['quick', 'nikto', 'sqlmap', 'nuclei', 'testssl', 'headers'])
def test_every_active_tool_is_guarded(scan_type):
    with dns({'rebind.example.com': '10.1.2.3'}), \
         mock.patch('scanner.utils.subprocess.check_output') as run, \
         mock.patch('scanner.utils.http_requests.get') as get:
        try:
            utils.run_scan('rebind.example.com', scan_type)
        except RuntimeError:
            pass
    run.assert_not_called()
    get.assert_not_called()


def test_subfinder_is_passive_and_needs_no_resolution():
    with dns(default=None), \
         mock.patch('scanner.utils.subprocess.check_output', return_value='a.example.com\n'):
        text, _ = utils.run_scan('example.com', 'subfinder')
    assert 'a.example.com' in text


# ─── headers check: redirects are validated hop by hop ────────────────────────

def _resp(status=200, location=None, url='https://example.com/'):
    r = Response()
    r.status_code = status
    r.url = url
    if location:
        r.headers['Location'] = location
    r.headers['Server'] = 'test'
    return r


def test_headers_check_does_not_follow_redirect_to_internal_address():
    with dns(), mock.patch(
        'scanner.utils.http_requests.get',
        side_effect=[_resp(302, 'http://169.254.169.254/latest/meta-data/')],
    ) as get:
        _, data = utils._run_headers_check('example.com')
    assert get.call_count == 1
    assert 'publicly routable' in (data['error'] or '')


def test_headers_check_follows_safe_redirects_with_a_hop_limit():
    hops = [_resp(302, f'https://example.com/{i}') for i in range(20)]
    with dns(), mock.patch('scanner.utils.http_requests.get', side_effect=hops) as get:
        _, data = utils._run_headers_check('example.com')
    assert get.call_count <= 6
    assert 'redirect' in (data['error'] or '').lower()


def test_headers_check_never_lets_requests_follow_redirects_itself():
    with dns(), mock.patch('scanner.utils.http_requests.get', return_value=_resp(200)) as get, \
         mock.patch('scanner.utils._check_ssl_cert', return_value=None):
        utils._run_headers_check('example.com')
    assert get.call_args.kwargs['allow_redirects'] is False


# ─── webhooks ─────────────────────────────────────────────────────────────────

@pytest.mark.django_db
@pytest.mark.parametrize('url', [
    'http://127.0.0.1:6379/', 'http://169.254.169.254/', 'http://localhost.example.com/',
    'ftp://example.com/x', 'file:///etc/passwd', 'http://user:pw@example.com/',
])
def test_webhook_api_refuses_unsafe_urls(alice, client_for, url):
    with dns({'localhost.example.com': '127.0.0.1'}):
        resp = client_for(alice).post(
            '/api/webhooks/', {'name': 'x', 'url': url, 'events': ['scan.completed']}, format='json',
        )
    assert resp.status_code == 400
    assert WebhookEndpoint.objects.count() == 0


@pytest.mark.django_db
def test_webhook_api_accepts_public_url(alice, client_for):
    with dns():
        resp = client_for(alice).post(
            '/api/webhooks/',
            {'name': 'x', 'url': 'https://hooks.slack.com/services/T/B/x', 'events': ['report.ready']},
            format='json',
        )
    assert resp.status_code == 201


@pytest.mark.django_db
def test_webhook_delivery_rechecks_host_and_refuses_redirects(alice):
    from scanner.notifications import _deliver_webhook
    wh = WebhookEndpoint.objects.create(
        user=alice, name='x', url='https://hooks.example.com/x', secret='s', events=['report.ready'],
    )
    with dns({'hooks.example.com': '10.0.0.9'}), mock.patch('scanner.notifications.http_requests.post') as post:
        _deliver_webhook(wh, 'report.ready', {})
    post.assert_not_called()

    with dns(), mock.patch('scanner.notifications.http_requests.post') as post:
        post.return_value.status_code = 200
        _deliver_webhook(wh, 'report.ready', {})
    assert post.call_args.kwargs['allow_redirects'] is False


# ─── scheduled scans ──────────────────────────────────────────────────────────

def _sched(client, **over):
    body = {'target': 'example.com', 'scan_type': 'quick', 'cron': '0 2 * * 1', **over}
    with dns():
        return client.post('/api/scheduled-scans/', body, format='json')


@pytest.mark.django_db
def test_scheduled_scan_accepts_sane_schedule(alice, client_for, verified_target):
    verified_target(alice, 'example.com')
    assert _sched(client_for(alice)).status_code == 201
    assert _sched(client_for(alice), cron='30 */6 * * *').status_code == 201
    assert _sched(client_for(alice), cron='0 0 31 12 6').status_code == 201
    assert _sched(client_for(alice), cron='15 9-17 * * 1-5').status_code == 201
    assert _sched(client_for(alice), cron='0 3 * * mon').status_code == 201


@pytest.mark.django_db
@pytest.mark.parametrize('over', [
    {'target': '127.0.0.1'}, {'target': '10.0.0.0/24'},
    {'scan_type': 'rm -rf'}, {'scan_type': 'nonexistent'},
    {'cron': '* * * * *'}, {'cron': '*/5 * * * *'}, {'cron': '0,30 * * * *'},
    {'cron': '0-30 * * * *'}, {'cron': 'abc'}, {'cron': '0 2 * *'}, {'cron': '99 2 * * *'},
    {'cron': '0 25 * * *'}, {'cron': '0 2 32 * *'}, {'cron': '0 2 0 * *'}, {'cron': '0 2 * 13 *'},
    {'cron': '0 2 * * 8'},
])
def test_scheduled_scan_rejects_unsafe_input(alice, client_for, over):
    assert _sched(client_for(alice), **over).status_code == 400
    assert ScheduledScan.objects.count() == 0


# ─── tasks: org crash + full_recon scheduling ─────────────────────────────────

@pytest.fixture
def org_with_owner(alice):
    org = Organization.objects.create(name='Acme', slug='acme', owner=alice)
    OrganizationMember.objects.create(organization=org, user=alice, role='owner')
    return org


@pytest.mark.django_db
def test_scheduled_scan_in_org_creates_scan_without_crashing(alice, org_with_owner, verified_target):
    from scanner.tasks import run_scheduled_scan
    verified_target(alice, 'example.com', organization=org_with_owner)
    s = ScheduledScan.objects.create(
        user=alice, organization=org_with_owner, target='example.com',
        scan_type='quick', cron='0 2 * * 1',
    )
    with mock.patch('scanner.tasks.execute_scan.delay') as delay:
        delay.return_value.id = 'task-1'
        run_scheduled_scan(s.id)
    scan = ScanResult.objects.get()
    assert scan.organization_id == org_with_owner.id
    delay.assert_called_once()


@pytest.mark.django_db
def test_scheduled_full_recon_starts_a_recon_session(alice, org_with_owner, verified_target):
    from scanner.tasks import run_scheduled_scan
    verified_target(alice, 'example.com', organization=org_with_owner)
    s = ScheduledScan.objects.create(
        user=alice, organization=org_with_owner, target='example.com',
        scan_type='full_recon', cron='0 2 * * 1',
    )
    with mock.patch('scanner.tasks.execute_full_recon.delay') as recon, \
         mock.patch('scanner.tasks.execute_scan.delay') as single:
        recon.return_value.id = 'task-2'
        run_scheduled_scan(s.id)
    session = ReconSession.objects.get()
    assert session.organization_id == org_with_owner.id
    assert session.celery_task_id == 'task-2'
    recon.assert_called_once_with(session.id)
    single.assert_not_called()


@pytest.mark.django_db
def test_full_recon_in_org_saves_scan_rows_with_org(alice, org_with_owner, verified_target):
    from scanner import tasks
    verified_target(alice, 'example.com', organization=org_with_owner)

    class SyncExecutor:
        def __init__(self, *a, **kw): pass
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def map(self, fn, it): return [fn(x) for x in it]

    session = ReconSession.objects.create(user=alice, organization=org_with_owner, target='example.com')
    with mock.patch.object(tasks.concurrent.futures, 'ThreadPoolExecutor', SyncExecutor), \
         mock.patch.object(tasks, 'run_scan', return_value=('ok', None)), \
         mock.patch.object(tasks.generate_report, 'delay'):
        tasks.execute_full_recon(session.id)
    scans = ScanResult.objects.filter(recon_session=session)
    assert scans.count() == len(tasks.FULL_RECON_TOOLS)
    assert set(scans.values_list('organization_id', flat=True)) == {org_with_owner.id}
