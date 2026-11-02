"""Scan targets and webhook URLs must never reach internal infrastructure."""
import socket
from unittest import mock

import pytest

from scanner import netguard
from scanner.netguard import UnsafeTarget

PUBLIC = '93.184.216.34'


def _resolves_to(*ips):
    def fake(host, *a, **kw):
        return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0))
                for ip in ips]
    return mock.patch('scanner.netguard.socket.getaddrinfo', side_effect=fake)


@pytest.mark.parametrize('ip', [
    '127.0.0.1', '127.1.2.3', '10.0.0.5', '172.16.0.1', '172.31.255.254', '192.168.1.1',
    '169.254.169.254', '100.64.0.1', '0.0.0.0', '192.0.0.1', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fc00::1', 'fd00:ec2::254',
    '::ffff:127.0.0.1', '::ffff:10.0.0.1', '64:ff9b::7f00:1', '2002:7f00:1::',
])
def test_internal_ips_are_refused(ip):
    with _resolves_to(ip):
        with pytest.raises(UnsafeTarget):
            netguard.assert_public_host(ip)


@pytest.mark.parametrize('ip', [PUBLIC, '8.8.8.8', '1.1.1.1', '2606:4700:4700::1111'])
def test_public_ips_are_allowed(ip):
    with _resolves_to(ip):
        netguard.assert_public_host(ip)


def test_hostname_resolving_to_internal_ip_is_refused():
    with _resolves_to('127.0.0.1'):
        with pytest.raises(UnsafeTarget):
            netguard.assert_public_host('innocent.example.com')


def test_hostname_with_any_internal_record_is_refused():
    with _resolves_to(PUBLIC, '10.0.0.7'):
        with pytest.raises(UnsafeTarget):
            netguard.assert_public_host('mixed.example.com')


def test_unresolvable_host_is_refused():
    with mock.patch('scanner.netguard.socket.getaddrinfo', side_effect=socket.gaierror):
        with pytest.raises(UnsafeTarget, match='resolve'):
            netguard.assert_public_host('nope.example.com')


def test_alternative_ip_encodings_are_refused_without_dns():
    # inet_aton() treats these as 127.0.0.1; we must parse them ourselves
    # rather than depend on what the resolver does.
    with mock.patch('scanner.netguard.socket.getaddrinfo', side_effect=AssertionError('DNS used')):
        for host in ('2130706433', '0x7f.0.0.1', '017700000001', '127.1'):
            with pytest.raises(UnsafeTarget):
                netguard.assert_public_host(host)


def test_private_targets_can_be_enabled_explicitly_for_labs(settings):
    settings.ALLOW_PRIVATE_TARGETS = True
    with _resolves_to('10.0.0.5'):
        netguard.assert_public_host('lab.internal.example.com')


# ─── target forms ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize('target', [
    'http://127.0.0.1/', 'https://10.1.1.1:8443/x', 'http://169.254.169.254/latest/meta-data/',
    '192.168.0.0/24', '10.0.0.0/8',
])
def test_assert_public_target_refuses_internal_forms(target):
    with _resolves_to('127.0.0.1'):
        with pytest.raises(UnsafeTarget):
            netguard.assert_public_target(target)


def test_url_with_credentials_is_refused():
    # http://good.example.com@127.0.0.1/ -> host is 127.0.0.1; reject the whole form
    with _resolves_to(PUBLIC):
        with pytest.raises(UnsafeTarget):
            netguard.assert_public_target('http://example.com@evil.example.com/')


def test_public_url_host_and_cidr_pass():
    with _resolves_to(PUBLIC):
        for t in ('example.com', 'https://example.com:8443/app', PUBLIC, '93.184.216.0/24'):
            netguard.assert_public_target(t)


def test_oversized_cidr_is_refused():
    with _resolves_to(PUBLIC):
        with pytest.raises(UnsafeTarget, match='large'):
            netguard.assert_public_target('93.184.0.0/16')


def test_host_of_extracts_hostnames():
    assert netguard.host_of('https://Example.com:8443/a?b=1') == 'example.com'
    assert netguard.host_of('example.com') == 'example.com'
    assert netguard.host_of('93.184.216.34') == '93.184.216.34'
