import pytest
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.test import APIClient


@pytest.fixture(autouse=True)
def _fast_password_hashing(settings):
    """PBKDF2 is deliberately slow; tests create many users."""
    settings.PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']


@pytest.fixture(autouse=True)
def _clear_cache():
    """django-ratelimit counters live in the cache; reset between tests."""
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def make_user(db):
    def _make(username, password='pass12345!'):
        return User.objects.create_user(username=username, password=password)
    return _make


@pytest.fixture
def alice(make_user):
    return make_user('alice')


@pytest.fixture
def bob(make_user):
    return make_user('bob')


@pytest.fixture
def client_for():
    def _client(user):
        c = APIClient()
        c.force_authenticate(user=user)
        return c
    return _client


@pytest.fixture
def verified_target(db):
    """Create a Target the user has proven ownership of."""
    from django.utils import timezone
    from scanner.models import Target

    def _make(user, value='example.com', method='dns', organization=None, target_type=None, **kw):
        if target_type is None:
            target_type = 'ip' if value.replace('.', '').isdigit() else 'domain'
        return Target.objects.create(
            user=user, organization=organization, name=value, value=value,
            target_type=target_type, verification_method=method,
            verified_at=kw.pop('verified_at', timezone.now()), **kw,
        )
    return _make


@pytest.fixture
def public_dns():
    """Every hostname resolves to a public address."""
    import socket
    from unittest import mock

    def fake(host, *a, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', 0))]
    with mock.patch('scanner.netguard.socket.getaddrinfo', side_effect=fake):
        yield
