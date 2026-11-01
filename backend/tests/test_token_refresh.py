"""Cookie-based token refresh, exactly as the frontend uses it."""
import pytest
from rest_framework.test import APIClient


@pytest.fixture
def logged_in(alice):
    c = APIClient()
    r = c.post('/api/token/', {'username': 'alice', 'password': 'pass12345!'}, format='json')
    assert r.status_code == 200
    return c, r.cookies['refresh_token'].value


@pytest.mark.django_db
def test_login_sets_httponly_cookie_and_hides_refresh_token(logged_in):
    c = APIClient()
    r = c.post('/api/token/', {'username': 'alice', 'password': 'pass12345!'}, format='json')
    assert 'refresh' not in r.json() and 'access' in r.json()
    assert r.cookies['refresh_token']['httponly']


@pytest.mark.django_db
@pytest.mark.parametrize('fmt,body', [('json', {}), ('json', None), ('multipart', {})])
def test_refresh_works_from_cookie_with_empty_body(logged_in, fmt, body):
    """The frontend POSTs `{}` as JSON. This used to crash with a 500."""
    c, cookie = logged_in
    c.cookies['refresh_token'] = cookie
    r = c.post('/api/token/refresh/', body, format=fmt)
    assert r.status_code == 200, r.content
    assert 'access' in r.json() and 'refresh' not in r.json()


@pytest.mark.django_db
def test_refresh_rotates_the_cookie(logged_in):
    c, cookie = logged_in
    c.cookies['refresh_token'] = cookie
    r = c.post('/api/token/refresh/', {}, format='json')
    new_cookie = r.cookies['refresh_token']
    assert new_cookie.value and new_cookie.value != cookie
    assert new_cookie['httponly'] and new_cookie['path'] == '/api/token/refresh/'


@pytest.mark.django_db
def test_refresh_still_accepts_token_in_body(logged_in):
    c, cookie = logged_in
    c.cookies.clear()
    r = c.post('/api/token/refresh/', {'refresh': cookie}, format='json')
    assert r.status_code == 200


@pytest.mark.django_db
def test_body_token_wins_over_cookie(logged_in):
    c, cookie = logged_in
    c.cookies['refresh_token'] = 'garbage'
    assert c.post('/api/token/refresh/', {'refresh': cookie}, format='json').status_code == 200


@pytest.mark.django_db
def test_refresh_without_any_token_is_rejected_cleanly():
    r = APIClient().post('/api/token/refresh/', {}, format='json')
    assert r.status_code == 400


@pytest.mark.django_db
@pytest.mark.parametrize('bad', ['garbage', '', 'a.b.c'])
def test_refresh_with_invalid_cookie_is_401(bad):
    c = APIClient()
    c.cookies['refresh_token'] = bad
    r = c.post('/api/token/refresh/', {}, format='json')
    assert r.status_code in (400, 401)
    assert 'access' not in r.json()
