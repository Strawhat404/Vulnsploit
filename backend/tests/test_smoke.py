import pytest
from rest_framework.test import APIClient


def test_health_endpoint():
    resp = APIClient().get('/api/health/')
    assert resp.status_code == 200
    assert resp.json()['status'] == 'ok'


@pytest.mark.django_db
def test_protected_endpoint_requires_auth():
    assert APIClient().get('/api/scans/').status_code == 401


@pytest.mark.django_db
def test_authenticated_user_can_list_scans(alice, client_for):
    resp = client_for(alice).get('/api/scans/')
    assert resp.status_code == 200
