import pytest

from simple_sonarqube_api.client import SonarQubeClient
from simple_sonarqube_api.client import SonarQubeAuthError


class DummyResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json = json_data or {}

    def json(self):
        return self._json

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("HTTP error")


def make_client():
    return SonarQubeClient(
        base_url="https://example.local",
        token="dummy",
    )


def test_is_authenticated_ok(monkeypatch):
    client = make_client()

    def fake_http(method, path, params=None):
        return DummyResponse(200, {"valid": True})

    monkeypatch.setattr(client, "_http_request", fake_http)

    assert client.is_authenticated() is True


def test_is_authenticated_false(monkeypatch):
    client = make_client()

    def fake_http(method, path, params=None):
        return DummyResponse(200, {"valid": False})

    monkeypatch.setattr(client, "_http_request", fake_http)

    assert client.is_authenticated() is False


def test_is_authenticated_auth_error(monkeypatch):
    client = make_client()

    def fake_http(method, path, params=None):
        return DummyResponse(401, {"errors": ["unauthorized"]})

    monkeypatch.setattr(client, "_http_request", fake_http)

    with pytest.raises(SonarQubeAuthError):
        client.is_authenticated()
