import pytest

from simple_sonarqube_api.client import SonarQubeClient


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


def test_get_issue_code_evidence_none_without_location():
    client = make_client()

    issue = {
        "component": "proj:file.py",
        "hasLocation": False,
    }

    assert client.get_issue_code_evidence(issue) is None


def test_get_issue_code_evidence_ok(monkeypatch):
    client = make_client()

    issue = {
        "component": "proj:file.py",
        "startLine": 10,
        "endLine": 11,
        "hasLocation": True,
    }

    fake_payload = {
        "sources": [
            [8, "a = 1"],
            [9, "b = 2"],
            [10, "vulnerable()"],
            [11, "return x"],
            [12, "end"],
        ]
    }

    def fake_http(method, path, params=None):
        return DummyResponse(200, fake_payload)

    monkeypatch.setattr(client, "_http_request", fake_http)

    result = client.get_issue_code_evidence(issue, context_lines=2)

    assert result is not None
    assert result["component"] == "proj:file.py"
    assert result["from"] == 8
    assert result["to"] == 13

    snippet = result["snippet"]
    assert "10 | vulnerable()" in snippet
    assert "11 | return x" in snippet
