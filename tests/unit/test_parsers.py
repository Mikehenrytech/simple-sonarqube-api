import pytest
from simple_sonarqube_api.client import SonarQubeClient, SonarQubeRequestError


def test_extract_list_of_dicts_ok():
    data = {"issues": [{"k": 1}, {"k": 2}]}
    out = SonarQubeClient._extract_list_of_dicts(data, "issues")
    assert out == [{"k": 1}, {"k": 2}]


def test_extract_list_of_dicts_wrong_type():
    data = {"issues": "nope"}
    with pytest.raises(SonarQubeRequestError):
        SonarQubeClient._extract_list_of_dicts(data, "issues")


def test_extract_list_of_dicts_item_not_dict():
    data = {"issues": [{"k": 1}, "bad"]}
    with pytest.raises(SonarQubeRequestError):
        SonarQubeClient._extract_list_of_dicts(data, "issues")


def test_extract_setting_value():
    data = {"settings": [{"key": "sonar.exclusions", "value": "**/generated/**"}]}
    assert SonarQubeClient._extract_setting_value(data, "sonar.exclusions") == "**/generated/**"


def test_normalize_project_ok():
    comp = {"key": "p1", "name": "Project 1", "qualifier": "TRK", "visibility": "private"}
    p = SonarQubeClient.normalize_project(comp, keep_raw=False)
    assert p.key == "p1"
    assert p.name == "Project 1"
    assert p.visibility == "private"
    assert p.raw is None


def test_normalize_project_missing_key():
    comp = {"name": "Project 1"}
    with pytest.raises(ValueError):
        SonarQubeClient.normalize_project(comp)


def test_extract_cwe_from_rule():
    payload = {"sysTags": ["cwe-79", "owasp-a1"]}
    assert SonarQubeClient.extract_cwe_from_rule(payload) == "CWE-79"
