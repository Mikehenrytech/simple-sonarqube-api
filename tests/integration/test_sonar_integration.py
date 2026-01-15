import pytest

from simple_sonarqube_api.client import SonarQubeAuthError, SonarQubeRequestError


pytestmark = pytest.mark.integration


def test_validate_authentication(sonar_client):
    # Si el token es inválido, debería lanzar SonarQubeAuthError en tu implementación
    ok = sonar_client.is_authenticated()
    assert ok is True


def test_list_some_projects(sonar_client):
    # No asumimos que haya X proyectos; solo que el endpoint responde bien
    projects = sonar_client.list_projects(limit=5)
    assert isinstance(projects, list)
    assert len(projects) <= 5
    for p in projects:
        assert "key" in p
        assert "name" in p


def test_iter_projects_normalized(sonar_client):
    # Comprueba que la normalización funciona con payload real
    projects = sonar_client.list_projects_normalized(limit=5, strict=True)
    assert len(projects) <= 5
    for p in projects:
        assert p.key
        assert p.name
        assert p.qualifier


def test_get_exclusions_if_project_provided(sonar_client, sonar_env):
    project_key = sonar_env.get("project_key")
    if not project_key:
        pytest.skip("Define SONAR_TEST_PROJECT_KEY para probar exclusions.")

    exclusions = sonar_client.get_exclusions(project_key)
    assert isinstance(exclusions, str)
    # puede ser "" si no hay exclusiones configuradas; eso también es OK


def test_iter_security_issues_smoke(sonar_client, sonar_env):
    """
    Smoke test: pide 1-3 issues. No asumimos que existan; el objetivo es que no explote.
    """
    project_key = sonar_env.get("project_key")
    additional = {}
    if project_key:
        # restringe para hacerlo rápido/determinista
        additional["projectKeys"] = project_key

    it = sonar_client.iter_security_issues(
        types=("VULNERABILITY",),
        resolved=False,
        **additional,
    )

    # Consumimos pocas para no tardar
    issues = []
    for i, issue in enumerate(it):
        issues.append(issue)
        if i >= 2:
            break

    assert isinstance(issues, list)
    for issue in issues:
        assert isinstance(issue, dict)
        assert "key" in issue


def test_get_rule_if_rule_key_provided(sonar_client, sonar_env):
    rule_key = sonar_env.get("rule_key")
    if not rule_key:
        pytest.skip("Define SONAR_TEST_RULE_KEY para probar get_rule.")
    rule = sonar_client.get_rule(rule_key)
    assert isinstance(rule, dict)
    # Campos típicos, pero dependen de permisos/config
    assert rule.get("key") == rule_key
