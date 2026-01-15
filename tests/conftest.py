from dotenv import load_dotenv
import os
import pytest

from simple_sonarqube_api.client import SonarQubeClient

load_dotenv()  # <-- aquí

def _env(name: str) -> str | None:
    v = os.getenv(name, "").strip()
    return v or None


@pytest.fixture(scope="session")
def sonar_env():
    base_url = _env("SONAR_BASE_URL")
    token = _env("SONAR_TOKEN")

    if not base_url or not token:
        pytest.skip("Faltan SONAR_BASE_URL/SONAR_TOKEN para tests de integración.")

    return {
        "base_url": base_url,
        "token": token,
        "project_key": _env("SONAR_TEST_PROJECT_KEY"),
        "rule_key": _env("SONAR_TEST_RULE_KEY"),
    }


@pytest.fixture(scope="session")
def sonar_client(sonar_env):
    return SonarQubeClient(
        base_url=sonar_env["base_url"],
        token=sonar_env["token"],
        timeout=20.0,
        max_retries=2,
        backoff_factor=0.3,
        page_size=100,
    )
