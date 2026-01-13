# src/simple_sonarqube_api/_http.py
from __future__ import annotations

from dataclasses import dataclass
import time
import requests

from .exceptions import (
    SonarQubeAuthError,
    SonarQubeNotFoundError,
    SonarQubePermissionError,
    SonarQubeRateLimitError,
    SonarQubeProtocolError,
    SonarQubeError,
)


@dataclass(frozen=True)
class HttpConfig:
    """
    Configuración de la capa HTTP.

    - timeout: segundos máximos por petición.
    - max_retries: reintentos ante errores transitorios.
    - retry_backoff: base para backoff exponencial (en segundos).
    - delay_between_calls: pausa mínima entre llamadas (rate limit cliente).
    """
    timeout: int = 30
    max_retries: int = 3
    retry_backoff: float = 0.8
    delay_between_calls: float = 0.0


class HttpClient:
    """
    Cliente HTTP de bajo nivel para SonarQube.

    Centraliza:
    - Autenticación (token)
    - Reintentos con backoff
    - Rate limiting simple (cliente)
    - Mapeo de códigos HTTP a excepciones de dominio
    """

    def __init__(self, base_url: str, token: str, config: HttpConfig | None = None):
        if not base_url:
            raise ValueError("base_url es obligatorio")
        if not token:
            raise ValueError("token es obligatorio")

        self.base_url = base_url.rstrip("/")
        self.auth = (token, "")
        self.session = requests.Session()
        self.config = config or HttpConfig()
        self._last_call_ts = 0.0

    def _rate_limit(self) -> None:
        if self.config.delay_between_calls and self.config.delay_between_calls > 0:
            now = time.time()
            elapsed = now - self._last_call_ts
            if elapsed < self.config.delay_between_calls:
                time.sleep(self.config.delay_between_calls - elapsed)

    def get_json(self, path: str, params: dict | None = None) -> dict:
        """
        Realiza un GET y devuelve JSON.

        Lanza excepciones de dominio:
          - SonarQubeAuthError (401)
          - SonarQubePermissionError (403)
          - SonarQubeNotFoundError (404)
          - SonarQubeRateLimitError (429)
          - SonarQubeError (otros)
        """
        if not path.startswith("/"):
            path = "/" + path

        url = f"{self.base_url}{path}"
        params = params or {}

        last_exc: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            try:
                self._rate_limit()

                r = self.session.get(
                    url,
                    auth=self.auth,
                    params=params,
                    timeout=self.config.timeout,
                )
                self._last_call_ts = time.time()

                # Mapeo explícito de estados
                if r.status_code == 401:
                    raise SonarQubeAuthError("Unauthorized (401). Revisa token o URL base.")
                if r.status_code == 403:
                    raise SonarQubePermissionError(
                        "Forbidden (403). Falta permiso (p.ej. 'See Source Code')."
                    )
                if r.status_code == 404:
                    raise SonarQubeNotFoundError("Not Found (404). Revisa keys/endpoint.")
                if r.status_code == 429:
                    raise SonarQubeRateLimitError("Rate limit (429). Reduce frecuencia o aumenta backoff.")

                r.raise_for_status()

                try:
                    return r.json()
                except ValueError as e:
                    raise SonarQubeProtocolError("Respuesta no es JSON válido.") from e

            except (requests.RequestException, SonarQubeRateLimitError) as e:
                last_exc = e
                if attempt >= self.config.max_retries:
                    break
                # Backoff exponencial
                time.sleep(self.config.retry_backoff * (2 ** attempt))

        raise SonarQubeError(f"HTTP error calling {path}: {last_exc}") from last_exc
