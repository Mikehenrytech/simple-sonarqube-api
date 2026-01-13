from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple, Union

import requests


class SonarQubeError(RuntimeError):
    """Error base del cliente."""


class SonarQubeAuthError(SonarQubeError):
    """Error de autenticación / autorización."""


class SonarQubeRequestError(SonarQubeError):
    """Error HTTP/Red/JSON no esperado."""


@dataclass(frozen=True)
class ClientConfig:
    base_url: str
    token: str
    timeout: float = 30.0
    page_size: int = 500
    delay_seconds: float = 0.0
    max_retries: int = 3
    backoff_factor: float = 0.5
    user_agent: str = "simple-sonarqube-api/0.1"


class SonarQubeClient:
    """
    Cliente minimalista para SonarQube Web API.

    - Auth: Basic auth con token como username y password vacío (patrón oficial).
    - Paginación: generadores iter_* (no acumulan en memoria).
    - Robustez: timeout, retries con backoff, logging, errores tipados.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        timeout: float = 30.0,
        page_size: int = 500,
        delay_seconds: float = 0.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        session: Optional[requests.Session] = None,
        logger: Optional[logging.Logger] = None,
        user_agent: str = "simple-sonarqube-api/0.1",
    ) -> None:
        base_url = (base_url or "").strip().rstrip("/")
        if not base_url:
            raise ValueError("base_url no puede estar vacío.")
        if not token or not token.strip():
            raise ValueError("token no puede estar vacío.")

        if page_size <= 0 or page_size > 500:
            # SonarQube suele aceptar hasta 500; si tu instancia soporta más, lo harás configurable después.
            raise ValueError("page_size debe estar entre 1 y 500.")

        self.cfg = ClientConfig(
            base_url=base_url,
            token=token.strip(),
            timeout=float(timeout),
            page_size=int(page_size),
            delay_seconds=float(delay_seconds),
            max_retries=int(max_retries),
            backoff_factor=float(backoff_factor),
            user_agent=user_agent,
        )

        self.log = logger or logging.getLogger(__name__)
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": self.cfg.user_agent})

        # Auth: (username=token, password="")
        self._auth = (self.cfg.token, "")

    # -------------------------
    # Infra
    # -------------------------
    def _sleep_if_needed(self) -> None:
        if self.cfg.delay_seconds > 0:
            time.sleep(self.cfg.delay_seconds)

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.cfg.base_url}{path}"
        params = params or {}

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.cfg.max_retries + 1):
            try:
                resp = self.session.request(
                    method=method.upper(),
                    url=url,
                    auth=self._auth,
                    params=params,
                    timeout=self.cfg.timeout,
                )

                # Manejo explícito de auth
                if resp.status_code in (401, 403):
                    raise SonarQubeAuthError(
                        f"Auth error {resp.status_code} en {path}. Revisa token/permisos."
                    )

                resp.raise_for_status()

                try:
                    data = resp.json()
                except ValueError as e:
                    raise SonarQubeRequestError(
                        f"Respuesta no-JSON en {path} (HTTP {resp.status_code})."
                    ) from e

                return data

            except (requests.Timeout, requests.ConnectionError) as e:
                last_exc = e
                self.log.warning("Fallo de red/timeout (%s) intento %d/%d", path, attempt, self.cfg.max_retries)
            except requests.HTTPError as e:
                # Errores HTTP (no auth) -> no siempre tiene sentido reintentar, pero 429/5xx sí.
                last_exc = e
                status = getattr(e.response, "status_code", None)
                if status in (429, 500, 502, 503, 504):
                    self.log.warning("HTTP %s en %s intento %d/%d", status, path, attempt, self.cfg.max_retries)
                else:
                    raise SonarQubeRequestError(f"HTTP error en {path}: {e}") from e

            # backoff
            if attempt < self.cfg.max_retries:
                backoff = self.cfg.backoff_factor * (2 ** (attempt - 1))
                time.sleep(backoff)

        raise SonarQubeRequestError(f"No se pudo completar la petición a {path}.") from last_exc

    def _iter_paginated(
        self,
        path: str,
        *,
        items_key: str,
        base_params: Optional[Dict[str, Any]] = None,
        page_param: str = "p",
        page_size_param: str = "ps",
    ) -> Iterator[Dict[str, Any]]:
        """
        Itera resultados paginados estilo SonarQube:
        - p: página (1..n)
        - ps: page size
        - items en data[items_key]
        """
        params = dict(base_params or {})
        page = 1

        while True:
            params[page_param] = page
            params[page_size_param] = self.cfg.page_size

            data = self._request("GET", path, params=params)
            items = data.get(items_key) or []
            if not items:
                return

            for item in items:
                yield item

            page += 1
            self._sleep_if_needed()

    # -------------------------
    # Auth
    # -------------------------
    def is_authenticated(self) -> bool:
        data = self._request("GET", "/api/authentication/validate")
        return bool(data.get("valid", False))

    # -------------------------
    # Issues
    # -------------------------
    def iter_issues(
        self,
        *,
        types: Optional[Union[str, Sequence[str]]] = None,
        project_keys: Optional[Union[str, Sequence[str]]] = None,
        component_keys: Optional[Union[str, Sequence[str]]] = None,
        resolved: Optional[bool] = None,
        line: Optional[int] = None,
        additional_params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Itera issues /api/issues/search.

        Nota SonarQube:
        - projectKeys y componentKeys son distintos; usa el correcto para tu caso.
        - resolved suele aceptarse como "true"/"false" string; aquí lo normalizamos.
        """
        params: Dict[str, Any] = {}
        if additional_params:
            params.update(additional_params)

        if types:
            if isinstance(types, str):
                params["types"] = types
            else:
                params["types"] = ",".join(types)

        if project_keys:
            params["projectKeys"] = project_keys if isinstance(project_keys, str) else ",".join(project_keys)

        if component_keys:
            # Normalizamos para poder validar bien el caso line
            if isinstance(component_keys, str):
                component_keys_str = component_keys
                component_list = [c.strip() for c in component_keys.split(",") if c.strip()]
            else:
                component_list = [c.strip() for c in component_keys if c and c.strip()]
                component_keys_str = ",".join(component_list)

            params["componentKeys"] = component_keys_str
        else:
            component_list = []

        if resolved is not None:
            params["resolved"] = "true" if resolved else "false"

        if line is not None:
            if line <= 0:
                raise ValueError("line debe ser un entero >= 1.")
            if not component_list:
                raise ValueError("Para filtrar por line es obligatorio indicar component_keys (file key).")
            if len(component_list) != 1:
                raise ValueError(
                    "Para filtrar por line debes indicar exactamente un component_key (un único fichero)."
                )
            params["line"] = int(line)

        yield from self._iter_paginated("/api/issues/search", items_key="issues", base_params=params)

    def iter_security_issues(
        self,
        *,
        types: Union[str, Sequence[str]] = ("VULNERABILITY",),
        resolved: bool = False,
        line: Optional[int] = None,
        **filters: Any,
    ) -> Iterator[Dict[str, Any]]:
        """
        Atajo para issues de seguridad (por defecto Vulnerability sin resolver).
        Admite `line` (requiere pasar component_keys vía filters, p.ej. componentKeys / component_keys).

        Ejemplo:
            client.iter_security_issues(
                types=("VULNERABILITY",),
                resolved=False,
                line=123,
                componentKeys="my_project:/src/Foo.java"
            )
        """
        # Permitimos al usuario pasar componentKeys vía filters (tal cual API),
        # o component_keys vía nombre Pythonico si quieres estandarizarlo.
        additional_params = dict(filters)

        # Si el usuario usa "component_keys" estilo Python, lo convertimos a "componentKeys"
        if "component_keys" in additional_params and "componentKeys" not in additional_params:
            ck = additional_params.pop("component_keys")
            additional_params["componentKeys"] = ck  # soporta str o lista; iter_issues normaliza

        # Igual para project_keys si lo pasara así
        if "project_keys" in additional_params and "projectKeys" not in additional_params:
            pk = additional_params.pop("project_keys")
            additional_params["projectKeys"] = pk

        # Ahora llamamos a iter_issues usando los parámetros estructurados
        yield from self.iter_issues(
            types=types,
            resolved=resolved,
            line=line,
            # Ojo: iter_issues espera component_keys / project_keys como args formales,
            # pero como aquí estamos pasando filtros "raw" de API, lo metemos en additional_params.
            additional_params=additional_params,
        )

    # -------------------------
    # Hotspots
    # -------------------------
    def iter_hotspots(
        self,
        project_key: str,
        *,
        additional_params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        if not project_key or not project_key.strip():
            raise ValueError("project_key no puede estar vacío.")

        params = {"projectKey": project_key.strip()}
        if additional_params:
            params.update(additional_params)

        yield from self._iter_paginated("/api/hotspots/search", items_key="hotspots", base_params=params)

    # -------------------------
    # Projects
    # -------------------------
    def iter_projects(self) -> Iterator[Dict[str, Any]]:
        params = {"qualifiers": "TRK"}
        yield from self._iter_paginated("/api/components/search", items_key="components", base_params=params)

    # -------------------------
    # Settings / exclusions
    # -------------------------
    def get_exclusions(self, project_key: str) -> str:
        if not project_key or not project_key.strip():
            raise ValueError("project_key no puede estar vacío.")

        data = self._request(
            "GET",
            "/api/settings/values",
            params={"component": project_key.strip(), "keys": "sonar.exclusions"},
        )

        settings = data.get("settings") or []
        for s in settings:
            if s.get("key") == "sonar.exclusions":
                return s.get("value") or ""
        return ""

    # -------------------------
    # Normalización (opcional)
    # -------------------------
    @staticmethod
    def normalize_issue(issue: Dict[str, Any]) -> Dict[str, Any]:
        tags = issue.get("tags") or []
        owasp = next((t for t in tags if "owasp" in t.lower()), "")

        project = issue.get("project", "") or ""
        project_short = project
        if ":" in project:
            parts = project.split(":", 1)
            if len(parts) == 2 and parts[1]:
                project_short = parts[1]

        text_range = issue.get("textRange") or {}
        start_line = text_range.get("startLine")
        end_line = text_range.get("endLine")

        return {
            "project": project,
            "project_short": project_short,
            "type": issue.get("type", ""),
            "severity": issue.get("severity", ""),
            "owasp": owasp,
            "rule": issue.get("rule", ""),
            "status": issue.get("status", ""),
            "creationDate": issue.get("creationDate", ""),
            "updateDate": issue.get("updateDate", ""),
            "effort": issue.get("effort", ""),
            "debt": issue.get("debt", ""),
            "quickFixAvailable": issue.get("quickFixAvailable", False),
            "component": issue.get("component", ""),
            "message": issue.get("message", ""),
            "key": issue.get("key", ""),
            # --- Localización en código ---
            "line": issue.get("line", ""),
            "startLine": start_line,
            "endLine": end_line,
            "hasLocation": start_line is not None,
        }

    @staticmethod
    def normalize_hotspot(hotspot: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "project": hotspot.get("project", ""),
            "vulnerabilityProbability": hotspot.get("vulnerabilityProbability", ""),
            "status": hotspot.get("status", ""),
            "creationDate": hotspot.get("creationDate", ""),
            "updateDate": hotspot.get("updateDate", ""),
            "author": hotspot.get("author", ""),
            "message": hotspot.get("message", ""),
        }

    # -------------------------
    # Evidence / Source code
    # -------------------------
    def get_issue_code_evidence(
            self,
            issue: Dict[str, Any],
            *,
            context_lines: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Obtiene el código fuente asociado a una issue usando /api/sources/show.

        Mapeo de parámetros (según tu requisito):
          - endpoint param "key"  <- issue["component"]
          - endpoint param "from" <- issue["startLine"]
          - endpoint param "to"   <- issue["endLine"]

        Args:
            issue: diccionario de issue (idealmente normalizado) que incluya:
                  component, startLine, endLine, hasLocation
            context_lines: líneas extra antes/después del rango.

        Returns:
            {
              "component": "<component key>",
              "from": <int>,
              "to": <int>,
              "snippet": "  108 | ...\n"
            }
            o None si no hay localización o no se pudo obtener el código.
        """
        if not isinstance(issue, dict):
            raise TypeError("issue debe ser un dict con los campos de la issue.")

        component_key: str = issue.get("component")
        start_line: int = issue.get("startLine")
        end_line: int = issue.get("endLine")
        has_location: bool = issue.get("hasLocation", start_line is not None)

        if not has_location or not has_location:
            return None

        if not component_key or not isinstance(component_key, str):
            return None

        if start_line is None or end_line is None:
            return None

        try:
            start_line_int = int(start_line)
            end_line_int = int(end_line)
        except (TypeError, ValueError):
            return None

        if start_line_int <= 0 or end_line_int <= 0:
            return None
        if end_line_int < start_line_int:
            # Normalización defensiva
            start_line_int, end_line_int = end_line_int, start_line_int

        if context_lines < 0:
            raise ValueError("context_lines debe ser >= 0.")

        from_line = max(1, start_line_int - int(context_lines))
        to_line = end_line_int + int(context_lines)

        # Llamada al endpoint oficial
        data = self._request(
            "GET",
            "/api/sources/show",
            params={
                "key": component_key,
                "from": from_line,
                "to": to_line,
            },
        )

        # Llamada al endpoint oficial
        data_raw = self.get_component_raw_source(component_key, from_line=from_line, to_line=to_line)
        print(f"data_raw: {data_raw}")

        sources = data.get("sources") or []
        if not sources:
            return None
        print(f"sources: {sources}")
        # Formato típico: {"sources":[{"line":108,"code":"..."}, ...]}
        snippet_lines: List[str] = []
        for row in sources:
            ln = row[0]
            code = row[1]

            #  TODO revisar desde aquí

            try:
                ln_int = int(ln)
            except (TypeError, ValueError):
                # Si viene raro, lo omitimos
                continue
            snippet_lines.append(f"{ln_int:>5} | {code}")

        if not snippet_lines:
            return None

        return {
            "component": component_key,
            "from": from_line,
            "to": to_line,
            "snippet": "\n".join(snippet_lines),
            "raw": data_raw
        }

    # -------------------------
    # Raw source (optionally ranged)
    # -------------------------
    def get_component_raw_source(
            self,
            component_key: str,
            *,
            from_line: Optional[int] = None,
            to_line: Optional[int] = None,
    ) -> Optional[str]:
        """
        Obtiene el código fuente de un componente usando /api/sources/raw
        y, si se indican, recorta localmente por rango de líneas.

        Args:
            component_key: clave del componente, p.ej.
                           "dvja:src/main/java/com/appsecco/dvja/services/UserService.java"
            from_line: línea inicial (1-based). Opcional.
            to_line: línea final (1-based). Opcional.

        Returns:
            El contenido del archivo (completo o recortado) como string,
            o None si no hay acceso o hay error.
        """
        if not component_key or not component_key.strip():
            raise ValueError("component_key no puede estar vacío.")

        if from_line is not None and from_line <= 0:
            raise ValueError("from_line debe ser un entero >= 1.")
        if to_line is not None and to_line <= 0:
            raise ValueError("to_line debe ser un entero >= 1.")
        if from_line is not None and to_line is not None and to_line < from_line:
            raise ValueError("to_line no puede ser menor que from_line.")

        url = f"{self.cfg.base_url}/api/sources/raw"

        # Pedimos siempre el raw completo; el recorte lo controlamos nosotros
        params = {"key": component_key.strip()}

        try:
            resp = self.session.get(
                url,
                auth=self._auth,
                params=params,
                timeout=self.cfg.timeout,
            )

            if resp.status_code in (401, 403):
                raise SonarQubeAuthError(
                    f"Auth error {resp.status_code} al acceder a código fuente raw."
                )

            resp.raise_for_status()

            # Fuerza la decodificación correcta
            resp.encoding = "utf-8"
            text = resp.text
            if not text:
                return None

            # Si no hay rango, devolvemos todo
            if from_line is None and to_line is None:
                return text

            lines = text.splitlines()

            # Convertimos a índices 0-based
            start_idx = (from_line - 1) if from_line is not None else 0
            end_idx = to_line if to_line is not None else len(lines)

            # Acotamos defensivamente
            start_idx = max(0, min(start_idx, len(lines)))
            end_idx = max(start_idx, min(end_idx, len(lines)))

            sliced = lines[start_idx:end_idx]

            return "\n".join(sliced)

        except (requests.Timeout, requests.ConnectionError) as e:
            self.log.error(
                "Fallo de red al obtener raw source de %s (%s-%s): %s",
                component_key, from_line, to_line, e
            )
            return None
        except requests.HTTPError as e:
            self.log.error(
                "HTTP error al obtener raw source de %s (%s-%s): %s",
                component_key, from_line, to_line, e
            )
            return None

# -------------------------
    # Projects
    # -------------------------
    def iter_projects(
        self,
        *,
        qualifiers: str = "TRK",
        include_visibility: bool = False,
        additional_params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Itera todos los proyectos (por defecto qualifier TRK) usando /api/components/search.

        Args:
            qualifiers: normalmente "TRK" para projects.
            include_visibility: si True, pide a la API que incluya 'visibility' (si tu versión lo soporta).
            additional_params: filtros extra del endpoint (p.ej. 'q' para búsqueda, etc.)
        """
        params: Dict[str, Any] = {"qualifiers": qualifiers}

        # Algunas versiones soportan "visibility" en el payload sin param;
        # otras aceptan "additionalFields" (depende de versión). Lo hacemos opt-in y no rompemos.
        if include_visibility:
            # "additionalFields" es habitual en varios endpoints; si tu instancia no lo soporta,
            # simplemente ignóralo (o captura el error si te interesa endurecer comportamiento).
            params["additionalFields"] = "visibility"

        if additional_params:
            # Evita que el caller pise qualifiers sin querer.
            extra = dict(additional_params)
            extra.pop("qualifiers", None)
            params.update(extra)

        yield from self._iter_paginated(
            "/api/components/search",
            items_key="components",
            base_params=params,
        )

    def list_projects(
        self,
        *,
        qualifiers: str = "TRK",
        include_visibility: bool = False,
        additional_params: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Devuelve una lista con todos los proyectos.

        Seguridad:
          - `limit` opcional para evitar consumir memoria/tiempo en instancias grandes.

        Args:
            qualifiers: normalmente "TRK".
            include_visibility: ver iter_projects.
            additional_params: ver iter_projects.
            limit: si se indica, corta la lista a ese máximo de proyectos.
        """
        if limit is not None:
            if not isinstance(limit, int) or limit <= 0:
                raise ValueError("limit debe ser un entero > 0.")

        projects: List[Dict[str, Any]] = []
        for p in self.iter_projects(
            qualifiers=qualifiers,
            include_visibility=include_visibility,
            additional_params=additional_params,
        ):
            projects.append(p)
            if limit is not None and len(projects) >= limit:
                break
        return projects