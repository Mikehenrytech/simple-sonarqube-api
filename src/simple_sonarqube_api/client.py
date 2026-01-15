from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union, Tuple

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


@dataclass(frozen=True)
class Project:
    key: str
    name: str
    qualifier: str = "TRK"
    visibility: Optional[str] = None
    last_analysis_date: Optional[str] = None
    revision: Optional[str] = None
    project: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None


class SonarQubeClient:
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
        self._auth = (self.cfg.token, "")

    # -------------------------
    # Infra (IO mínimo)
    # -------------------------
    def _sleep_if_needed(self) -> None:
        if self.cfg.delay_seconds > 0:
            time.sleep(self.cfg.delay_seconds)

    def _build_url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.cfg.base_url}{path}"

    def _http_request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """
        ÚNICA responsabilidad: hacer HTTP y devolver Response.
        - Maneja retries/backoff en errores de red y algunos HTTP.
        - NO parsea JSON, NO interpreta payload.
        """
        url = self._build_url(path)
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
                return resp

            except (requests.Timeout, requests.ConnectionError) as e:
                last_exc = e
                self.log.warning(
                    "Fallo de red/timeout %s intento %d/%d",
                    path, attempt, self.cfg.max_retries
                )

            if attempt < self.cfg.max_retries:
                backoff = self.cfg.backoff_factor * (2 ** (attempt - 1))
                time.sleep(backoff)

        raise SonarQubeRequestError(f"No se pudo completar la petición a {path}.") from last_exc

    # -------------------------
    # Infra (tratamiento respuesta)
    # -------------------------
    @staticmethod
    def _raise_for_auth(resp: requests.Response, *, path: str) -> None:
        if resp.status_code in (401, 403):
            raise SonarQubeAuthError(
                f"Auth error {resp.status_code} en {path}. Revisa token/permisos."
            )

    @staticmethod
    def _raise_for_http(resp: requests.Response, *, path: str) -> None:
        try:
            resp.raise_for_status()
        except requests.HTTPError as e:
            raise SonarQubeRequestError(f"HTTP error en {path}: {e}") from e

    @classmethod
    def _parse_json(cls, resp: requests.Response, *, path: str) -> Dict[str, Any]:
        """
        Rutina testeable si simulas un Response (o la testeas indirectamente).
        """
        try:
            data = resp.json()
        except ValueError as e:
            raise SonarQubeRequestError(
                f"Respuesta no-JSON en {path} (HTTP {resp.status_code})."
            ) from e
        if not isinstance(data, dict):
            raise SonarQubeRequestError(f"JSON inesperado (no dict) en {path}.")
        return data

    def _handle_response_json(self, resp: requests.Response, *, path: str) -> Dict[str, Any]:
        """
        Combina validación de status + parseo JSON.
        Esto es lo que mockearías si quisieras tests más “alto nivel”.
        """
        self._raise_for_auth(resp, path=path)
        # Si quieres reintentos en 429/5xx, lo ideal es moverlo a _http_request con loop de status.
        self._raise_for_http(resp, path=path)
        return self._parse_json(resp, path=path)

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Método puente: hace HTTP + trata respuesta, y devuelve dict JSON.
        """
        resp = self._http_request(method, path, params=params)
        return self._handle_response_json(resp, path=path)

    # -------------------------
    # Extractores puros (unit-test friendly)
    # -------------------------
    @staticmethod
    def _extract_bool(data: Dict[str, Any], key: str, *, default: bool = False) -> bool:
        v = data.get(key, default)
        return bool(v)

    @staticmethod
    def _extract_list_of_dicts(data: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
        raw = data.get(key) or []
        if not isinstance(raw, list):
            raise SonarQubeRequestError(f"Campo '{key}' no es lista.")
        out: List[Dict[str, Any]] = []
        for i, item in enumerate(raw):
            if not isinstance(item, dict):
                raise SonarQubeRequestError(f"Elemento {i} de '{key}' no es dict.")
            out.append(item)
        return out

    # -------------------------
    # Paginación
    # -------------------------
    def _iter_paginated(
        self,
        path: str,
        *,
        items_key: str,
        base_params: Optional[Dict[str, Any]] = None,
        page_param: str = "p",
        page_size_param: str = "ps",
    ) -> Iterator[Dict[str, Any]]:
        params = dict(base_params or {})
        page = 1

        while True:
            params[page_param] = page
            params[page_size_param] = self.cfg.page_size

            data = self._request_json("GET", path, params=params)
            items = self._extract_list_of_dicts(data, items_key)
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
        data = self._request_json("GET", "/api/authentication/validate")
        return self._extract_bool(data, "valid", default=False)

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
        params: Dict[str, Any] = {}
        if additional_params:
            params.update(additional_params)

        if types:
            params["types"] = types if isinstance(types, str) else ",".join(types)

        if project_keys:
            params["projectKeys"] = project_keys if isinstance(project_keys, str) else ",".join(project_keys)

        component_list: List[str] = []
        if component_keys:
            if isinstance(component_keys, str):
                component_list = [c.strip() for c in component_keys.split(",") if c.strip()]
                params["componentKeys"] = ",".join(component_list)
            else:
                component_list = [c.strip() for c in component_keys if c and c.strip()]
                params["componentKeys"] = ",".join(component_list)

        if resolved is not None:
            params["resolved"] = "true" if resolved else "false"

        if line is not None:
            if line <= 0:
                raise ValueError("line debe ser un entero >= 1.")
            if not component_list:
                raise ValueError("Para filtrar por line es obligatorio indicar component_keys.")
            if len(component_list) != 1:
                raise ValueError("Para filtrar por line debes indicar exactamente un component_key.")
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
        additional_params = dict(filters)

        if "component_keys" in additional_params and "componentKeys" not in additional_params:
            additional_params["componentKeys"] = additional_params.pop("component_keys")
        if "project_keys" in additional_params and "projectKeys" not in additional_params:
            additional_params["projectKeys"] = additional_params.pop("project_keys")

        yield from self.iter_issues(
            types=types,
            resolved=resolved,
            line=line,
            additional_params=additional_params,
        )

    def iter_project_vulnerabilities(
            self,
            project_key: str,
            *,
            resolved: bool = False,
            line: Optional[int] = None,
            additional_params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        """
        Itera issues de tipo VULNERABILITY para un proyecto concreto.

        Garantía: siempre filtra por el project_key proporcionado (projectKeys=<project_key>).

        Args:
            project_key: key del proyecto (TRK), p.ej. "my_project"
            resolved: si incluir resueltas (True) o solo no resueltas (False)
            line: opcional; si se usa, requiere component_keys (fichero) en additional_params via 'componentKeys' o 'component_keys'
            additional_params: filtros extra de /api/issues/search (p.ej. severities, statuses, rules, branch, createdAfter...)

        Yields:
            dict de issue (payload SonarQube).
        """
        if not project_key or not project_key.strip():
            raise ValueError("project_key no puede estar vacío.")

        # Copia defensiva
        extra: Dict[str, Any] = dict(additional_params or {})

        # Evitamos que el caller pueda romper el contrato y traer "todo"
        # (si quieres permitir múltiples projects, crea otro método distinto)
        extra.pop("projectKeys", None)
        extra.pop("project_keys", None)

        # Si el caller usa nombre pythonico para component, lo normalizamos
        if "component_keys" in extra and "componentKeys" not in extra:
            extra["componentKeys"] = extra.pop("component_keys")

        yield from self.iter_issues(
            types=("VULNERABILITY",),
            project_keys=project_key.strip(),
            resolved=resolved,
            line=line,
            additional_params=extra,
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
    # Projects (una sola definición)
    # -------------------------
    def iter_projects(
        self,
        *,
        qualifiers: str = "TRK",
        include_visibility: bool = False,
        additional_params: Optional[Dict[str, Any]] = None,
    ) -> Iterator[Dict[str, Any]]:
        params: Dict[str, Any] = {"qualifiers": qualifiers}
        if include_visibility:
            params["additionalFields"] = "visibility"
        if additional_params:
            extra = dict(additional_params)
            extra.pop("qualifiers", None)
            params.update(extra)

        yield from self._iter_paginated("/api/components/search", items_key="components", base_params=params)

    def list_projects(
        self,
        *,
        qualifiers: str = "TRK",
        include_visibility: bool = False,
        additional_params: Optional[Dict[str, Any]] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        if limit is not None and (not isinstance(limit, int) or limit <= 0):
            raise ValueError("limit debe ser un entero > 0.")

        out: List[Dict[str, Any]] = []
        for p in self.iter_projects(
            qualifiers=qualifiers,
            include_visibility=include_visibility,
            additional_params=additional_params,
        ):
            out.append(p)
            if limit is not None and len(out) >= limit:
                break
        return out

    # -------------------------
    # Settings / exclusions
    # -------------------------
    @staticmethod
    def _extract_setting_value(data: Dict[str, Any], setting_key: str) -> str:
        settings = data.get("settings") or []
        if not isinstance(settings, list):
            return ""
        for s in settings:
            if isinstance(s, dict) and s.get("key") == setting_key:
                v = s.get("value")
                return v if isinstance(v, str) else ("" if v is None else str(v))
        return ""

    def get_exclusions(self, project_key: str) -> str:
        if not project_key or not project_key.strip():
            raise ValueError("project_key no puede estar vacío.")

        data = self._request_json(
            "GET",
            "/api/settings/values",
            params={"component": project_key.strip(), "keys": "sonar.exclusions"},
        )
        return self._extract_setting_value(data, "sonar.exclusions")

    # -------------------------
    # Normalización (puro)
    # -------------------------
    @staticmethod
    def normalize_project(component: Dict[str, Any], *, keep_raw: bool = False) -> Project:
        if not isinstance(component, dict):
            raise TypeError("component debe ser un dict (payload de SonarQube).")

        key = component.get("key")
        name = component.get("name")

        if not key or not isinstance(key, str) or not key.strip():
            raise ValueError("Proyecto inválido: falta 'key' o no es válido.")
        if not name or not isinstance(name, str) or not name.strip():
            raise ValueError("Proyecto inválido: falta 'name' o no es válido.")

        qualifier = component.get("qualifier") or "TRK"
        visibility = component.get("visibility")
        last_analysis_date = component.get("lastAnalysisDate")
        revision = component.get("revision")
        project_field = component.get("project")

        def _to_str_or_none(v: Any) -> Optional[str]:
            if v is None:
                return None
            return v if isinstance(v, str) else str(v)

        return Project(
            key=key.strip(),
            name=name.strip(),
            qualifier=_to_str_or_none(qualifier) or "TRK",
            visibility=_to_str_or_none(visibility),
            last_analysis_date=_to_str_or_none(last_analysis_date),
            revision=_to_str_or_none(revision),
            project=_to_str_or_none(project_field),
            raw=component if keep_raw else None,
        )

    def iter_projects_normalized(
        self,
        *,
        qualifiers: str = "TRK",
        include_visibility: bool = False,
        additional_params: Optional[Dict[str, Any]] = None,
        keep_raw: bool = False,
        strict: bool = False,
    ) -> Iterator[Project]:
        for comp in self.iter_projects(
            qualifiers=qualifiers,
            include_visibility=include_visibility,
            additional_params=additional_params,
        ):
            try:
                yield self.normalize_project(comp, keep_raw=keep_raw)
            except (TypeError, ValueError) as e:
                if strict:
                    raise
                self.log.warning("Proyecto omitido por payload inválido: %s", e)

    # -------------------------
    # Rule
    # -------------------------
    def get_rule(self, rule_key: str) -> Dict[str, Any]:
        if not rule_key or not rule_key.strip():
            raise ValueError("rule_key no puede estar vacío.")
        data = self._request_json("GET", "/api/rules/show", params={"key": rule_key.strip()})
        rule = data.get("rule") or {}
        return rule if isinstance(rule, dict) else {}

    @staticmethod
    def extract_cwe_from_rule(rule_payload: Dict[str, Any]) -> Optional[str]:
        if not isinstance(rule_payload, dict):
            return None

        tags = rule_payload.get("tags") or []
        sys_tags = rule_payload.get("sysTags") or []

        def _pick(tags_list: Any) -> Optional[str]:
            if not isinstance(tags_list, list):
                return None
            for t in tags_list:
                if not isinstance(t, str):
                    continue
                tl = t.lower().strip()
                if tl.startswith("cwe-"):
                    return "CWE-" + tl.split("cwe-", 1)[1].strip()
            return None

        return _pick(sys_tags) or _pick(tags)

    def list_projects_normalized2(self, *, limit: int = 5, strict: bool = False, **kwargs):
        out = []
        for i, p in enumerate(self.iter_projects_normalized(strict=strict, **kwargs)):
            out.append(p)
            if len(out) >= limit:
                break
        return out

    def list_projects_normalized(
        self,
        *,
        qualifiers: str = "TRK",
        include_visibility: bool = False,
        additional_params: Optional[dict] = None,
        keep_raw: bool = False,
        strict: bool = False,
        limit: Optional[int] = None,
    ) -> List["Project"]:
        """
        Devuelve una lista de proyectos normalizados (con límite opcional).
        Wrapper conveniente sobre iter_projects_normalized().
        """
        if limit is not None and (not isinstance(limit, int) or limit <= 0):
            raise ValueError("limit debe ser un entero > 0.")

        out: List["Project"] = []
        for p in self.iter_projects_normalized(
            qualifiers=qualifiers,
            include_visibility=include_visibility,
            additional_params=additional_params,
            keep_raw=keep_raw,
            strict=strict,
        ):
            out.append(p)
            if limit is not None and len(out) >= limit:
                break
        return out

    def get_issue_code_evidence(
        self,
        issue: Dict[str, Any],
        *,
        context_lines: int = 10,
    ) -> Optional[Dict[str, Any]]:
        """
        Obtiene evidencia de código para una issue usando /api/sources/show.

        Requiere en `issue`:
          - component (str)
          - startLine (int) y endLine (int) o equivalente
          - hasLocation (bool) opcional

        Devuelve:
          {
            "component": "...",
            "from": <int>,
            "to": <int>,
            "snippet": "  108 | ...\n"
          }
        """
        component_key, start_line, end_line = self._extract_issue_location(issue)
        if component_key is None or start_line is None or end_line is None:
            return None

        if context_lines < 0:
            raise ValueError("context_lines debe ser >= 0.")

        if end_line < start_line:
            start_line, end_line = end_line, start_line

        from_line = max(1, start_line - int(context_lines))
        to_line = end_line + int(context_lines)

        data = self._request_json(
            "GET",
            "/api/sources/show",
            params={"key": component_key, "from": from_line, "to": to_line},
        )

        snippet = self._build_sources_snippet(data)
        if snippet is None:
            return None

        return {
            "component": component_key,
            "from": from_line,
            "to": to_line,
            "snippet": snippet,
        }


    @staticmethod
    def _extract_issue_location(issue: Dict[str, Any]) -> Tuple[Optional[str], Optional[int], Optional[int]]:
        """
        Rutina pura: extrae (component_key, start_line, end_line) de una issue.
        Soporta distintos formatos:
          - issue["startLine"]/["endLine"] (issue ya normalizada)
          - issue["textRange"]["startLine"]/["endLine"] (payload típico de SonarQube)
          - issue["line"] (solo una línea)
        """
        if not isinstance(issue, dict):
            raise TypeError("issue debe ser un dict.")

        component_key = issue.get("component")
        if not isinstance(component_key, str) or not component_key.strip():
            return None, None, None
        component_key = component_key.strip()

        # Si hasLocation está explícito y es False, salimos
        has_location = issue.get("hasLocation", None)
        if has_location is False:
            return None, None, None

        # 1) preferimos startLine/endLine directos (normalizado)
        start_line = issue.get("startLine")
        end_line = issue.get("endLine")

        # 2) si no, intentamos textRange (payload estándar)
        if start_line is None or end_line is None:
            tr = issue.get("textRange") or {}
            if isinstance(tr, dict):
                start_line = start_line if start_line is not None else tr.get("startLine")
                end_line = end_line if end_line is not None else tr.get("endLine")

        # 3) si no, usamos issue["line"] como línea única
        if start_line is None and end_line is None:
            one = issue.get("line")
            start_line = one
            end_line = one

        try:
            start_i = int(start_line) if start_line is not None else None
            end_i = int(end_line) if end_line is not None else None
        except (TypeError, ValueError):
            return None, None, None

        if start_i is None or end_i is None:
            return None, None, None
        if start_i <= 0 or end_i <= 0:
            return None, None, None

        return component_key, start_i, end_i


    @staticmethod
    def _build_sources_snippet(data: Dict[str, Any]) -> Optional[str]:
        """
        Rutina pura: construye snippet a partir del JSON de /api/sources/show.

        SonarQube puede devolver:
          A) {"sources":[{"line":108,"code":"..."}, ...]}
          B) {"sources":[[108,"..."], ...]}  (algunas implementaciones/serializaciones)
        """
        if not isinstance(data, dict):
            return None

        sources = data.get("sources") or []
        if not isinstance(sources, list) or not sources:
            return None

        lines_out: List[str] = []

        for row in sources:
            ln = None
            code = None

            # Formato A: dict
            if isinstance(row, dict):
                ln = row.get("line")
                code = row.get("code")

            # Formato B: lista/tupla [line, code]
            elif isinstance(row, (list, tuple)) and len(row) >= 2:
                ln = row[0]
                code = row[1]

            if code is None:
                continue

            try:
                ln_int = int(ln)
            except (TypeError, ValueError):
                continue

            # code puede no ser str
            code_str = code if isinstance(code, str) else str(code)
            lines_out.append(f"{ln_int:>5} | {code_str}")

        if not lines_out:
            return None

        return "\n".join(lines_out)
