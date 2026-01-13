# src/simple_sonarqube_api/models.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class IssueSummary:
    """
    Vista “report-friendly” de una issue (alineada con tu extract_issues_info).

    Nota: mantenemos campos como str/Any porque SonarQube devuelve formatos que pueden variar
    (por ejemplo effort/debt), y porque esto es una librería cliente, no un validador estricto.
    """
    project: str
    project_short: str
    type: str
    severity: str
    owasp: str
    rule: str
    status: str
    creation_date: str
    update_date: str
    effort: str
    debt: str
    quick_fix_available: bool
    component: str
    message: str
    key: str

    @classmethod
    def from_api(cls, issue: Dict[str, Any]) -> "IssueSummary":
        tags = issue.get("tags") or []
        owasp = ""
        for t in tags:
            if "owasp" in t:
                owasp = t
                break

        project = issue.get("project", "") or ""
        project_short = project.split(":", 1)[1] if ":" in project else project

        return cls(
            project=project,
            project_short=project_short,
            type=issue.get("type", "") or "",
            severity=issue.get("severity", "") or "",
            owasp=owasp,
            rule=issue.get("rule", "") or "",
            status=issue.get("status", "") or "",
            creation_date=issue.get("creationDate", "") or "",
            update_date=issue.get("updateDate", "") or "",
            effort=str(issue.get("effort", "") or ""),
            debt=str(issue.get("debt", "") or ""),
            quick_fix_available=bool(issue.get("quickFixAvailable", False)),
            component=issue.get("component", "") or "",
            message=str(issue.get("message", "") or ""),
            key=str(issue.get("key", "") or ""),
        )


@dataclass(frozen=True)
class HotspotSummary:
    """
    Vista “report-friendly” de un hotspot (alineada con tu extract_hotspots_info).
    """
    project: str
    vulnerability_probability: str
    status: str
    creation_date: str
    update_date: str
    author: str
    message: str

    @classmethod
    def from_api(cls, hotspot: Dict[str, Any]) -> "HotspotSummary":
        return cls(
            project=hotspot.get("project", "") or "",
            vulnerability_probability=hotspot.get("vulnerabilityProbability", "") or "",
            status=hotspot.get("status", "") or "",
            creation_date=hotspot.get("creationDate", "") or "",
            update_date=hotspot.get("updateDate", "") or "",
            author=hotspot.get("author", "") or "",
            message=str(hotspot.get("message", "") or ""),
        )


@dataclass(frozen=True)
class ProjectSummary:
    """
    Proyecto (TRK) según /api/components/search?qualifiers=TRK.
    """
    key: str
    name: str
    qualifier: str
    visibility: Optional[str] = None

    @classmethod
    def from_api(cls, component: Dict[str, Any]) -> "ProjectSummary":
        return cls(
            key=component.get("key", "") or "",
            name=component.get("name", "") or "",
            qualifier=component.get("qualifier", "") or "",
            visibility=component.get("visibility"),
        )


@dataclass(frozen=True)
class CodeEvidence:
    """
    Evidencia de código asociada a una issue.

    - snippet: texto listo para report (con números de línea prefijados).
    - component: key de componente (ruta lógica en SonarQube).
    - start_line/end_line: rango original (si aplica).
    - method: cómo se obtuvo ("issue_snippets" o "issues_show+sources_show").
    - raw: opcionalmente payloads completos (útil para debug; puede contener información sensible).
    """
    issue_key: str
    method: str
    component: Optional[str]
    start_line: Optional[int]
    end_line: Optional[int]
    snippet: Optional[str]
    raw: Optional[Dict[str, Any]] = None
    issue_raw: Optional[Dict[str, Any]] = None
    source_raw: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CodeEvidence":
        return cls(
            issue_key=str(d.get("issue_key", "") or ""),
            method=str(d.get("method", "") or ""),
            component=d.get("component"),
            start_line=d.get("startLine"),
            end_line=d.get("endLine"),
            snippet=d.get("snippet"),
            raw=d.get("raw"),
            issue_raw=d.get("issue_raw") or d.get("issue_raw") or d.get("issue_raw"),
            source_raw=d.get("source_raw") or d.get("source_raw") or d.get("source_raw"),
        )
