from __future__ import annotations

import base64
import ipaddress
import json
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from supplyguard.scanner import ScanError

REQUEST_TIMEOUT = 30
MAX_RESPONSE_BYTES = 5_000_000
ISSUE_PAGE_SIZE = 100
MAX_ISSUE_PAGES = 5
METRIC_KEYS = (
    "ncloc",
    "bugs",
    "vulnerabilities",
    "code_smells",
    "security_hotspots",
    "coverage",
    "duplicated_lines_density",
    "reliability_rating",
    "security_rating",
    "security_review_rating",
    "sqale_rating",
)
RATING_METRICS = {
    "reliability_rating",
    "security_rating",
    "security_review_rating",
    "sqale_rating",
}
SEVERITY_MAP = {
    "BLOCKER": "CRITICAL",
    "CRITICAL": "HIGH",
    "MAJOR": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "LOW",
}


class _NoRedirect(HTTPRedirectHandler):
    # A redirect could forward the token to another host.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def _validated_base_url(value: str) -> str:
    parts = urlsplit(value.strip())
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host:
        raise ScanError("SonarQube URL must start with https:// (or http:// for localhost).")
    if parts.username or parts.password or parts.query or parts.fragment:
        raise ScanError("SonarQube URL must not contain credentials, a query, or a fragment.")
    if parts.scheme == "http" and not _is_loopback(host):
        raise ScanError("Plain http:// is only allowed for localhost; use https:// so the token is encrypted.")
    return f"{parts.scheme}://{parts.netloc}{parts.path.rstrip('/')}"


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class SonarQubeClient:
    def __init__(self, url: str, token: str) -> None:
        if not token:
            raise ScanError("A SonarQube token is required; set the SONAR_TOKEN environment variable.")
        self.base_url = _validated_base_url(url)
        credentials = base64.b64encode(f"{token}:".encode()).decode()
        self._headers = {"Authorization": f"Basic {credentials}", "Accept": "application/json"}
        self._opener = build_opener(_NoRedirect())

    def get(self, path: str, **params: Any) -> dict[str, Any]:
        query = urlencode({key: value for key, value in params.items() if value is not None})
        request = Request(f"{self.base_url}/api/{path}?{query}", headers=self._headers)
        try:
            with self._opener.open(request, timeout=REQUEST_TIMEOUT) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            if error.code in (401, 403):
                raise ScanError("SonarQube rejected the token or it lacks permission for this project.") from error
            if error.code == 404:
                raise ScanError("SonarQube project or endpoint not found; check the project key and branch.") from error
            if 300 <= error.code < 400:
                raise ScanError("SonarQube redirected the request; use the final server URL.") from error
            raise ScanError(f"SonarQube returned HTTP {error.code}.") from error
        except (URLError, TimeoutError, OSError) as error:
            raise ScanError(f"Could not reach SonarQube: {error}") from error
        if len(body) > MAX_RESPONSE_BYTES:
            raise ScanError("SonarQube response exceeded the size limit.")
        try:
            return json.loads(body)
        except ValueError as error:
            raise ScanError("SonarQube returned an invalid response.") from error


def _rating_letter(value: str) -> str:
    try:
        return "ABCDE"[int(float(value)) - 1]
    except (ValueError, IndexError):
        return value


def _metric_value(key: str, value: str) -> Any:
    if key in RATING_METRICS:
        return _rating_letter(value)
    try:
        number = float(value)
    except ValueError:
        return value
    return int(number) if number.is_integer() else round(number, 1)


def _issue_payload(issue: dict[str, Any], project: str) -> dict[str, Any]:
    component = str(issue.get("component", ""))
    prefix = f"{project}:"
    return {
        "key": issue.get("key"),
        "rule": issue.get("rule"),
        "type": issue.get("type"),
        "sonar_severity": issue.get("severity"),
        "severity": SEVERITY_MAP.get(str(issue.get("severity")), "LOW"),
        "file": component[len(prefix):] if component.startswith(prefix) else component,
        "line": issue.get("line"),
        "message": issue.get("message"),
        "status": issue.get("status"),
        "effort": issue.get("effort"),
        "tags": issue.get("tags", []),
    }


def fetch_sonarqube(
    url: str,
    project_key: str,
    token: str,
    branch: str | None = None,
) -> dict[str, Any]:
    """Read quality gate, metrics, and open bugs/vulnerabilities from a SonarQube server."""
    client = SonarQubeClient(url, token)
    gate = client.get("qualitygates/project_status", projectKey=project_key, branch=branch)
    measures = client.get(
        "measures/component",
        component=project_key,
        metricKeys=",".join(METRIC_KEYS),
        branch=branch,
    )
    status = gate.get("projectStatus", {})
    metrics = {
        item["metric"]: _metric_value(item["metric"], item.get("value", ""))
        for item in measures.get("component", {}).get("measures", [])
        if "metric" in item
    }

    issues: list[dict[str, Any]] = []
    total_issues = 0
    for page in range(1, MAX_ISSUE_PAGES + 1):
        result = client.get(
            "issues/search",
            componentKeys=project_key,
            branch=branch,
            types="VULNERABILITY,BUG",
            resolved="false",
            ps=ISSUE_PAGE_SIZE,
            p=page,
        )
        total_issues = int(result.get("paging", {}).get("total", 0))
        issues.extend(_issue_payload(item, project_key) for item in result.get("issues", []))
        if len(issues) >= total_issues or not result.get("issues"):
            break

    return {
        "server": client.base_url,
        "project_key": project_key,
        "branch": branch,
        "quality_gate": {
            "status": status.get("status", "NONE"),
            "failed_conditions": [
                {
                    "metric": condition.get("metricKey"),
                    "comparator": condition.get("comparator"),
                    "threshold": condition.get("errorThreshold"),
                    "actual": condition.get("actualValue"),
                }
                for condition in status.get("conditions", [])
                if condition.get("status") == "ERROR"
            ],
        },
        "metrics": metrics,
        "issues": issues,
        "issues_total": total_issues,
        "issues_truncated": total_issues > len(issues),
        "note": (
            "Results come from your SonarQube server's latest analysis and are reported separately; "
            "they do not affect the SupplyGuard score."
        ),
    }
