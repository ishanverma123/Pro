from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
import threading
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from supplyguard.github import parse_public_github_url, scan_github_repository
from supplyguard.scanner import ScanError, scan_directory
from supplyguard.sonarqube import fetch_sonarqube


LOGGER = logging.getLogger("supplyguard.web")
MAX_REQUEST_BYTES = 16_384
MAX_RETAINED_SCANS = 25
STATIC_FILES = {
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
}


@dataclass(frozen=True)
class SonarConfig:
    """Server-side SonarQube settings; the token never leaves this process."""

    url: str = ""
    project: str = ""
    token: str = ""

    @classmethod
    def from_environment(cls) -> "SonarConfig":
        return cls(
            url=os.environ.get("SONAR_HOST_URL", "").strip(),
            project=os.environ.get("SONAR_PROJECT_KEY", "").strip(),
            token=os.environ.get("SONAR_TOKEN", ""),
        )

    def public_view(self) -> dict[str, Any]:
        return {
            "token_configured": bool(self.token),
            "url": self.url,
            "url_locked": bool(self.url),
            "project": self.project,
            "default_enabled": bool(self.token and self.url and self.project),
        }


class ScanManager:
    """Runs at most one scan at a time and retains a bounded in-memory history."""

    def __init__(self, sonar: SonarConfig | None = None) -> None:
        self._sonar = sonar or SonarConfig()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="supplyguard-scan")
        self._lock = threading.Lock()
        self._jobs: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self._active: str | None = None

    def start(
        self,
        source_type: str,
        target: str | Path,
        query_osv: bool,
        sonar_request: dict[str, str] | None = None,
    ) -> str:
        with self._lock:
            if self._active is not None:
                active = self._jobs.get(self._active)
                if active and active["status"] in {"queued", "running"}:
                    raise RuntimeError("A scan is already in progress.")

            job_id = secrets.token_urlsafe(18)
            job = {
                "id": job_id,
                "status": "queued",
                "source_type": source_type,
                "target": str(target),
                "created_at": None,
                "report": None,
                "error": None,
            }
            self._jobs[job_id] = job
            self._active = job_id
            self._trim_jobs()
        try:
            future = self._executor.submit(self._run, job_id, source_type, target, query_osv, sonar_request)
        except RuntimeError:
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.update(status="failed", error="The scan worker is not available.")
                if self._active == job_id:
                    self._active = None
            raise
        future.add_done_callback(lambda completed: self._clear_active(job_id, completed))
        return job_id

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def shutdown(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=True)

    def _fetch_sonarqube(self, request: dict[str, str]) -> dict[str, Any]:
        url = self._sonar.url or request["url"]
        try:
            return fetch_sonarqube(
                url, request["project"], self._sonar.token, request["branch"] or None
            )
        except ScanError as error:
            # SonarQube is supplementary; its failure must not discard the scan.
            return {
                "error": str(error),
                "server": url,
                "project_key": request["project"],
                "branch": request["branch"] or None,
            }

    def _run(
        self,
        job_id: str,
        source_type: str,
        target: str | Path,
        query_osv: bool,
        sonar_request: dict[str, str] | None,
    ) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job["status"] = "running"
        try:
            if source_type == "github":
                report = scan_github_repository(str(target), query_osv=query_osv)
            else:
                report = scan_directory(Path(target), query_osv=query_osv)
            if sonar_request:
                report["sonarqube"] = self._fetch_sonarqube(sonar_request)
        except ScanError as error:
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.update(status="failed", error=str(error))
        except Exception:
            LOGGER.exception("Unexpected scan failure for job %s", job_id)
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.update(status="failed", error="An unexpected scan error occurred.")
        else:
            with self._lock:
                job = self._jobs.get(job_id)
                if job:
                    job.update(
                        status="complete",
                        created_at=report["generated_at"],
                        report=report,
                    )

    def _clear_active(self, job_id: str, future: Future[None]) -> None:
        if future.cancelled():
            with self._lock:
                job = self._jobs.get(job_id)
                if job and job["status"] == "queued":
                    job.update(status="failed", error="The scan was cancelled.")
        with self._lock:
            if self._active == job_id:
                self._active = None

    def _trim_jobs(self) -> None:
        while len(self._jobs) > MAX_RETAINED_SCANS:
            self._jobs.popitem(last=False)


class LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        token: str,
        manager: ScanManager,
        sonar: SonarConfig | None = None,
    ) -> None:
        self.csrf_token = token
        self.sonar = sonar or SonarConfig()
        self.scan_manager = manager
        super().__init__(address, DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server: LocalHTTPServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if not self._valid_host():
            self._send_error(HTTPStatus.BAD_REQUEST, "Invalid host header.")
            return

        request_path = urlsplit(self.path).path
        if request_path == "/":
            template = files("supplyguard.web").joinpath("index.html").read_text(
                encoding="utf-8"
            )
            body = template.replace("__CSRF_TOKEN__", self.server.csrf_token).encode("utf-8")
            self._send_bytes(HTTPStatus.OK, body, "text/html; charset=utf-8", no_store=True)
            return
        if request_path in STATIC_FILES:
            filename, content_type = STATIC_FILES[request_path]
            body = files("supplyguard.web").joinpath(filename).read_bytes()
            self._send_bytes(HTTPStatus.OK, body, content_type, no_store=True)
            return
        if request_path == "/api/config":
            self._send_json(HTTPStatus.OK, {"sonarqube": self.server.sonar.public_view()})
            return
        if request_path.startswith("/api/scans/"):
            job_id = request_path.removeprefix("/api/scans/")
            if not job_id or "/" in job_id:
                self._send_error(HTTPStatus.NOT_FOUND, "Scan not found.")
                return
            job = self.server.scan_manager.get(job_id)
            if job is None:
                self._send_error(HTTPStatus.NOT_FOUND, "Scan not found.")
                return
            self._send_json(HTTPStatus.OK, job)
            return
        self._send_error(HTTPStatus.NOT_FOUND, "Not found.")

    def do_POST(self) -> None:
        if not self._valid_host():
            self._send_error(HTTPStatus.BAD_REQUEST, "Invalid host header.")
            return
        if urlsplit(self.path).path != "/api/scans":
            self._send_error(HTTPStatus.NOT_FOUND, "Not found.")
            return
        if not self._valid_origin():
            self._send_error(HTTPStatus.FORBIDDEN, "Request origin is not allowed.")
            return
        if self.headers.get("X-SupplyGuard-Token") != self.server.csrf_token:
            self._send_error(HTTPStatus.FORBIDDEN, "Request token is invalid.")
            return
        if self.headers.get_content_type() != "application/json":
            self._send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Expected application/json.")
            return
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_error(HTTPStatus.LENGTH_REQUIRED, "A valid Content-Length is required.")
            return
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body is too large.")
            return
        try:
            body = self.rfile.read(length)
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_error(HTTPStatus.BAD_REQUEST, "Request body must be valid JSON.")
            return
        if not isinstance(payload, dict):
            self._send_error(HTTPStatus.BAD_REQUEST, "Request body must be a JSON object.")
            return
        if set(payload) - {"source", "target", "osv", "sonarqube"}:
            self._send_error(HTTPStatus.BAD_REQUEST, "Request contains unsupported fields.")
            return
        source_type = payload.get("source", "local")
        target_value = payload.get("target")
        if source_type not in {"local", "github"}:
            self._send_error(HTTPStatus.BAD_REQUEST, "Source must be local or github.")
            return
        if not isinstance(target_value, str) or not target_value.strip():
            self._send_error(HTTPStatus.BAD_REQUEST, "A directory path or repository URL is required.")
            return
        if len(target_value) > 4096:
            self._send_error(HTTPStatus.BAD_REQUEST, "The path or URL is too long.")
            return
        if not isinstance(payload.get("osv", False), bool):
            self._send_error(HTTPStatus.BAD_REQUEST, "The osv option must be a boolean.")
            return
        sonar_request = self._parse_sonar_request(payload.get("sonarqube"))
        if sonar_request is False:
            return

        if source_type == "github":
            try:
                _, _, canonical_url = parse_public_github_url(target_value)
            except ScanError as error:
                self._send_error(HTTPStatus.BAD_REQUEST, str(error))
                return
            target: str | Path = canonical_url
        else:
            try:
                target = Path(target_value).expanduser().resolve()
            except (OSError, RuntimeError, ValueError):
                self._send_error(HTTPStatus.BAD_REQUEST, "The directory path is invalid.")
                return
            if not target.is_dir():
                self._send_error(HTTPStatus.BAD_REQUEST, "The selected path is not a directory.")
                return
        try:
            job_id = self.server.scan_manager.start(
                source_type, target, payload.get("osv", False), sonar_request or None
            )
        except RuntimeError as error:
            self._send_json(HTTPStatus.CONFLICT, {"error": str(error)})
            return
        self._send_json(HTTPStatus.ACCEPTED, {"id": job_id, "status": "queued"})

    def _parse_sonar_request(self, value: Any) -> dict[str, str] | None | bool:
        """Return the validated request, None when disabled, or False after sending an error."""
        if value is None:
            return None
        if not isinstance(value, dict) or set(value) - {"url", "project", "branch"}:
            self._send_error(HTTPStatus.BAD_REQUEST, "Invalid SonarQube options.")
            return False
        fields = {key: value.get(key, "") for key in ("url", "project", "branch")}
        if not all(isinstance(item, str) and len(item) <= 2048 for item in fields.values()):
            self._send_error(HTTPStatus.BAD_REQUEST, "Invalid SonarQube options.")
            return False
        fields = {key: item.strip() for key, item in fields.items()}
        config = self.server.sonar
        if not config.token:
            self._send_error(
                HTTPStatus.BAD_REQUEST,
                "Set SONAR_TOKEN in the environment before starting the dashboard to use SonarQube.",
            )
            return False
        if not (config.url or fields["url"]):
            self._send_error(HTTPStatus.BAD_REQUEST, "A SonarQube server URL is required.")
            return False
        if not fields["project"]:
            self._send_error(HTTPStatus.BAD_REQUEST, "A SonarQube project key is required.")
            return False
        return fields

    def log_message(self, format: str, *args: Any) -> None:
        LOGGER.info("%s - %s", self.client_address[0], format % args)

    def _valid_host(self) -> bool:
        host_header = self.headers.get("Host", "")
        try:
            expected_host = self.server.server_address[0]
            expected_port = self.server.server_address[1]
            host, separator, port = host_header.rpartition(":")
            if not separator:
                host, port = host_header, "80"
            if port != str(expected_port):
                return False
            host = host.strip("[]").lower()
            if host == "localhost":
                return ipaddress.ip_address(expected_host).is_loopback
            return host == expected_host.lower().strip("[]")
        except ValueError:
            return False

    def _valid_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return False
        host = self.headers.get("Host", "")
        return origin == f"http://{host}"

    def _send_json(self, status: HTTPStatus, value: dict[str, Any]) -> None:
        body = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8", no_store=True)

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json(status, {"error": message})

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        no_store: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        )
        self.send_header("Cache-Control", "no-store" if no_store else "no-cache")
        self.end_headers()
        self.wfile.write(body)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    try:
        if host == "localhost":
            bind_host = "127.0.0.1"
        else:
            address = ipaddress.ip_address(host)
            if not address.is_loopback:
                raise ValueError("SupplyGuard's dashboard can only bind to a loopback address.")
            bind_host = str(address)
    except ValueError as error:
        raise ValueError(
            "SupplyGuard's dashboard can only bind to a loopback address "
            "(localhost, 127.0.0.1, or ::1)."
        ) from error

    token = secrets.token_urlsafe(32)
    sonar = SonarConfig.from_environment()
    manager = ScanManager(sonar)
    server = LocalHTTPServer((bind_host, port), token, manager, sonar)
    actual_host, actual_port = server.server_address[:2]
    display_host = f"[{actual_host}]" if ":" in actual_host else actual_host
    print(f"SupplyGuard dashboard: http://{display_host}:{actual_port}")
    print("Local-only server. Press Ctrl-C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SupplyGuard dashboard.")
    finally:
        server.shutdown()
        server.server_close()
        manager.shutdown()
