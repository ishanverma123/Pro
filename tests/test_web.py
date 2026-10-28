from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import patch

from supplyguard.github import parse_public_github_url
from supplyguard.scanner import ScanError
from supplyguard.sonarqube import SonarQubeClient
from supplyguard.web.server import LocalHTTPServer, ScanManager, SonarConfig, serve


class WebServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.manager = ScanManager()
        self.token = "t"
        self.server = LocalHTTPServer(("127.0.0.1", 0), self.token, self.manager)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.manager.shutdown()
        self.thread.join(timeout=2)
        self.temporary_directory.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = HTTPConnection(self.host, self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
        connection.close()
        return result

    def scan_headers(self) -> dict[str, str]:
        return {
            "Origin": f"http://{self.host}:{self.port}",
            "X-SupplyGuard-Token": self.token,
            "Content-Type": "application/json",
        }

    def use_sonar(self, config: SonarConfig) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.manager.shutdown()
        self.thread.join(timeout=2)
        self.manager = ScanManager(config)
        self.server = LocalHTTPServer(("127.0.0.1", 0), self.token, self.manager, config)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def run_scan(self, payload: dict) -> dict:
        status, _, body = self.request(
            "POST", "/api/scans", body=json.dumps(payload).encode(), headers=self.scan_headers()
        )
        self.assertEqual(status, 202, body)
        job_id = json.loads(body)["id"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            _, _, body = self.request("GET", f"/api/scans/{job_id}")
            job = json.loads(body)
            if job["status"] in {"complete", "failed"}:
                return job
            time.sleep(0.05)
        self.fail("scan did not finish")

    def test_config_endpoint_never_exposes_the_token(self) -> None:
        self.use_sonar(SonarConfig("https://sonar.example.com", "proj", "sqp_secret"))
        status, _, body = self.request("GET", "/api/config")
        config = json.loads(body)["sonarqube"]
        self.assertEqual(status, 200)
        self.assertNotIn(b"sqp_secret", body)
        self.assertTrue(config["default_enabled"] and config["url_locked"])

        self.use_sonar(SonarConfig())
        config = json.loads(self.request("GET", "/api/config")[2])["sonarqube"]
        self.assertFalse(config["token_configured"] or config["default_enabled"])

    def test_sonarqube_requires_server_side_token_and_valid_options(self) -> None:
        payload = {"target": str(self.root), "sonarqube": {"url": "https://s.example.com", "project": "p"}}
        status, _, body = self.request(
            "POST", "/api/scans", body=json.dumps(payload).encode(), headers=self.scan_headers()
        )
        self.assertEqual(status, 400)
        self.assertIn(b"SONAR_TOKEN", body)

        self.use_sonar(SonarConfig("", "", "tok"))
        for bad in ({"url": "https://s.example.com"}, {"project": "p"}, {"project": "p", "url": "x", "extra": 1}):
            status, _, _ = self.request(
                "POST", "/api/scans",
                body=json.dumps({"target": str(self.root), "sonarqube": bad}).encode(),
                headers=self.scan_headers(),
            )
            self.assertEqual(status, 400, bad)

    def test_scan_includes_sonarqube_and_survives_its_failure(self) -> None:
        self.use_sonar(SonarConfig("https://sonar.example.com", "", "tok"))
        request = {"target": str(self.root), "sonarqube": {"url": "https://evil.example", "project": "p"}}
        calls = []

        def fake(url, project, token, branch):
            calls.append((url, token))
            return {"quality_gate": {"status": "OK"}, "project_key": project}

        with patch("supplyguard.web.server.fetch_sonarqube", fake):
            job = self.run_scan(request)
        self.assertEqual(job["report"]["sonarqube"]["quality_gate"]["status"], "OK")
        self.assertEqual(calls, [("https://sonar.example.com", "tok")])

        with patch.object(SonarQubeClient, "get", side_effect=ScanError("unreachable")):
            job = self.run_scan(request)
        self.assertEqual(job["status"], "complete")
        self.assertEqual(job["report"]["sonarqube"]["error"], "unreachable")
        self.assertNotIn("sonarqube", self.run_scan({"target": str(self.root)})["report"])

    def test_dashboard_and_assets_have_hardening_headers(self) -> None:
        status, headers, body = self.request("GET", "/")

        self.assertEqual(status, 200)
        self.assertIn(self.token.encode(), body)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertEqual(headers["x-content-type-options"], "nosniff")

        asset_status, _, asset_body = self.request("GET", "/app.js")
        self.assertEqual(asset_status, 200)
        self.assertIn(b"createFindingCard", asset_body)

    def test_host_header_and_csrf_controls_reject_cross_site_requests(self) -> None:
        status, _, _ = self.request("GET", "/", headers={"Host": "attacker.example"})
        self.assertEqual(status, 400)

        body = json.dumps({"target": str(self.root)}).encode()
        status, _, _ = self.request(
            "POST",
            "/api/scans",
            body=body,
            headers={
                "Origin": f"http://attacker.example:{self.port}",
                "X-SupplyGuard-Token": self.token,
                "Content-Type": "application/json",
            },
        )
        self.assertEqual(status, 403)

        status, _, _ = self.request(
            "POST",
            "/api/scans",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        self.assertEqual(status, 403)

    def test_scan_api_validates_input_and_returns_completed_report(self) -> None:
        (self.root / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
        body = json.dumps(
            {"source": "local", "target": str(self.root), "osv": False}
        ).encode()
        status, _, response_body = self.request(
            "POST", "/api/scans", body=body, headers=self.scan_headers()
        )
        self.assertEqual(status, 202)
        job_id = json.loads(response_body)["id"]

        deadline = time.monotonic() + 3
        job = None
        while time.monotonic() < deadline:
            status, _, response_body = self.request("GET", f"/api/scans/{job_id}")
            self.assertEqual(status, 200)
            job = json.loads(response_body)
            if job["status"] in {"complete", "failed"}:
                break
            time.sleep(0.02)

        self.assertIsNotNone(job)
        self.assertEqual(job["status"], "complete")
        self.assertEqual(job["report"]["dependencies_found"], 1)

    def test_invalid_request_fields_and_non_directory_are_rejected(self) -> None:
        headers = self.scan_headers()
        for payload in (
            {"source": "local", "target": str(self.root), "unexpected": True},
            {"source": "local", "target": str(self.root / "missing")},
            {"source": "local", "target": ""},
            {"source": "github", "target": "http://127.0.0.1/owner/repo"},
        ):
            status, _, _ = self.request(
                "POST",
                "/api/scans",
                body=json.dumps(payload).encode(),
                headers=headers,
            )
            self.assertEqual(status, 400)

    def test_public_github_scan_is_dispatched_to_github_analyzer(self) -> None:
        expected_report = {
            "generated_at": "test-time",
            "findings": [],
            "schema_version": 2,
            "source": {"type": "github"},
        }
        with patch(
            "supplyguard.web.server.scan_github_repository",
            return_value=expected_report,
        ) as github_scan:
            status, _, response_body = self.request(
                "POST",
                "/api/scans",
                body=json.dumps(
                    {
                        "source": "github",
                        "target": "https://github.com/example/project",
                        "osv": False,
                    }
                ).encode(),
                headers=self.scan_headers(),
            )
            self.assertEqual(status, 202)
            job_id = json.loads(response_body)["id"]
            deadline = time.monotonic() + 2
            job = None
            while time.monotonic() < deadline:
                status, _, response_body = self.request("GET", f"/api/scans/{job_id}")
                job = json.loads(response_body)
                if job["status"] in {"complete", "failed"}:
                    break
                time.sleep(0.02)

        self.assertEqual(job["status"], "complete")
        self.assertEqual(job["report"], expected_report)
        github_scan.assert_called_once_with("https://github.com/example/project", query_osv=False)

    def test_concurrent_scan_is_rejected(self) -> None:
        started = threading.Event()
        release = threading.Event()

        def wait_for_release(*args: object, **kwargs: object) -> dict[str, object]:
            started.set()
            release.wait(timeout=3)
            return {"generated_at": "test", "findings": []}

        with patch("supplyguard.web.server.scan_directory", side_effect=wait_for_release):
            job_id = self.manager.start("local", self.root, False)
            self.assertTrue(started.wait(timeout=2))
            with self.assertRaisesRegex(RuntimeError, "already in progress"):
                self.manager.start("local", self.root, False)
            release.set()
            deadline = time.monotonic() + 2
            while (
                time.monotonic() < deadline
                and self.manager.get(job_id)["status"] not in {"complete", "failed"}
            ):
                time.sleep(0.01)
            self.assertEqual(self.manager.get(job_id)["status"], "complete")

    def test_server_refuses_non_loopback_bind(self) -> None:
        with self.assertRaisesRegex(ValueError, "loopback"):
            serve(host="192.0.2.10", port=0)

    def test_public_github_urls_are_canonicalized_and_validated(self) -> None:
        owner, repository, canonical = parse_public_github_url(
            "https://github.com/example/project.git"
        )
        self.assertEqual((owner, repository), ("example", "project"))
        self.assertEqual(canonical, "https://github.com/example/project")

        for value in (
            "http://github.com/example/project",
            "https://github.com.evil.example/example/project",
            "https://github.com/example/project/tree/main",
            "https://user@github.com/example/project",
            "https://127.0.0.1/example/project",
        ):
            with self.subTest(value=value), self.assertRaises(ScanError):
                parse_public_github_url(value)


if __name__ == "__main__":
    unittest.main()
