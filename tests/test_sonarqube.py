import json
import unittest
from unittest.mock import patch

from supplyguard.cli import format_text_report, main
from supplyguard.scanner import ScanError
from supplyguard.sonarqube import SonarQubeClient, fetch_sonarqube


def fake_get(self, path, **params):
    if path == "qualitygates/project_status":
        return {"projectStatus": {"status": "ERROR", "conditions": [
            {"status": "ERROR", "metricKey": "new_coverage", "comparator": "LT", "errorThreshold": "80", "actualValue": "42"},
            {"status": "OK", "metricKey": "bugs"}]}}
    if path == "measures/component":
        return {"component": {"measures": [
            {"metric": "bugs", "value": "3"}, {"metric": "coverage", "value": "61.25"},
            {"metric": "security_rating", "value": "2.0"}]}}
    return {"paging": {"total": 1}, "issues": [{
        "key": "K1", "rule": "python:S5659", "type": "VULNERABILITY", "severity": "BLOCKER",
        "component": "proj:src/app.py", "line": 7, "message": "Bad crypto", "status": "OPEN"}]}


class SonarQubeTests(unittest.TestCase):
    def test_url_and_token_validation(self):
        for url in ("http://sonar.example.com", "https://user:pw@sonar.example.com", "ftp://x", "https://a.com?x=1"):
            with self.assertRaises(ScanError):
                SonarQubeClient(url, "token")
        with self.assertRaises(ScanError):
            SonarQubeClient("https://sonar.example.com", "")
        SonarQubeClient("http://localhost:9000", "token")

    def test_fetch_maps_gate_metrics_and_issues(self):
        with patch.object(SonarQubeClient, "get", fake_get):
            result = fetch_sonarqube("https://sonar.example.com/", "proj", "token", "main")
        self.assertEqual(result["server"], "https://sonar.example.com")
        self.assertEqual(result["quality_gate"]["status"], "ERROR")
        self.assertEqual(len(result["quality_gate"]["failed_conditions"]), 1)
        self.assertEqual(result["metrics"], {"bugs": 3, "coverage": 61.2, "security_rating": "B"})
        issue = result["issues"][0]
        self.assertEqual((issue["file"], issue["severity"]), ("src/app.py", "CRITICAL"))

    def test_cli_includes_section_and_gate_policy(self):
        import io
        import tempfile
        from contextlib import redirect_stdout

        with tempfile.TemporaryDirectory() as root, patch.object(SonarQubeClient, "get", fake_get), \
                patch.dict("os.environ", {"SONAR_TOKEN": "sqp_secret123"}):
            args = ["scan", root, "--sonar-url", "https://sonar.example.com", "--sonar-project", "proj"]
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(args + ["--format", "json"]), 0)
            self.assertEqual(json.loads(out.getvalue())["sonarqube"]["project_key"], "proj")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(main(args + ["--fail-on-quality-gate"]), 1)
            self.assertIn("Quality gate: ERROR", out.getvalue())
            self.assertNotIn("sqp_secret123", out.getvalue())

    def test_text_report_without_sonarqube_unchanged(self):
        report = {"summary": {k: 0 for k in ("critical", "high", "medium", "low", "total")},
                  "source": {}, "target": "x", "files_scanned": 0, "dependencies_found": 0,
                  "security_score": 100, "findings": []}
        self.assertNotIn("SonarQube", format_text_report(report))


if __name__ == "__main__":
    unittest.main()
