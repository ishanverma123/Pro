from __future__ import annotations

import json
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from supplyguard.cli import main
from supplyguard.scanner import (
    ScanError,
    _cvss3_base_score,
    _severity_from_osv,
    scan_directory,
)


class ScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, relative_path: str, content: str) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def write_secret(self) -> None:
        secret_value = "this-is-a-real-looking-secret"
        self.write("config.py", f"password = {secret_value!r}\n")

    def test_secret_findings_do_not_expose_matched_values(self) -> None:
        self.write_secret()

        report = scan_directory(self.root)

        self.assertEqual(report["summary"]["high"], 1)
        self.assertNotIn("this-is-a-real-looking-secret", json.dumps(report))
        finding = report["findings"][0]
        self.assertEqual(finding["category"], "Secrets")
        self.assertEqual(finding["confidence"], 6)
        self.assertIn("[REDACTED]", finding["evidence"])
        self.assertEqual(report["schema_version"], 2)

    def test_placeholder_is_not_reported_as_secret(self) -> None:
        self.write("config.py", 'password = "change-me-now"\n')

        report = scan_directory(self.root)

        self.assertEqual(report["findings"], [])

    def test_workflow_reports_mutable_action_and_write_all(self) -> None:
        self.write(
            ".github/workflows/ci.yml",
            "permissions: write-all\njobs:\n  test:\n    steps:\n"
            "      - uses: actions/checkout@v4\n",
        )

        report = scan_directory(self.root)

        self.assertEqual(report["summary"]["high"], 1)
        self.assertEqual(report["summary"]["medium"], 1)

    def test_dependency_parsers_count_exact_versions(self) -> None:
        self.write("requirements.txt", "requests==2.31.0\nflask>=3.0\n")
        self.write(
            "package.json",
            json.dumps({"dependencies": {"left-pad": "1.3.0", "express": "^4.0.0"}}),
        )
        self.write("go.mod", "module example.com/app\nrequire example.com/lib v1.2.3\n")

        report = scan_directory(self.root)

        self.assertEqual(report["dependencies_found"], 3)
        self.assertFalse(report["osv_lookup_enabled"])
        self.assertEqual(report["dependency_summary"]["direct"], 3)
        self.assertTrue(any("lookup was not run" in note for note in report["analysis_notes"]))

    def test_dependency_lockfiles_include_transitive_versions(self) -> None:
        self.write(
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "app", "version": "1.0.0"},
                        "node_modules/direct": {"version": "1.2.3"},
                        "node_modules/direct/node_modules/transitive": {"version": "2.3.4"},
                    },
                }
            ),
        )
        self.write(
            "poetry.lock",
            '[[package]]\nname = "flask"\nversion = "3.0.0"\n',
        )

        report = scan_directory(self.root)

        self.assertEqual(report["dependencies_found"], 3)
        self.assertEqual(report["dependency_summary"]["direct"], 1)
        self.assertEqual(report["dependency_summary"]["transitive"], 2)
        self.assertEqual(report["dependency_summary"]["ecosystems"], {"PyPI": 1, "npm": 2})

    def test_python_ast_checks_find_dynamic_sql_and_insecure_calls(self) -> None:
        self.write(
            "app.py",
            "cursor.execute(f'SELECT * FROM users WHERE name={name}')\n"
            "requests.get(url, verify=False)\n"
            "subprocess.run(command, shell=True)\n",
        )

        report = scan_directory(self.root)
        rule_ids = {item["rule_id"] for item in report["findings"]}

        self.assertIn("python.sql_injection", rule_ids)
        self.assertIn("python.tls_verification_disabled", rule_ids)
        self.assertIn("python.subprocess_shell_true", rule_ids)
        self.assertTrue(all(item["evidence"] for item in report["findings"]))

    def test_python_parameterized_sql_is_not_flagged(self) -> None:
        self.write(
            "app.py",
            'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n',
        )

        report = scan_directory(self.root)

        self.assertNotIn("python.sql_injection", {item["rule_id"] for item in report["findings"]})

    def test_python_parse_failures_are_reported_as_incomplete_analysis(self) -> None:
        self.write("broken.py", "def unfinished(:\n")

        report = scan_directory(self.root)

        self.assertEqual(report["checks_executed"]["python_ast_parse_failures"], 1)
        self.assertTrue(report["analysis_warnings"])

    def test_cvss_vector_is_scored_and_mapped_to_severity(self) -> None:
        vulnerability = {
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                }
            ]
        }

        self.assertEqual(_cvss3_base_score(vulnerability["severity"][0]["score"]), 9.8)
        self.assertEqual(_severity_from_osv(vulnerability), "CRITICAL")

    def test_osv_report_includes_cvss_aliases_and_fixed_versions(self) -> None:
        self.write("requirements.txt", "requests==1.0.0\n")
        response_body = json.dumps(
            {
                "results": [
                    {
                        "vulns": [
                            {
                                "id": "GHSA-example",
                                "summary": "Example advisory",
                                "aliases": ["CVE-2026-1234"],
                                "severity": [
                                    {
                                        "type": "CVSS_V3",
                                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    }
                                ],
                                "affected": [
                                    {
                                        "ranges": [
                                            {"events": [{"introduced": "0"}, {"fixed": "1.0.1"}]}
                                        ]
                                    }
                                ],
                                "references": [
                                    {"url": "https://example.com/security/advisory"}
                                ],
                            }
                        ]
                    }
                ]
            }
        ).encode()
        with patch("urllib.request.urlopen", return_value=io.BytesIO(response_body)):
            report = scan_directory(self.root, query_osv=True)

        finding = report["findings"][0]
        self.assertEqual(finding["severity"], "CRITICAL")
        self.assertEqual(finding["cvss_score"], 9.8)
        self.assertEqual(finding["aliases"], ["CVE-2026-1234"])
        self.assertEqual(finding["fix_versions"], ["1.0.1"])
        self.assertEqual(report["checks_executed"]["osv_queries"], 1)

    def test_osv_failure_is_not_silently_ignored(self) -> None:
        self.write("requirements.txt", "requests==2.31.0\n")
        with patch("supplyguard.scanner._query_osv", side_effect=ScanError("network unavailable")):
            with self.assertRaisesRegex(ScanError, "network unavailable"):
                scan_directory(self.root, query_osv=True)

    def test_cli_policy_exit_and_json_report(self) -> None:
        self.write_secret()
        output = self.root / "report.json"

        exit_code = main(["scan", str(self.root), "--output", str(output)])

        self.assertEqual(exit_code, 1)
        self.assertTrue(output.exists())
        self.assertEqual(json.loads(output.read_text())["summary"]["high"], 1)

    def test_cli_can_disable_policy_gate(self) -> None:
        self.write_secret()

        exit_code = main(["scan", str(self.root), "--fail-on", "never"])

        self.assertEqual(exit_code, 0)

    def test_cli_text_and_json_console_formats(self) -> None:
        import io
        from contextlib import redirect_stdout

        self.write_secret()
        text = io.StringIO()
        with redirect_stdout(text):
            main(["scan", str(self.root), "--fail-on", "never"])
        self.assertIn("SupplyGuard scan report", text.getvalue())
        self.assertIn("[HIGH]", text.getvalue())
        self.assertNotIn("\033[", text.getvalue())

        as_json = io.StringIO()
        with redirect_stdout(as_json):
            main(["scan", str(self.root), "--format", "json", "--fail-on", "never"])
        self.assertEqual(json.loads(as_json.getvalue())["summary"]["high"], 1)

    def test_cli_dispatches_github_urls(self) -> None:
        report = scan_directory(self.root)
        with patch("supplyguard.github.scan_github_repository", return_value=report) as scan:
            exit_code = main(["scan", "https://github.com/octo/repo", "--fail-on", "never"])
        self.assertEqual(exit_code, 0)
        scan.assert_called_once_with("https://github.com/octo/repo", query_osv=False)

    def test_invalid_scan_target_is_an_error(self) -> None:
        with self.assertRaises(ScanError):
            scan_directory(self.root / "does-not-exist")

    def test_generated_directories_are_pruned_from_scan(self) -> None:
        credential_name = "pass" + "word"
        credential_value = "never" + " scan this"
        secret_fixture = f"{credential_name} = {credential_value!r}\n"
        self.write(".git/config.py", secret_fixture)
        self.write("node_modules/pkg/config.py", secret_fixture)
        self.write("app.py", "print('safe')\n")

        report = scan_directory(self.root)

        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()
