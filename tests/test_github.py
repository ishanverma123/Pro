from __future__ import annotations

import io
import tarfile
import unittest
from unittest.mock import patch

from supplyguard.github import scan_github_repository
from supplyguard.scanner import ScanError


class FakeResponse(io.BytesIO):
    def __init__(self, value: bytes, url: str) -> None:
        super().__init__(value)
        self.url = url

    def geturl(self) -> str:
        return self.url


def make_archive(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for path, content in files.items():
            member = tarfile.TarInfo(f"example-repo-deadbeef/{path}")
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    return output.getvalue()


class GitHubScanTests(unittest.TestCase):
    def test_scans_public_archive_at_pinned_commit(self) -> None:
        commit = "a" * 40
        archive = make_archive(
            {
                "requirements.txt": b"requests==2.31.0\n",
                "app.py": b"cursor.execute(f'SELECT {value}')\n",
            }
        )
        response = FakeResponse(
            archive, "https://codeload.github.com/example/project/tar.gz/" + commit
        )
        with (
            patch(
                "supplyguard.github._request_json",
                side_effect=[
                    {"private": False, "default_branch": "main"},
                    {"sha": commit},
                ],
            ),
            patch("supplyguard.github._open_url", return_value=response) as open_url,
        ):
            report = scan_github_repository("https://github.com/example/project")

        self.assertEqual(report["source"]["type"], "github")
        self.assertEqual(report["source"]["visibility"], "public")
        self.assertEqual(report["source"]["commit"], commit)
        self.assertEqual(report["dependencies_found"], 1)
        self.assertIn("python.sql_injection", {item["rule_id"] for item in report["findings"]})
        self.assertEqual(open_url.call_count, 1)
        self.assertIn(commit, open_url.call_args.args[0].full_url)

    def test_private_repository_is_rejected_without_fetching_archive(self) -> None:
        with (
            patch(
                "supplyguard.github._request_json",
                return_value={"private": True, "default_branch": "main"},
            ),
            patch("supplyguard.github._open_url") as open_url,
            self.assertRaisesRegex(ScanError, "Only public"),
        ):
            scan_github_repository("https://github.com/example/private")
        open_url.assert_not_called()

    def test_archive_path_traversal_is_not_scanned(self) -> None:
        commit = "b" * 40
        credential_name = "pass" + "word"
        fixture = f"{credential_name}='should not appear'\n".encode()
        archive = make_archive({"../../outside.py": fixture})
        response = FakeResponse(
            archive, "https://codeload.github.com/example/project/tar.gz/" + commit
        )
        with (
            patch(
                "supplyguard.github._request_json",
                side_effect=[
                    {"private": False, "default_branch": "main"},
                    {"sha": commit},
                ],
            ),
            patch("supplyguard.github._open_url", return_value=response),
        ):
            report = scan_github_repository("https://github.com/example/project")
        self.assertEqual(report["files_scanned"], 0)
        self.assertEqual(report["findings"], [])


if __name__ == "__main__":
    unittest.main()
