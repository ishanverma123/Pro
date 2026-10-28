from __future__ import annotations

import json
import re
import tarfile
from dataclasses import dataclass
from http.client import HTTPException
from pathlib import PurePosixPath
from typing import Any, Iterator
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from supplyguard.scanner import (
    MAX_FILE_SIZE,
    MAX_SCAN_BYTES,
    MAX_SCAN_ENTRIES,
    MAX_SCAN_FILES,
    ScanError,
    _analyze_entries,
)


GITHUB_API = "https://api.github.com"
CODELOAD_HOST = "codeload.github.com"
MAX_ARCHIVE_DOWNLOAD = 75_000_000
MAX_API_RESPONSE = 1_000_000
OWNER_OR_REPO = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class _GitHubRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request: Request, response: Any, code: int, message: str, headers: Any, new_url: str) -> Request | None:
        destination = urlsplit(new_url)
        if destination.scheme != "https" or destination.hostname not in {
            "api.github.com",
            CODELOAD_HOST,
        }:
            raise ScanError("GitHub request redirected to a host that is not allowed.")
        return super().redirect_request(request, response, code, message, headers, new_url)


def _open_url(request: Request, timeout: int) -> Any:
    opener = build_opener(_GitHubRedirectHandler())
    return opener.open(request, timeout=timeout)


@dataclass
class _BoundedReader:
    response: Any
    limit: int
    consumed: int = 0

    def read(self, size: int = -1) -> bytes:
        remaining = self.limit - self.consumed
        if remaining <= 0:
            if self.response.read(1):
                raise ScanError("GitHub repository archive exceeds the download size limit.")
            return b""
        requested = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self.response.read(requested)
        self.consumed += len(data)
        if self.consumed > self.limit:
            raise ScanError("GitHub repository archive exceeds the download size limit.")
        return data


def parse_public_github_url(value: str) -> tuple[str, str, str]:
    try:
        parsed = urlsplit(value.strip())
        if (
            parsed.scheme != "https"
            or parsed.hostname != "github.com"
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) != 2:
            raise ValueError
        owner, repository = parts
        if repository.endswith(".git"):
            repository = repository[:-4]
        if not OWNER_OR_REPO.fullmatch(owner) or not OWNER_OR_REPO.fullmatch(repository):
            raise ValueError
        if owner in {".", ".."} or repository in {".", ".."}:
            raise ValueError
    except (ValueError, UnicodeError) as error:
        raise ScanError(
            "Enter a public GitHub repository URL in the form "
            "https://github.com/owner/repository."
        ) from error
    canonical = f"https://github.com/{owner}/{repository}"
    return owner, repository, canonical


def _request_json(url: str) -> dict[str, Any]:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "SupplyGuard/0.2.0",
        },
    )
    try:
        with _open_url(request, timeout=15) as response:
            if urlsplit(response.geturl()).hostname != "api.github.com":
                raise ScanError("GitHub API redirected to an unexpected host.")
            payload = response.read(MAX_API_RESPONSE + 1)
    except HTTPError as error:
        if error.code == 404:
            raise ScanError(
                "GitHub repository or its default-branch commit was not found. "
                "Private repositories are not supported."
            ) from error
        if error.code in {403, 429}:
            raise ScanError(
                "GitHub API access was denied or rate-limited. Try again later."
            ) from error
        raise ScanError(f"GitHub API request failed with HTTP {error.code}.") from error
    except (URLError, TimeoutError, OSError, HTTPException) as error:
        raise ScanError(f"Could not reach the GitHub API: {error}") from error
    if len(payload) > MAX_API_RESPONSE:
        raise ScanError("GitHub API response exceeds the size limit.")
    try:
        result = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ScanError("GitHub API returned invalid JSON.") from error
    if not isinstance(result, dict):
        raise ScanError("GitHub API returned an unexpected response.")
    return result


def _safe_member_path(name: str) -> str | None:
    if "\x00" in name or "\\" in name:
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    if len(path.parts) < 2:
        return None
    relative = PurePosixPath(*path.parts[1:])
    if not relative.parts:
        return None
    return relative.as_posix()


def _archive_entries(response: Any) -> Iterator[tuple[str, bytes]]:
    final_url = urlsplit(response.geturl())
    if final_url.scheme != "https" or final_url.hostname != CODELOAD_HOST:
        raise ScanError("GitHub archive redirected to an unexpected host.")
    bounded = _BoundedReader(response, MAX_ARCHIVE_DOWNLOAD)
    entry_count = 0
    file_count = 0
    total_bytes = 0
    try:
        archive = tarfile.open(fileobj=bounded, mode="r|gz")
        for member in archive:
            entry_count += 1
            if entry_count > MAX_SCAN_ENTRIES:
                raise ScanError(
                    f"GitHub archive contains more than {MAX_SCAN_ENTRIES} entries."
                )
            if member.isdir():
                continue
            if not member.isfile():
                continue
            file_count += 1
            if file_count > MAX_SCAN_FILES:
                raise ScanError(f"GitHub archive contains more than {MAX_SCAN_FILES} files.")
            if member.size < 0:
                raise ScanError("GitHub repository archive contains an invalid file size.")
            total_bytes += member.size
            if total_bytes > MAX_SCAN_BYTES:
                raise ScanError(
                    f"GitHub archive exceeds the {MAX_SCAN_BYTES // 1_000_000} MB scan limit."
                )
            relative_path = _safe_member_path(member.name)
            if relative_path is None:
                continue
            if member.size > MAX_FILE_SIZE:
                yield relative_path, None
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            content = extracted.read(MAX_FILE_SIZE + 1)
            if len(content) != member.size:
                raise ScanError("GitHub repository archive is truncated or malformed.")
            yield relative_path, content
    except (tarfile.TarError, OSError, EOFError) as error:
        raise ScanError(f"Could not read the GitHub repository archive: {error}") from error


def scan_github_repository(url: str, query_osv: bool = False) -> dict[str, Any]:
    owner, repository, canonical_url = parse_public_github_url(url)
    api_repo = (
        f"{GITHUB_API}/repos/{quote(owner, safe='')}/{quote(repository, safe='')}"
    )
    metadata = _request_json(api_repo)
    if metadata.get("private") is not False:
        raise ScanError("Only public GitHub repositories can be scanned.")
    default_branch = metadata.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise ScanError("GitHub repository did not report a default branch.")

    commit_info = _request_json(
        f"{api_repo}/commits/{quote(default_branch, safe='')}"
    )
    commit = commit_info.get("sha")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", commit):
        raise ScanError("GitHub API returned an invalid commit identifier.")

    archive_url = f"https://{CODELOAD_HOST}/{quote(owner, safe='')}/{quote(repository, safe='')}/tar.gz/{commit}"
    request = Request(archive_url, headers={"User-Agent": "SupplyGuard/0.2.0"})
    try:
        with _open_url(request, timeout=30) as response:
            report = _analyze_entries(
                canonical_url,
                _archive_entries(response),
                query_osv=query_osv,
                source={
                    "type": "github",
                    "repository_url": canonical_url,
                    "visibility": "public",
                    "commit": commit,
                    "default_branch": default_branch,
                },
            )
    except HTTPError as error:
        if error.code == 404:
            raise ScanError("Could not download the public GitHub repository archive.") from error
        if error.code in {403, 429}:
            raise ScanError("GitHub archive download was rate-limited or denied.") from error
        raise ScanError(f"GitHub archive request failed with HTTP {error.code}.") from error
    except (URLError, TimeoutError, OSError, HTTPException) as error:
        raise ScanError(f"Could not download the GitHub repository archive: {error}") from error
    return report
