from __future__ import annotations

import ast
import json
import math
import os
import re
import time
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None


SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
SEVERITY_ORDER = {severity: index for index, severity in enumerate(SEVERITIES)}
SEVERITY_PENALTY = {"CRITICAL": 30, "HIGH": 18, "MEDIUM": 8, "LOW": 2}
IGNORED_DIRECTORIES = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".tox",
    ".nox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".next",
    ".cache",
    "dist",
    "build",
    "vendor",
}
MAX_FILE_SIZE = 1_000_000
MAX_SCAN_FILES = 25_000
MAX_SCAN_ENTRIES = 100_000
MAX_SCAN_BYTES = 250_000_000
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

SECRET_PATTERNS = (
    ("AWS access key ID", "HIGH", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "GitHub token",
        "CRITICAL",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    ),
    (
        "Slack token",
        "CRITICAL",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    (
        "Google API key",
        "HIGH",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    (
        "Stripe live key",
        "CRITICAL",
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    ),
    (
        "Private key",
        "HIGH",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "Hard-coded credential",
        "HIGH",
        re.compile(
            r"""(?i)\b(?:password|passwd|secret(?:[_-]?(?:access[_-]?)?key)?|"""
            r"""private[_-]?key|access[_-]?key|client[_-]?secret|"""
            r"""api[_-]?key|access[_-]?token|auth[_-]?token|token)\b\s*[:=]\s*"""
            r"""(?:(?P<quote>['"])(?P<value>[^'"]{8,})(?P=quote)|"""
            r"""(?P<bare>[A-Za-z0-9/+_=.-]{8,}))"""
        ),
    ),
)
PLACEHOLDER_VALUE = re.compile(
    r"(?i)^(?:(?:change[ _-]?me|example|sample|placeholder)(?:[ _-].*)?|your[_ -].*|<.*>|\$\{.*\})$"
)
ACTION_USE = re.compile(r"^\s*(?:-\s*)?uses:\s*['\"]?([^\s'\"]+)", re.IGNORECASE)
IMMUTABLE_SHA = re.compile(r"@[0-9a-fA-F]{40}$")
UNTRUSTED_PR_REF = re.compile(
    r"\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)"
)
REQUIREMENT = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)\s*(==|===)\s*([^\s;#]+)"
)
GO_REQUIRE = re.compile(
    r"^\s*(?:require\s+)?([A-Za-z0-9._~/-]+)\s+(v\d+\.\d+\.\d+[^\s]*)"
)
EXACT_NPM_VERSION = re.compile(r"^v?\d+\.\d+(?:\.\d+)?(?:[-+][A-Za-z0-9.-]+)?$")
PYTHON_EXTENSIONS = {".py", ".pyw"}
LANGUAGE_BY_EXTENSION = {
    ".py": "Python",
    ".pyw": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".java": "Java",
    ".kt": "Kotlin",
    ".rs": "Rust",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".c": "C/C++",
    ".h": "C/C++",
    ".cc": "C/C++",
    ".cpp": "C/C++",
    ".hpp": "C/C++",
    ".swift": "Swift",
    ".sh": "Shell",
    ".bash": "Shell",
    ".yaml": "YAML",
    ".yml": "YAML",
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    file: str
    line: int
    description: str
    recommendation: str
    source: str
    category: str
    confidence: int
    cwe: str | None
    evidence: str
    references: tuple[str, ...] = ()
    fix_versions: tuple[str, ...] = ()
    cvss_score: float | None = None
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    ecosystem: str
    file: str
    line: int
    direct: bool = True


class ScanError(Exception):
    """Raised when a scan cannot produce a trustworthy report."""


def _relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _iter_files(root: Path) -> tuple[list[Path], list[str]]:
    files: list[Path] = []
    symlinks: list[str] = []

    def raise_walk_error(error: OSError) -> None:
        raise ScanError(f"Could not inspect scan target: {error}") from error

    entries_seen = 0
    for current, directory_names, file_names in os.walk(
        root, topdown=True, followlinks=False, onerror=raise_walk_error
    ):
        current_path = Path(current)
        entries_seen += len(directory_names) + len(file_names)
        if entries_seen > MAX_SCAN_ENTRIES:
            raise ScanError(f"Scan target contains more than {MAX_SCAN_ENTRIES} filesystem entries.")
        kept_directories: list[str] = []
        for name in directory_names:
            path = current_path / name
            if name in IGNORED_DIRECTORIES or name.startswith((".venv-", "venv-", "env-")):
                continue
            if path.is_symlink():
                symlinks.append(_relative(path, root))
                continue
            kept_directories.append(name)
        directory_names[:] = sorted(kept_directories)
        for name in sorted(file_names):
            path = current_path / name
            if path.is_symlink():
                symlinks.append(_relative(path, root))
                continue
            files.append(path)
            if len(files) > MAX_SCAN_FILES:
                raise ScanError(f"Scan target contains more than {MAX_SCAN_FILES} files.")
    return sorted(files), sorted(symlinks)


def _new_finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    file: str,
    line: int,
    description: str,
    recommendation: str,
    source: str,
    category: str,
    confidence: int,
    evidence: str,
    cwe: str | None = None,
    references: Iterable[str] = (),
    fix_versions: Iterable[str] = (),
    cvss_score: float | None = None,
    aliases: Iterable[str] = (),
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        file=file,
        line=max(1, line),
        description=description,
        recommendation=recommendation,
        source=source,
        category=category,
        confidence=max(1, min(10, confidence)),
        cwe=cwe,
        evidence=_redact_evidence(evidence),
        references=tuple(references),
        fix_versions=tuple(fix_versions),
        cvss_score=cvss_score,
        aliases=tuple(aliases),
    )


def _redact_evidence(line: str) -> str:
    evidence = line.strip()
    for _, _, pattern in SECRET_PATTERNS:
        if "value" in pattern.groupindex or "bare" in pattern.groupindex:
            def redact(match: re.Match[str]) -> str:
                matched_value = match.groupdict().get("value") or match.groupdict().get("bare")
                return match.group(0).replace(matched_value or "", "[REDACTED]")

            evidence = pattern.sub(redact, evidence)
        else:
            evidence = pattern.sub("[REDACTED]", evidence)
    return evidence[:500]


def _scan_secrets(text: str, relative_path: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for title, severity, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            if title == "Hard-coded credential":
                value = (match.group("value") or match.group("bare") or "").strip()
                if match.group("bare") and re.match(r"\s*\(", line[match.end() :]):
                    continue
                if PLACEHOLDER_VALUE.fullmatch(value):
                    continue
            findings.append(
                _new_finding(
                    rule_id="secret." + title.lower().replace(" ", "_"),
                    title=f"Possible {title.lower()}",
                    severity=severity,
                    file=relative_path,
                    line=line_number,
                    description=(
                        f"A line matches a pattern commonly associated with a {title.lower()}. "
                        "This is a pattern match and needs validation; the matched value is "
                        "intentionally omitted from this report."
                    ),
                    recommendation=(
                        "Verify whether the value is active. If real, revoke or rotate it, "
                        "remove it from repository history where appropriate, and use a "
                        "managed secret store."
                    ),
                    source="SupplyGuard",
                    category="Secrets",
                    confidence=9 if title != "Hard-coded credential" else 6,
                    cwe="CWE-798",
                    evidence=line,
                    references=("https://cwe.mitre.org/data/definitions/798.html",),
                )
            )
    return findings


class _PythonSecurityVisitor(ast.NodeVisitor):
    def __init__(self, source: str, relative_path: str) -> None:
        self.source = source
        self.lines = source.splitlines()
        self.relative_path = relative_path
        self.findings: list[Finding] = []
        self.dynamic_query_names: set[str] = set()

    def visit_Assign(self, node: ast.Assign) -> None:
        dynamic = self._is_dynamic_string(node.value)
        for target in node.targets:
            if isinstance(target, ast.Name):
                if dynamic:
                    self.dynamic_query_names.add(target.id)
                else:
                    self.dynamic_query_names.discard(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name):
            if node.value is not None and self._is_dynamic_string(node.value):
                self.dynamic_query_names.add(node.target.id)
            else:
                self.dynamic_query_names.discard(node.target.id)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        line = self._line(node)
        function_name = self._call_name(node.func)

        if (
            function_name.endswith((".execute", ".executemany"))
            and node.args
            and self._is_dynamic_string(node.args[0])
        ):
            self.findings.append(
                _new_finding(
                    rule_id="python.sql_injection",
                    title="SQL query is assembled with string interpolation",
                    severity="HIGH",
                    file=self.relative_path,
                    line=node.lineno,
                    description=(
                        "A SQL execution call receives a dynamically formatted query string. "
                        "If untrusted data reaches the interpolation, an attacker may alter "
                        "the query."
                    ),
                    recommendation=(
                        "Use the database driver's parameterized query API and pass values "
                        "separately. Do not construct SQL by concatenating or formatting "
                        "untrusted values."
                    ),
                    source="SupplyGuard",
                    category="Code",
                    confidence=8,
                    cwe="CWE-89",
                    evidence=line,
                    references=(
                        "https://cwe.mitre.org/data/definitions/89.html",
                        "https://owasp.org/www-community/attacks/SQL_Injection",
                    ),
                )
            )
        elif (
            function_name.endswith((".execute", ".executemany"))
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in self.dynamic_query_names
        ):
            self.findings.append(
                _new_finding(
                    rule_id="python.sql_injection",
                    title="SQL query variable is dynamically assembled",
                    severity="HIGH",
                    file=self.relative_path,
                    line=node.lineno,
                    description=(
                        "The query variable was assigned a dynamically formatted string in "
                        "this file. Confirm that untrusted input is not interpolated."
                    ),
                    recommendation=(
                        "Use parameterized SQL and pass values separately; avoid string "
                        "interpolation for query construction."
                    ),
                    source="SupplyGuard",
                    category="Code",
                    confidence=7,
                    cwe="CWE-89",
                    evidence=line,
                    references=("https://cwe.mitre.org/data/definitions/89.html",),
                )
            )

        if function_name in {"eval", "exec"} and node.args and not isinstance(
            node.args[0], ast.Constant
        ):
            self.findings.append(
                _new_finding(
                    rule_id="python.dynamic_code_execution",
                    title=f"Dynamic code passed to {function_name}()",
                    severity="HIGH",
                    file=self.relative_path,
                    line=node.lineno,
                    description=(
                        f"{function_name}() evaluates code at runtime. Dynamically sourced code "
                        "can lead to arbitrary code execution."
                    ),
                    recommendation=(
                        "Remove dynamic evaluation. If parsing data, use a data parser such as "
                        "JSON and validate the resulting structure."
                    ),
                    source="SupplyGuard",
                    category="Code",
                    confidence=8,
                    cwe="CWE-94",
                    evidence=line,
                    references=("https://cwe.mitre.org/data/definitions/94.html",),
                )
            )

        if function_name in {"os.system", "subprocess.getoutput", "subprocess.getstatusoutput"}:
            self.findings.append(
                _new_finding(
                    rule_id="python.shell_command",
                    title="Shell command is invoked through a string interface",
                    severity="HIGH",
                    file=self.relative_path,
                    line=node.lineno,
                    description=(
                        "This API invokes a shell with a command string. Risk depends on whether "
                        "untrusted input can influence the command."
                    ),
                    recommendation=(
                        "Prefer subprocess.run with an argument list and shell=False. Validate "
                        "arguments and avoid shell metacharacter concatenation."
                    ),
                    source="SupplyGuard",
                    category="Code",
                    confidence=7,
                    cwe="CWE-78",
                    evidence=line,
                    references=("https://cwe.mitre.org/data/definitions/78.html",),
                )
            )

        if function_name.startswith("subprocess.") and any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            self.findings.append(
                _new_finding(
                    rule_id="python.subprocess_shell_true",
                    title="Subprocess call enables shell interpretation",
                    severity="HIGH",
                    file=self.relative_path,
                    line=node.lineno,
                    description=(
                        "shell=True enables shell parsing. This is dangerous when command "
                        "arguments can contain attacker-controlled data."
                    ),
                    recommendation=(
                        "Use an argument list with shell=False. If shell use is necessary, "
                        "strictly validate each input and do not concatenate untrusted text."
                    ),
                    source="SupplyGuard",
                    category="Code",
                    confidence=8,
                    cwe="CWE-78",
                    evidence=line,
                    references=("https://cwe.mitre.org/data/definitions/78.html",),
                )
            )

        if function_name in {"requests.get", "requests.post", "requests.put", "requests.request"}:
            if any(
                keyword.arg == "verify"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is False
                for keyword in node.keywords
            ):
                self.findings.append(
                    _new_finding(
                        rule_id="python.tls_verification_disabled",
                        title="TLS certificate verification is disabled",
                        severity="HIGH",
                        file=self.relative_path,
                        line=node.lineno,
                        description=(
                            "The HTTP request disables certificate validation, allowing "
                            "man-in-the-middle attacks to go undetected."
                        ),
                        recommendation="Keep TLS certificate verification enabled.",
                        source="SupplyGuard",
                        category="Code",
                        confidence=9,
                        cwe="CWE-295",
                        evidence=line,
                        references=("https://cwe.mitre.org/data/definitions/295.html",),
                    )
                )

        if function_name in {"yaml.load", "yaml.unsafe_load"}:
            safe_loader = any(
                keyword.arg == "Loader"
                and isinstance(keyword.value, ast.Attribute)
                and keyword.value.attr in {"SafeLoader", "CSafeLoader"}
                for keyword in node.keywords
            ) or (
                len(node.args) > 1
                and isinstance(node.args[1], ast.Attribute)
                and node.args[1].attr in {"SafeLoader", "CSafeLoader"}
            )
            if not safe_loader:
                self.findings.append(
                    _new_finding(
                        rule_id="python.unsafe_yaml_load",
                        title="YAML is loaded without a safe loader",
                        severity="HIGH",
                        file=self.relative_path,
                        line=node.lineno,
                        description=(
                            "Unsafe YAML loaders can construct arbitrary Python objects when "
                            "parsing untrusted documents."
                        ),
                        recommendation="Use yaml.safe_load() or an explicit SafeLoader.",
                        source="SupplyGuard",
                        category="Code",
                        confidence=8,
                        cwe="CWE-502",
                        evidence=line,
                        references=("https://cwe.mitre.org/data/definitions/502.html",),
                    )
                )

        if function_name in {"pickle.load", "pickle.loads", "dill.load", "dill.loads"}:
            self.findings.append(
                _new_finding(
                    rule_id="python.unsafe_deserialization",
                    title="Unsafe object deserialization",
                    severity="HIGH",
                    file=self.relative_path,
                    line=node.lineno,
                    description=(
                        "Pickle-compatible deserializers can execute code while loading "
                        "crafted input. The risk depends on whether the data is trusted."
                    ),
                    recommendation=(
                        "Do not deserialize untrusted data with pickle. Prefer a non-executable "
                        "format such as JSON and validate its schema."
                    ),
                    source="SupplyGuard",
                    category="Code",
                    confidence=7,
                    cwe="CWE-502",
                    evidence=line,
                    references=("https://cwe.mitre.org/data/definitions/502.html",),
                )
            )
        self.generic_visit(node)

    @staticmethod
    def _call_name(node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            prefix = _PythonSecurityVisitor._call_name(node.value)
            return f"{prefix}.{node.attr}" if prefix else node.attr
        return ""

    @staticmethod
    def _is_dynamic_string(node: ast.expr) -> bool:
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(value, ast.FormattedValue) for value in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            return node.func.attr == "format"
        return False

    def _line(self, node: ast.AST) -> str:
        line_number = getattr(node, "lineno", 1)
        if 1 <= line_number <= len(self.lines):
            return self.lines[line_number - 1]
        return ""


def _scan_python(text: str, relative_path: str) -> tuple[list[Finding], str | None]:
    try:
        tree = ast.parse(text, filename=relative_path)
    except (SyntaxError, ValueError) as error:
        return [], f"{relative_path}: Python AST checks skipped ({error.msg if isinstance(error, SyntaxError) else error})."
    visitor = _PythonSecurityVisitor(text, relative_path)
    visitor.visit(tree)
    return visitor.findings, None


def _scan_workflow(text: str, relative_path: str) -> list[Finding]:
    lines = text.splitlines()
    findings: list[Finding] = []
    pull_request_target_line: int | None = None
    checkout_lines: list[int] = []
    has_explicit_permissions = False

    for line_number, line in enumerate(lines, start=1):
        if re.search(r"^\s*permissions\s*:", line, re.IGNORECASE):
            has_explicit_permissions = True
        if re.search(r"^\s*permissions:\s*write-all\b", line, re.IGNORECASE):
            findings.append(
                _new_finding(
                    rule_id="workflow.write_all_permissions",
                    title="Workflow grants write-all permissions",
                    severity="HIGH",
                    file=relative_path,
                    line=line_number,
                    description="The workflow grants every available permission as writable.",
                    recommendation=(
                        "Set explicit workflow and job permissions, granting only the minimum "
                        "required scopes."
                    ),
                    source="SupplyGuard",
                    category="CI/CD",
                    confidence=9,
                    cwe="CWE-250",
                    evidence=line,
                    references=("https://cwe.mitre.org/data/definitions/250.html",),
                )
            )
        if re.search(r"^\s*pull_request_target\s*:", line):
            pull_request_target_line = line_number
        match = ACTION_USE.search(line)
        if match:
            reference = match.group(1).rstrip(",")
            if reference.startswith("./"):
                continue
            if "actions/checkout@" in reference:
                checkout_lines.append(line_number)
            if not IMMUTABLE_SHA.search(reference):
                findings.append(
                    _new_finding(
                        rule_id="workflow.action_not_pinned",
                        title="GitHub Action is not pinned to an immutable commit",
                        severity="MEDIUM",
                        file=relative_path,
                        line=line_number,
                        description=(
                            f"`{reference}` is a mutable action reference; a tag or branch can "
                            "change after review."
                        ),
                        recommendation=(
                            "Pin the action to a verified full commit SHA and optionally keep "
                            "the human-readable version in a comment."
                        ),
                        source="SupplyGuard",
                        category="CI/CD",
                        confidence=9,
                        cwe="CWE-829",
                        evidence=line,
                        references=("https://cwe.mitre.org/data/definitions/829.html",),
                    )
                )

    if not has_explicit_permissions:
        findings.append(
            _new_finding(
                rule_id="workflow.permissions_not_explicit",
                title="Workflow does not declare an explicit permission policy",
                severity="MEDIUM",
                file=relative_path,
                line=1,
                description=(
                    "The workflow inherits repository or organization defaults. Those defaults "
                    "can change and may grant more access than this workflow needs."
                ),
                recommendation=(
                    "Declare the minimum required top-level permissions, starting with "
                    "`permissions: {}` and granting specific scopes per job."
                ),
                source="SupplyGuard",
                category="CI/CD",
                confidence=6,
                cwe="CWE-250",
                evidence=lines[0] if lines else "",
                references=("https://cwe.mitre.org/data/definitions/250.html",),
            )
        )

    if pull_request_target_line is not None:
        for line_number in checkout_lines:
            checkout_block = "\n".join(lines[line_number - 1 : min(line_number + 7, len(lines))])
            if UNTRUSTED_PR_REF.search(checkout_block):
                findings.append(
                    _new_finding(
                        rule_id="workflow.untrusted_pull_request_checkout",
                        title="Privileged workflow checks out an untrusted pull request ref",
                        severity="CRITICAL",
                        file=relative_path,
                        line=pull_request_target_line,
                        description=(
                            "`pull_request_target` runs with base-repository privileges, while "
                            "the workflow appears to check out code controlled by the pull "
                            "request author."
                        ),
                        recommendation=(
                            "Do not check out or execute pull request code in "
                            "`pull_request_target`. Use `pull_request` or isolate privileged "
                            "operations in a separate trusted workflow."
                        ),
                        source="SupplyGuard",
                        category="CI/CD",
                        confidence=9,
                        cwe="CWE-829",
                        evidence=lines[pull_request_target_line - 1],
                        references=("https://cwe.mitre.org/data/definitions/829.html",),
                    )
                )
                break
    return findings


def _parse_dependencies(path: Path, root: Path, text: str) -> list[Dependency]:
    relative_path = _relative(path, root)
    return _parse_dependency_file(path.name, relative_path, text)


def _parse_dependency_file(name: str, relative_path: str, text: str) -> list[Dependency]:
    dependencies: list[Dependency] = []
    if name == "requirements.txt":
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = REQUIREMENT.match(line)
            if match:
                dependencies.append(
                    Dependency(match.group(1), match.group(3), "PyPI", relative_path, line_number)
                )
    elif name in {"package.json", "package-lock.json", "npm-shrinkwrap.json"}:
        try:
            manifest = json.loads(text)
        except json.JSONDecodeError as error:
            raise ScanError(f"Invalid JSON in {relative_path}: {error}") from error
        if not isinstance(manifest, dict):
            return dependencies
        if name == "package.json":
            for section in (
                "dependencies",
                "devDependencies",
                "optionalDependencies",
                "peerDependencies",
            ):
                packages = manifest.get(section, {})
                if not isinstance(packages, dict):
                    continue
                for package_name, version in packages.items():
                    if isinstance(package_name, str) and isinstance(version, str):
                        if EXACT_NPM_VERSION.fullmatch(version):
                            dependencies.append(
                                Dependency(
                                    package_name, version.lstrip("v"), "npm", relative_path, 1
                                )
                            )
        else:
            packages = manifest.get("packages", {})
            if isinstance(packages, dict):
                for package_path, package_data in packages.items():
                    if not package_path or not isinstance(package_data, dict):
                        continue
                    package_name = package_data.get("name")
                    if not isinstance(package_name, str):
                        package_name = package_path.rsplit("node_modules/", 1)[-1]
                    version = package_data.get("version")
                    if isinstance(version, str) and EXACT_NPM_VERSION.fullmatch(version):
                        direct = package_path.count("node_modules/") == 1
                        dependencies.append(
                            Dependency(
                                package_name,
                                version.lstrip("v"),
                                "npm",
                                relative_path,
                                1,
                                direct,
                            )
                        )
            if name == "package-lock.json" and not dependencies:
                _parse_npm_v1(manifest.get("dependencies", {}), relative_path, dependencies)
    elif name == "Pipfile.lock":
        try:
            manifest = json.loads(text)
        except json.JSONDecodeError as error:
            raise ScanError(f"Invalid JSON in {relative_path}: {error}") from error
        if isinstance(manifest, dict):
            for section in ("default", "develop"):
                packages = manifest.get(section, {})
                if not isinstance(packages, dict):
                    continue
                for package_name, package_data in packages.items():
                    if not isinstance(package_data, dict):
                        continue
                    version = package_data.get("version", "")
                    if isinstance(version, str) and version.startswith("=="):
                        dependencies.append(
                            Dependency(
                                package_name, version[2:], "PyPI", relative_path, 1, section == "default"
                            )
                        )
    elif name == "poetry.lock":
        if tomllib is None:
            package_blocks = re.split(r"(?m)^\[\[package\]\]\s*$", text)
            for block in package_blocks[1:]:
                package_name = re.search(r'(?m)^name\s*=\s*"([^"]+)"\s*$', block)
                version = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', block)
                if package_name and version:
                    dependencies.append(
                        Dependency(
                            package_name.group(1),
                            version.group(1),
                            "PyPI",
                            relative_path,
                            1,
                            False,
                        )
                    )
        else:
            try:
                manifest = tomllib.loads(text)
            except tomllib.TOMLDecodeError as error:
                raise ScanError(f"Invalid TOML in {relative_path}: {error}") from error
            for package in manifest.get("package", []):
                if isinstance(package, dict):
                    package_name = package.get("name")
                    version = package.get("version")
                    if isinstance(package_name, str) and isinstance(version, str):
                        dependencies.append(
                            Dependency(package_name, version, "PyPI", relative_path, 1, False)
                        )
    elif name == "go.mod":
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = GO_REQUIRE.match(line)
            if match and not match.group(1).startswith("module"):
                dependencies.append(
                    Dependency(match.group(1), match.group(2), "Go", relative_path, line_number)
                )
    elif name == "go.sum":
        seen: set[tuple[str, str]] = set()
        for line_number, line in enumerate(text.splitlines(), start=1):
            parts = line.split()
            if len(parts) < 2:
                continue
            module, version = parts[:2]
            if version.endswith("/go.mod"):
                continue
            key = (module, version)
            if key in seen or not re.fullmatch(r"v\d+\.\d+\.\d+[^/\s]*", version):
                continue
            seen.add(key)
            dependencies.append(Dependency(module, version, "Go", relative_path, line_number, False))
    return dependencies


def _parse_npm_v1(
    packages: Any, relative_path: str, output: list[Dependency], depth: int = 0
) -> None:
    if not isinstance(packages, dict) or depth > 64:
        return
    for package_name, package_data in packages.items():
        if not isinstance(package_data, dict):
            continue
        version = package_data.get("version")
        if isinstance(version, str) and EXACT_NPM_VERSION.fullmatch(version):
            output.append(
                Dependency(
                    package_name,
                    version.lstrip("v"),
                    "npm",
                    relative_path,
                    1,
                    depth == 0,
                )
            )
        _parse_npm_v1(package_data.get("dependencies", {}), relative_path, output, depth + 1)


def _cvss3_base_score(vector: str) -> float | None:
    metrics: dict[str, str] = {}
    for component in vector.split("/"):
        if ":" in component:
            key, value = component.split(":", 1)
            metrics[key] = value
    try:
        scope_changed = metrics["S"] == "C"
        attack_vector = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
        attack_complexity = {"L": 0.77, "H": 0.44}[metrics["AC"]]
        privileges_required = (
            {"N": 0.85, "L": 0.62, "H": 0.27}
            if scope_changed
            else {"N": 0.85, "L": 0.62, "H": 0.27}
        )[metrics["PR"]]
        user_interaction = {"N": 0.85, "R": 0.62}[metrics["UI"]]
        impact_values = {"H": 0.56, "L": 0.22, "N": 0.0}
        confidentiality = impact_values[metrics["C"]]
        integrity = impact_values[metrics["I"]]
        availability = impact_values[metrics["A"]]
    except KeyError:
        return None

    if scope_changed:
        privileges_required = {"N": 0.85, "L": 0.68, "H": 0.5}[metrics["PR"]]
    impact_subscore = 1 - (
        (1 - confidentiality) * (1 - integrity) * (1 - availability)
    )
    if scope_changed:
        impact = 7.52 * (impact_subscore - 0.029) - 3.25 * (impact_subscore - 0.02) ** 15
    else:
        impact = 6.42 * impact_subscore
    if impact <= 0:
        return 0.0
    exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction
    score = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10)
    return math.ceil(score * 10 - 1e-10) / 10


def _severity_from_osv(vulnerability: dict[str, Any]) -> str:
    for severity in vulnerability.get("severity", []):
        if not isinstance(severity, dict):
            continue
        score = severity.get("score")
        if isinstance(score, str) and score.startswith("CVSS:3"):
            numeric_score = _cvss3_base_score(score)
            if numeric_score is not None:
                if numeric_score >= 9:
                    return "CRITICAL"
                if numeric_score >= 7:
                    return "HIGH"
                if numeric_score >= 4:
                    return "MEDIUM"
                return "LOW"
        elif isinstance(score, (int, float)):
            if score >= 9:
                return "CRITICAL"
            if score >= 7:
                return "HIGH"
            if score >= 4:
                return "MEDIUM"
            return "LOW"
        elif isinstance(score, str):
            try:
                numeric_score = float(score)
            except ValueError:
                continue
            if 0 <= numeric_score <= 10:
                if numeric_score >= 9:
                    return "CRITICAL"
                if numeric_score >= 7:
                    return "HIGH"
                if numeric_score >= 4:
                    return "MEDIUM"
                return "LOW"
    database_specific = vulnerability.get("database_specific")
    database_severity = (
        database_specific.get("severity") if isinstance(database_specific, dict) else None
    )
    if isinstance(database_severity, str):
        normalized = database_severity.upper()
        if normalized in SEVERITY_ORDER:
            return normalized
    return "MEDIUM"


def _cvss_score_from_osv(vulnerability: dict[str, Any]) -> float | None:
    for severity in vulnerability.get("severity", []):
        if not isinstance(severity, dict):
            continue
        score = severity.get("score")
        if isinstance(score, str) and score.startswith("CVSS:3"):
            calculated = _cvss3_base_score(score)
            if calculated is not None:
                return calculated
        elif isinstance(score, (int, float)):
            return float(score)
    return None


def _query_osv(dependencies: list[Dependency]) -> list[Finding]:
    if not dependencies:
        return []
    from urllib.error import HTTPError, URLError
    from urllib.request import Request, urlopen

    findings: list[Finding] = []
    unique_queries: dict[tuple[str, str, str], list[Dependency]] = defaultdict(list)
    for dependency in dependencies:
        unique_queries[(dependency.ecosystem, dependency.name, dependency.version)].append(
            dependency
        )
    query_items = list(unique_queries.items())
    if len(query_items) > 2_000:
        raise ScanError("OSV lookup is limited to 2,000 unique dependencies per scan.")

    for start in range(0, len(query_items), 100):
        batch = query_items[start : start + 100]
        request_data = {
            "queries": [
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                for (ecosystem, name, version), _ in batch
            ]
        }
        request = Request(
            OSV_BATCH_URL,
            data=json.dumps(request_data).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "supplyguard/0.2.0"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=15) as response:
                result = json.loads(response.read(10_000_001).decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            raise ScanError(f"OSV vulnerability lookup failed: {error}") from error
        if not isinstance(result, dict) or not isinstance(result.get("results"), list):
            raise ScanError("OSV returned an unexpected response.")
        if len(result["results"]) != len(batch):
            raise ScanError("OSV returned an unexpected number of query results.")

        for index, ((ecosystem, package_name, version), locations) in enumerate(batch):
            response_item = result["results"][index]
            vulnerabilities = response_item.get("vulns", []) if isinstance(response_item, dict) else []
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    continue
                vulnerability_id = vulnerability.get("id", "Unknown advisory")
                summary = vulnerability.get("summary") or "Known vulnerability affects this dependency."
                fixed_versions = sorted(
                    {
                        fixed
                        for affected in vulnerability.get("affected", [])
                        if isinstance(affected, dict)
                        for range_data in affected.get("ranges", [])
                        if isinstance(range_data, dict)
                        for event in range_data.get("events", [])
                        if isinstance(event, dict)
                        for fixed in [event.get("fixed")]
                        if isinstance(fixed, str)
                    }
                )
                aliases = [
                    alias
                    for alias in vulnerability.get("aliases", [])
                    if isinstance(alias, str)
                ]
                reference_urls = [
                    reference.get("url")
                    for reference in vulnerability.get("references", [])
                    if isinstance(reference, dict)
                    and isinstance(reference.get("url"), str)
                    and reference["url"].startswith("https://")
                ]
                reference_urls.insert(
                    0, f"https://osv.dev/vulnerability/{vulnerability_id}"
                )
                cwes = _osv_cwes(vulnerability)
                recommendation = (
                    "Upgrade to a fixed version: " + ", ".join(fixed_versions[:5]) + "."
                    if fixed_versions
                    else "Review the advisory and update to a version confirmed as unaffected."
                )
                for dependency in locations:
                    findings.append(
                        _new_finding(
                            rule_id=f"osv.{vulnerability_id}",
                            title=f"Vulnerable dependency: {dependency.name} {dependency.version}",
                            severity=_severity_from_osv(vulnerability),
                            file=dependency.file,
                            line=dependency.line,
                            description=f"{vulnerability_id}: {summary}",
                            recommendation=recommendation,
                            source="OSV",
                            category="Dependencies",
                            confidence=10,
                            cwe=cwes[0] if cwes else None,
                            evidence=f"{ecosystem} package {dependency.name}=={dependency.version}",
                            references=reference_urls[:10],
                            fix_versions=fixed_versions,
                            cvss_score=_cvss_score_from_osv(vulnerability),
                            aliases=aliases[:10],
                        )
                    )
    return findings


def _osv_cwes(vulnerability: dict[str, Any]) -> list[str]:
    result: set[str] = set()
    database_specific = vulnerability.get("database_specific")
    if isinstance(database_specific, dict):
        cwe_ids = database_specific.get("cwe_ids", [])
        if isinstance(cwe_ids, list):
            result.update(item for item in cwe_ids if isinstance(item, str))
    return sorted(result)


def _score(findings: list[Finding]) -> tuple[int, dict[str, Any]]:
    deductions = [
        SEVERITY_PENALTY[finding.severity] * (0.5 + finding.confidence / 20)
        for finding in findings
    ]
    total_penalty = min(100, sum(deductions))
    score = max(0, round(100 - total_penalty))
    return score, {
        "model": "severity-confidence-weighted-v1",
        "description": (
            "Starts at 100. Each finding deducts a severity weight multiplied by "
            "(0.5 + confidence/20); deductions are capped at 100. This is a prioritization "
            "heuristic, not a compliance or safety certification."
        ),
        "total_penalty": round(total_penalty, 1),
        "band": "strong" if score >= 85 else "moderate" if score >= 65 else "weak",
    }


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.file, finding.line)
        existing = unique.get(key)
        if existing is None or finding.confidence > existing.confidence:
            unique[key] = finding
    return sorted(
        unique.values(),
        key=lambda item: (
            SEVERITY_ORDER[item.severity],
            -item.confidence,
            item.file,
            item.line,
            item.rule_id,
        ),
    )


def _finding_payload(finding: Finding) -> dict[str, Any]:
    result = asdict(finding)
    for key in ("references", "fix_versions", "aliases"):
        result[key] = list(result[key])
    return result


def _analyze_entries(
    target: str,
    entries: Iterable[tuple[str, bytes | None]],
    *,
    initial_skipped: list[dict[str, str]] | None = None,
    query_osv: bool = False,
    source: dict[str, Any] | None = None,
) -> dict[str, Any]:
    scan_started = time.perf_counter()
    findings: list[Finding] = []
    dependencies: list[Dependency] = []
    skipped = list(initial_skipped or [])
    scanned_count = 0
    bytes_scanned = 0
    languages: Counter[str] = Counter()
    checks_executed: Counter[str] = Counter()
    analysis_warnings: list[str] = []
    analysis_notes = [
        "Python AST checks cover selected rules only. Other languages receive secret-pattern checks, not language-specific SAST.",
        "GitHub Actions checks are targeted text rules; container, infrastructure-as-code, and image analysis are not included.",
        "A clean report means no configured rule matched, not that the repository is vulnerability-free.",
        "Finding confidence is a rule-specific triage estimate, not a statistical probability.",
        "Dependency inventory does not verify lockfile integrity, package provenance, or every transitive resolution.",
        "Direct versus transitive dependency classification is best-effort and depends on the lockfile format.",
    ]

    for relative_path, raw in entries:
        if raw is None:
            skipped.append({"file": relative_path, "reason": "exceeds 1 MB scan limit"})
            continue
        if len(raw) > MAX_FILE_SIZE:
            skipped.append({"file": relative_path, "reason": "exceeds 1 MB scan limit"})
            continue
        bytes_scanned += len(raw)
        if bytes_scanned > MAX_SCAN_BYTES:
            raise ScanError(
                f"Scan target exceeds the {MAX_SCAN_BYTES // 1_000_000} MB scan limit."
            )
        if b"\x00" in raw:
            skipped.append({"file": relative_path, "reason": "binary file"})
            continue
        text = raw.decode("utf-8", errors="replace")
        scanned_count += 1
        suffix = Path(relative_path).suffix.lower()
        language = LANGUAGE_BY_EXTENSION.get(suffix)
        if language:
            languages[language] += 1
        secret_findings = _scan_secrets(text, relative_path)
        findings.extend(secret_findings)
        checks_executed["secret_patterns"] += 1
        if suffix in PYTHON_EXTENSIONS:
            python_findings, parse_warning = _scan_python(text, relative_path)
            findings.extend(python_findings)
            if parse_warning:
                analysis_warnings.append(parse_warning)
                checks_executed["python_ast_parse_failures"] += 1
            else:
                checks_executed["python_ast_rules"] += 1
        if relative_path.startswith(".github/workflows/") and suffix in {".yml", ".yaml"}:
            findings.extend(_scan_workflow(text, relative_path))
            checks_executed["github_actions_rules"] += 1
        if Path(relative_path).name in {
            "requirements.txt",
            "package.json",
            "package-lock.json",
            "npm-shrinkwrap.json",
            "Pipfile.lock",
            "poetry.lock",
            "go.mod",
            "go.sum",
        }:
            dependencies.extend(
                _parse_dependency_file(Path(relative_path).name, relative_path, text)
            )
            checks_executed["dependency_manifests"] += 1

    if query_osv:
        findings.extend(_query_osv(dependencies))
        checks_executed["osv_queries"] = len(
            {(item.ecosystem, item.name, item.version) for item in dependencies}
        )
    elif dependencies:
        analysis_notes.append(
            "Dependency vulnerability lookup was not run. Dependency inventory is not an SCA verdict; enable OSV to check exact versions."
        )

    findings = _deduplicate_findings(findings)
    dependencies = list(
        {
            (
                dependency.ecosystem,
                dependency.name,
                dependency.version,
                dependency.file,
                dependency.line,
                dependency.direct,
            ): dependency
            for dependency in dependencies
        }.values()
    )
    components: dict[tuple[str, str, str], bool] = {}
    for dependency in dependencies:
        key = (dependency.ecosystem, dependency.name, dependency.version)
        components[key] = components.get(key, False) or dependency.direct
    ecosystem_counts = Counter(ecosystem for ecosystem, _, _ in components)
    counts = Counter(item.severity for item in findings)
    category_counts = Counter(item.category for item in findings)
    source_counts = Counter(item.source for item in findings)
    score, score_explanation = _score(findings)
    dependency_direct = sum(components.values())
    dependency_transitive = len(components) - dependency_direct
    return {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scan_duration_ms": round((time.perf_counter() - scan_started) * 1000, 1),
        "target": target,
        "source": source or {"type": "local"},
        "analysis_engine": {
            "name": "SupplyGuard",
            "version": "0.2.0",
            "rule_set": "local-rules-v2",
        },
        "files_scanned": scanned_count,
        "files_skipped": skipped,
        "bytes_scanned": bytes_scanned,
        "languages": dict(sorted(languages.items())),
        "checks_executed": dict(sorted(checks_executed.items())),
        "analysis_warnings": analysis_warnings,
        "analysis_notes": analysis_notes,
        "dependencies_found": len(components),
        "dependency_summary": {
            "direct": dependency_direct,
            "transitive": dependency_transitive,
            "ecosystems": dict(sorted(ecosystem_counts.items())),
        },
        "osv_lookup_enabled": query_osv,
        "security_score": score,
        "score_explanation": score_explanation,
        "summary": {
            **{severity.lower(): counts.get(severity, 0) for severity in SEVERITIES},
            "total": len(findings),
            "by_category": dict(sorted(category_counts.items())),
            "by_source": dict(sorted(source_counts.items())),
        },
        "findings": [_finding_payload(item) for item in findings],
    }


def scan_directory(root: Path, query_osv: bool = False) -> dict[str, Any]:
    root = root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ScanError(f"Scan target is not a directory: {root}")
    files, symlinks = _iter_files(root)
    skipped: list[dict[str, str]] = [
        {"file": path, "reason": "symbolic link not followed"} for path in symlinks
    ]

    def entries() -> Iterable[tuple[str, bytes]]:
        for path in files:
            relative_path = _relative(path, root)
            try:
                if path.stat().st_size > MAX_FILE_SIZE:
                    skipped.append(
                        {"file": relative_path, "reason": "exceeds 1 MB scan limit"}
                    )
                    continue
                with path.open("rb") as file:
                    raw = file.read(MAX_FILE_SIZE + 1)
            except OSError as error:
                raise ScanError(f"Could not read {relative_path}: {error}") from error
            yield relative_path, raw

    return _analyze_entries(
        str(root),
        entries(),
        initial_skipped=skipped,
        query_osv=query_osv,
    )
