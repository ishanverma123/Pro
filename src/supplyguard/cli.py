from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from supplyguard.scanner import SEVERITY_ORDER, ScanError, scan_directory

SEVERITY_COLORS = {"CRITICAL": "1;31", "HIGH": "31", "MEDIUM": "33", "LOW": "36"}


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if enabled else text


def format_text_report(report: dict[str, Any], color: bool = False, limit: int = 50) -> str:
    summary = report["summary"]
    source = report.get("source", {})
    lines = [
        _paint("SupplyGuard scan report", "1", color),
        f"Target:   {source.get('url') or report['target']}",
    ]
    if source.get("commit"):
        lines.append(f"Commit:   {source['commit']}")
    lines += [
        f"Files:    {report['files_scanned']} scanned, {len(report.get('files_skipped', []))} skipped",
        f"Deps:     {report['dependencies_found']} found",
        f"Score:    {report['security_score']}/100 (heuristic, not a certification)",
        "Findings: "
        + ", ".join(
            f"{summary[level.lower()]} {level.lower()}" for level in SEVERITY_COLORS
        )
        + f" ({summary['total']} total)",
        "",
    ]
    findings = sorted(
        report["findings"],
        key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f.get("line") or 0),
    )
    for finding in findings[:limit]:
        label = _paint(f"[{finding['severity']}]", SEVERITY_COLORS[finding["severity"]], color)
        location = finding["file"] + (f":{finding['line']}" if finding.get("line") else "")
        lines.append(f"{label} {finding['title']} ({finding['rule_id']}, confidence {finding['confidence']}/10)")
        lines.append(f"    {location}")
        if finding.get("evidence"):
            lines.append(f"    evidence: {finding['evidence']}")
        lines.append(f"    fix: {finding['recommendation']}")
    if len(findings) > limit:
        lines.append(f"... {len(findings) - limit} more findings; use --format json or --output for all.")
    sonar = report.get("sonarqube")
    if sonar:
        metrics = sonar["metrics"]
        gate = sonar["quality_gate"]
        gate_color = "32" if gate["status"] == "OK" else "31"
        lines += [
            "",
            _paint("SonarQube", "1", color) + f" ({sonar['server']}, project {sonar['project_key']})",
            "Quality gate: " + _paint(gate["status"], gate_color, color),
        ]
        for condition in gate["failed_conditions"]:
            lines.append(
                f"    failed: {condition['metric']} {condition['actual']} "
                f"(threshold {condition['comparator']} {condition['threshold']})"
            )
        lines.append(
            "Metrics:  "
            + ", ".join(f"{key}={metrics[key]}" for key in sorted(metrics))
        )
        for issue in sonar["issues"][:limit]:
            label = _paint(f"[{issue['severity']}]", SEVERITY_COLORS[issue["severity"]], color)
            location = f"{issue['file']}:{issue['line']}" if issue.get("line") else issue["file"]
            lines.append(f"{label} {issue['message']} ({issue['rule']})")
            lines.append(f"    {location}")
        if sonar["issues_total"] > min(limit, len(sonar["issues"])):
            lines.append(f"... {sonar['issues_total']} open bugs/vulnerabilities in total; use --output for the stored subset.")
    for warning in report.get("analysis_warnings", []):
        lines.append(f"warning: {warning}")
    return "\n".join(lines) + "\n"


def _arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="supplyguard",
        description="Scan a local directory or public GitHub repository for supply-chain security risks.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    serve_parser = commands.add_parser("serve", help="Run the local web dashboard.")
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Loopback address to bind to (default: 127.0.0.1).",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Local port to use (default: 8765; use 0 to choose an available port).",
    )
    scan_parser = commands.add_parser("scan", help="Scan a local directory or public GitHub URL.")
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Local directory or https://github.com/owner/repository (default: .).",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Console output format (default: text).",
    )
    scan_parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    scan_parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Write the full JSON report to this file.",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default="high",
        help="Exit with status 1 when findings at or above this severity exist (default: high).",
    )
    scan_parser.add_argument(
        "--osv",
        action="store_true",
        help="Send exact-pinned dependency names and versions to OSV for vulnerability lookups.",
    )
    scan_parser.add_argument(
        "--sonar-url",
        default=os.environ.get("SONAR_HOST_URL"),
        help="SonarQube server URL to include its results (default: $SONAR_HOST_URL).",
    )
    scan_parser.add_argument(
        "--sonar-project",
        default=os.environ.get("SONAR_PROJECT_KEY"),
        help="SonarQube project key (default: $SONAR_PROJECT_KEY). Token is read from $SONAR_TOKEN.",
    )
    scan_parser.add_argument("--sonar-branch", help="SonarQube branch to read (default: main branch).")
    scan_parser.add_argument(
        "--fail-on-quality-gate",
        action="store_true",
        help="Exit with status 1 when the SonarQube quality gate fails.",
    )
    return parser.parse_args(argv)


def _fails_policy(report: dict[str, Any], threshold: str) -> bool:
    if threshold == "never":
        return False
    threshold_index = SEVERITY_ORDER[threshold.upper()]
    return any(
        SEVERITY_ORDER[finding["severity"]] <= threshold_index
        for finding in report["findings"]
    )


def main(argv: list[str] | None = None) -> int:
    args = _arguments(argv)
    if args.command == "serve":
        from supplyguard.web.server import serve

        try:
            if not 0 <= args.port <= 65535:
                raise ValueError("Port must be between 0 and 65535.")
            serve(host=args.host, port=args.port)
        except (OSError, ValueError) as error:
            print(f"supplyguard: error: {error}", file=sys.stderr)
            return 2
        return 0

    try:
        if args.target.lower().startswith(("http://", "https://")):
            from supplyguard.github import scan_github_repository

            report = scan_github_repository(args.target, query_osv=args.osv)
        else:
            report = scan_directory(Path(args.target).expanduser(), query_osv=args.osv)
        if args.sonar_url or args.sonar_project:
            if not (args.sonar_url and args.sonar_project):
                raise ScanError("Both --sonar-url and --sonar-project are required for SonarQube results.")
            from supplyguard.sonarqube import fetch_sonarqube

            report["sonarqube"] = fetch_sonarqube(
                args.sonar_url,
                args.sonar_project,
                os.environ.get("SONAR_TOKEN", ""),
                args.sonar_branch,
            )
        serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            try:
                args.output.expanduser().write_text(serialized, encoding="utf-8")
            except OSError as error:
                raise ScanError(f"Could not write report to {args.output}: {error}") from error
        if args.format == "json":
            if not args.output:
                sys.stdout.write(serialized)
        else:
            color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ
            sys.stdout.write(format_text_report(report, color))
            if args.output:
                print(f"JSON report written to {args.output}")
    except ScanError as error:
        print(f"supplyguard: error: {error}", file=sys.stderr)
        return 2

    if args.fail_on_quality_gate and report.get("sonarqube", {}).get("quality_gate", {}).get("status") == "ERROR":
        print("supplyguard: SonarQube quality gate failed", file=sys.stderr)
        return 1
    if _fails_policy(report, args.fail_on):
        print(
            f"supplyguard: policy failed (--fail-on {args.fail_on}); "
            f"severity threshold exceeded",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
