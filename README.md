# SupplyGuard

SupplyGuard is a local-first software supply-chain scanner with a command-line
interface and a responsive local web dashboard. It uses only the Python
standard library and does not clone, install, or execute code from a scanned
repository.

## What it checks

- Likely AWS keys, GitHub tokens, private-key headers, and hard-coded credentials.
- Python AST checks for interpolated SQL, dynamic `eval`/`exec`, shell-enabled
  subprocess calls, disabled TLS verification, unsafe YAML loading, and
  pickle-compatible deserialization.
- GitHub Actions workflow references that are not pinned to a full commit SHA,
  missing explicit permission policies, workflows granting `write-all`, and
  the risky combination of `pull_request_target` with checkout of an untrusted
  pull request ref.
- Exact-version dependency inventory from `requirements.txt`, npm manifests
  and lockfiles, `Pipfile.lock`, `poetry.lock`, `go.mod`, and `go.sum`.
- Optional OSV vulnerability lookups with CVSS v3 scoring, advisory references,
  aliases, and reported fixed versions.

Findings include rule identifiers, severity, CWE where available, confidence
estimates, redacted source evidence, references, CVSS scores and aliases where
reported by OSV, fixed versions, and remediation guidance. Reports also include
coverage, skipped files, language counts, dependency totals, analysis notes,
scan duration, and the score formula/version. Secret values are redacted from
evidence.

These are deterministic baseline checks, not a complete SAST or secret-scanning
engine. They can miss issues or produce false positives. Confidence is a
triage estimate, not a probability; the security score is a prioritization
heuristic, not a compliance or safety certification. Vulnerability lookups only
cover exact versions recognized by OSV. Language-specific AST checks currently
cover selected Python rules; other languages receive secret-pattern scanning,
and GitHub Actions checks are targeted text rules. Container, infrastructure-
as-code, cloud posture, and image checks are not implemented. Direct versus
transitive dependency classification is best-effort.

## Install and run

Requires Python 3.10 or later. Install in a virtual environment:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/supplyguard scan . --output supplyguard-report.json
```

CLI usage (`scan` accepts a local directory or a public GitHub URL):

```sh
supplyguard scan .                                   # readable terminal report
supplyguard scan https://github.com/owner/repository # public GitHub repository
supplyguard scan . --format json                     # JSON on stdout
supplyguard scan . --output report.json              # also save full JSON
supplyguard scan . --fail-on medium --osv --no-color # CI gate with OSV lookups
```

To include results from your SonarQube server (the token is read from the
environment, never from a flag, so it stays out of shell history):

```sh
export SONAR_TOKEN=...   # user or project analysis token with Browse permission
supplyguard scan . --sonar-url https://sonar.example.com --sonar-project my-key \
  [--sonar-branch main] [--fail-on-quality-gate]
```

`SONAR_HOST_URL` and `SONAR_PROJECT_KEY` may be used instead of the flags. The
report gains a `sonarqube` section with the quality-gate status and failed
conditions, key metrics (bugs, vulnerabilities, code smells, hotspots, coverage,
duplication, ratings), and up to 500 open bugs/vulnerabilities. This reads the
server's latest analysis; SupplyGuard does not run the SonarQube scanner, and
these results are reported separately without changing the SupplyGuard score.
Only `https://` is accepted (`http://` for localhost), redirects are refused so
the token is never forwarded.

The dashboard shows the same data in a **Quality gate & code quality** panel.
Set the variables before starting it and the SonarQube toggle is on by default,
prefilled with your server and project (the URL is locked to `SONAR_HOST_URL`
when set; the project key and branch can be edited per scan):

```sh
SONAR_TOKEN=... SONAR_HOST_URL=https://sonar.example.com \
  SONAR_PROJECT_KEY=my-key supplyguard serve
```

The token is held only by the server process and is never sent to the browser.
Without `SONAR_TOKEN` the toggle is disabled. If SonarQube is unreachable the
scan still completes and the panel shows the error.

Exit codes: `0` pass, `1` severity threshold exceeded, `2` error.

Start the web dashboard:

```sh
.venv/bin/supplyguard serve
```

Open the loopback URL printed by the command (by default
`http://127.0.0.1:8765`). Select **Local directory** or **Public GitHub
repository**, enter its path or URL, then select **Start scan**. The dashboard
shows a score with its formula, coverage and limitations, severity breakdown,
filterable detailed findings, and a JSON report download.

GitHub scanning accepts only public repository URLs of the form
`https://github.com/owner/repository`. It resolves and records a commit SHA,
then downloads that immutable commit's archive from GitHub without cloning or
executing project code. Repository metadata and source are sent only to
GitHub; enabling OSV additionally sends exact dependency coordinates to
`api.osv.dev`. Private repositories, arbitrary URLs, and repository subpaths
are not supported.

Stop the local server with `Ctrl-C`.

By default, the command exits with status `1` if it finds a high- or
critical-severity finding, which makes it usable as a CI gate. Override that
threshold with `--fail-on critical|high|medium|low|never`.

To look up pinned dependencies in OSV:

```sh
.venv/bin/supplyguard scan . --osv --output supplyguard-report.json
```

`--osv` sends dependency package names and exact versions to `api.osv.dev`.
It is opt-in; without it, scanning and reporting are local-only. Network or
malformed-manifest errors are reported and return status `2`, rather than
producing a success-shaped partial report. Lookups are batched and limited to
2,000 unique dependency versions per scan. Without OSV, the report explicitly
notes that dependency inventory is not a vulnerability assessment.

The dashboard binds only to a loopback address, rejects non-loopback hosts,
and uses a per-run request token, origin checks, a restrictive content
security policy, and no cross-origin API access. It is intended for a single
trusted user on their own machine; do not expose it through a network proxy or
change it to listen on a public interface. Scan jobs run one at a time and
recent results remain in memory only for the lifetime of the server.

The scanner prunes common generated/vendor directories (`.git`, virtual
environments, `node_modules`, `dist`, and `build`), does not follow symbolic
links, and skips binary files and files over 1 MB. It caps scans at 25,000
files, 100,000 filesystem entries, and 250 MB of scanned content. Skipped files
are listed in the JSON report. These limits prevent unbounded work but do not
replace operating-system isolation when scanning untrusted or very large trees.
GitHub archives additionally have a 75 MB compressed-download limit. Python
syntax errors are reported as analysis warnings rather than silently treated
as fully analyzed files.

The GUI/API is designed for one trusted local user. It is not a multi-user,
network-facing deployment: do not expose it through a proxy or bind it to a
public interface. For production CI or enterprise use, run dedicated SAST/SCA
tools and isolate scans at the OS/container level.

## Development

```sh
python -m unittest discover -s tests -v
python -m supplyguard.cli --help
python -m supplyguard.cli serve --help
```
