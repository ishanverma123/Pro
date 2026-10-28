"use strict";

const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
const form = document.querySelector("#scan-form");
const sourceType = document.querySelector("#source-type");
const pathInput = document.querySelector("#repository-path");
const targetLabel = document.querySelector("#target-label");
const pathHelp = document.querySelector("#path-help");
const osvOption = document.querySelector("#osv-option");
const sonarOption = document.querySelector("#sonar-option");
const sonarFields = document.querySelector("#sonar-fields");
const sonarUrl = document.querySelector("#sonar-url");
const sonarProject = document.querySelector("#sonar-project");
const sonarBranch = document.querySelector("#sonar-branch");
const sonarDisclosure = document.querySelector("#sonar-disclosure");
const scanButton = document.querySelector("#scan-button");
const scanStatus = document.querySelector("#scan-status");
const scanError = document.querySelector("#scan-error");
const emptyState = document.querySelector("#empty-state");
const reportSection = document.querySelector("#report");
const findingSearch = document.querySelector("#finding-search");
const severityFilter = document.querySelector("#severity-filter");
const findingsList = document.querySelector("#findings-list");
const loadMoreFindings = document.querySelector("#load-more-findings");
const noResults = document.querySelector("#no-results");
const downloadButton = document.querySelector("#download-report");

let activeReport = null;
let visibleFindingLimit = 50;
let pollTimer = null;
let pollingStartedAt = 0;
const POLL_INTERVAL_MS = 900;
const MAX_POLL_DURATION_MS = 15 * 60 * 1000;

let sonarUnavailable = false;
let sonarUrlLocked = false;

function updateSonarFields() {
  sonarFields.hidden = !sonarOption.checked;
}

// The token is read from the server's environment and is never sent to the browser.
async function loadSonarConfig() {
  try {
    const { sonarqube } = await requestJson("/api/config");
    sonarUnavailable = !sonarqube.token_configured;
    sonarUrlLocked = sonarqube.url_locked;
    sonarUrl.value = sonarqube.url || "";
    sonarProject.value = sonarqube.project || "";
    sonarUrl.readOnly = sonarUrlLocked;
    sonarOption.checked = sonarqube.default_enabled;
    sonarOption.disabled = sonarUnavailable;
    if (sonarUnavailable) {
      sonarOption.checked = false;
      sonarDisclosure.textContent =
        "Unavailable: set SONAR_TOKEN (and SONAR_HOST_URL / SONAR_PROJECT_KEY) before running supplyguard serve.";
    }
  } catch {
    sonarUnavailable = true;
    sonarOption.checked = false;
    sonarOption.disabled = true;
  }
  updateSonarFields();
}

sonarOption.addEventListener("change", updateSonarFields);
loadSonarConfig();

function setBusy(isBusy) {
  scanButton.disabled = isBusy;
  sourceType.disabled = isBusy;
  pathInput.disabled = isBusy;
  osvOption.disabled = isBusy;
  sonarOption.disabled = isBusy || sonarUnavailable;
  for (const input of [sonarUrl, sonarProject, sonarBranch]) {
    input.disabled = isBusy || (input === sonarUrl && sonarUrlLocked);
  }
  scanButton.querySelector("span").textContent = isBusy ? "Scanning…" : "Start scan";
  updateScanStatus(isBusy, isBusy ? "Scan in progress" : "Ready to scan");
  if (isBusy) {
    scanError.hidden = true;
    scanError.textContent = "";
  }
}

function updateSourceMode() {
  const isGitHub = sourceType.value === "github";
  targetLabel.textContent = isGitHub ? "Public GitHub repository URL" : "Repository directory";
  pathInput.value = isGitHub ? "" : ".";
  pathInput.placeholder = isGitHub
    ? "https://github.com/owner/repository"
    : "/path/to/repository";
  pathInput.autocomplete = isGitHub ? "url" : "off";
  pathHelp.replaceChildren(
    document.createTextNode(
      isGitHub
        ? "Only public GitHub repositories are supported. The default-branch source archive and commit metadata are fetched from GitHub; code is not executed."
        : "Enter a local path. For example: ",
    ),
  );
  if (!isGitHub) {
    const example = document.createElement("code");
    example.textContent = "/Users/you/project";
    pathHelp.append(example);
  }
}

function updateScanStatus(isBusy, label) {
  scanStatus.className = isBusy ? "scan-status is-running" : "scan-idle";
  const indicator = document.createElement("span");
  indicator.className = isBusy ? "spinner" : "status-dot";
  indicator.setAttribute("aria-hidden", "true");
  scanStatus.replaceChildren(indicator, document.createTextNode(label));
}

function showError(message) {
  scanError.textContent = message;
  scanError.hidden = false;
}

async function requestJson(url, options = {}) {
  const response = await fetch(url, {
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.method === "POST" ? { "X-SupplyGuard-Token": csrfToken } : {}),
      ...options.headers,
    },
    cache: "no-store",
  });
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error("The local server returned an invalid response.");
  }
  if (!response.ok) {
    throw new Error(payload.error || `The request failed (${response.status}).`);
  }
  return payload;
}

async function pollScan(jobId) {
  if (Date.now() - pollingStartedAt > MAX_POLL_DURATION_MS) {
    setBusy(false);
    showError("The scan is taking longer than expected. Check the directory size and try again.");
    return;
  }
  try {
    const job = await requestJson(`/api/scans/${encodeURIComponent(jobId)}`);
    if (job.status === "complete") {
      clearTimeout(pollTimer);
      setBusy(false);
      renderReport(job.report);
      return;
    }
    if (job.status === "failed") {
      clearTimeout(pollTimer);
      setBusy(false);
      showError(job.error || "The scan could not be completed.");
      return;
    }
    updateScanStatus(true, job.status === "queued" ? "Waiting to scan" : "Scanning repository");
    pollTimer = window.setTimeout(() => pollScan(jobId), POLL_INTERVAL_MS);
  } catch (error) {
    clearTimeout(pollTimer);
    setBusy(false);
    showError(error instanceof Error ? error.message : "Could not retrieve scan status.");
  }
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!form.reportValidity()) return;

  clearTimeout(pollTimer);
  setBusy(true);
  try {
    const job = await requestJson("/api/scans", {
      method: "POST",
        body: JSON.stringify({
          source: sourceType.value,
          target: pathInput.value.trim(),
          osv: osvOption.checked,
          ...(sonarOption.checked && {
            sonarqube: {
              url: sonarUrl.value.trim(),
              project: sonarProject.value.trim(),
              branch: sonarBranch.value.trim(),
            },
          }),
        }),
    });
    pollingStartedAt = Date.now();
    pollScan(job.id);
  } catch (error) {
    setBusy(false);
    showError(error instanceof Error ? error.message : "Could not start the scan.");
  }
});

function renderReport(report) {
  if (!report || !Array.isArray(report.findings) || !report.summary) {
    showError("The scan report was incomplete and cannot be displayed.");
    return;
  }
  activeReport = report;
  emptyState.hidden = true;
  reportSection.hidden = false;
  downloadButton.disabled = false;

  const score = Math.max(0, Math.min(100, Number(report.security_score) || 0));
  document.querySelector("#score-value").textContent = String(score);
  const circumference = 2 * Math.PI * 44;
  document.querySelector("#score-progress").setAttribute(
    "stroke-dashoffset",
    String(circumference * (1 - score / 100)),
  );
  document.querySelector("#score-message").textContent =
    report.score_explanation?.band === "strong"
      ? "Fewer observed risks"
      : report.score_explanation?.band === "moderate"
        ? "Risks need review"
        : "Priority remediation needed";
  document.querySelector("#score-subtitle").textContent =
    `${report.files_scanned} ${report.files_scanned === 1 ? "file" : "files"} scanned · heuristic, not a certification`;
  document.querySelector("#score-model").textContent =
    report.score_explanation?.description || "A weighted estimate based on detected findings.";

  const severities = [
    ["critical", "Critical", "critical"],
    ["high", "High", "high"],
    ["medium", "Medium", "medium"],
    ["low", "Low", "low"],
  ];
  const total = report.findings.length;
  document.querySelector("#finding-total").textContent =
    `${total} ${total === 1 ? "finding" : "findings"}`;
  const severityGrid = document.querySelector("#severity-grid");
  severityGrid.replaceChildren();
  for (const [key, label, className] of severities) {
    const item = document.createElement("div");
    item.className = "severity-stat";
    const dot = document.createElement("span");
    dot.className = `severity-dot ${className}`;
    const name = document.createElement("span");
    name.textContent = label;
    const count = document.createElement("strong");
    count.textContent = String(Number(report.summary[key]) || 0);
    item.append(dot, name, count);
    severityGrid.append(item);
  }

  document.querySelector("#repo-path").textContent = report.target;
  const skipped = Array.isArray(report.files_skipped) ? report.files_skipped.length : 0;
  const dependencyCount = Number(report.dependencies_found) || 0;
  const metadata = [
    `${dependencyCount} ${dependencyCount === 1 ? "dependency" : "dependencies"} found`,
    `${report.files_scanned} files scanned`,
  ];
  if (skipped) metadata.push(`${skipped} files skipped`);
  if (report.osv_lookup_enabled) metadata.push("OSV lookup enabled");
  document.querySelector("#repo-subtitle").textContent = metadata.join(" · ");
  const revision = document.querySelector("#repo-revision");
  if (report.source?.type === "github" && report.source.commit) {
    revision.hidden = false;
    revision.href = `${report.source.repository_url}/commit/${encodeURIComponent(report.source.commit)}`;
    revision.textContent = `Public GitHub · ${report.source.commit.slice(0, 12)} · default branch`;
  } else {
    revision.hidden = true;
    revision.removeAttribute("href");
    revision.textContent = "";
  }

  renderAnalysisDetails(report);
  renderSonarQube(report.sonarqube);

  findingSearch.value = "";
  severityFilter.value = "all";
  visibleFindingLimit = 50;
  renderFindings();
  reportSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderFindings() {
  if (!activeReport) return;
  const query = findingSearch.value.trim().toLowerCase();
  const selectedSeverity = severityFilter.value;
  const findings = activeReport.findings.filter((finding) => {
    if (selectedSeverity !== "all" && finding.severity !== selectedSeverity) return false;
    if (!query) return true;
    return [
      finding.title,
      finding.file,
      finding.description,
      finding.recommendation,
      finding.rule_id,
      finding.category,
      finding.cwe,
      finding.evidence,
    ].some((value) => String(value || "").toLowerCase().includes(query));
  });
  findingsList.replaceChildren();
  noResults.hidden = findings.length > 0;
  for (const finding of findings.slice(0, visibleFindingLimit)) {
    findingsList.append(createFindingCard(finding));
  }
  loadMoreFindings.hidden = findings.length <= visibleFindingLimit;
  loadMoreFindings.textContent =
    `Show 50 more findings (${findings.length - visibleFindingLimit} remaining)`;
}

function createFindingCard(finding) {
  const card = document.createElement("article");
  card.className = "finding-card";
  const top = document.createElement("div");
  top.className = "finding-top";
  const left = document.createElement("div");
  left.className = "finding-title-group";
  const severity = document.createElement("span");
  severity.className = `severity-badge ${String(finding.severity).toLowerCase()}`;
  severity.textContent = finding.severity;
  const title = document.createElement("h3");
  title.textContent = finding.title;
  left.append(severity, title);
  const location = document.createElement("span");
  location.className = "finding-location";
  location.textContent = `${finding.file}:${finding.line}`;
  top.append(left, location);

  const description = document.createElement("p");
  description.className = "finding-description";
  description.textContent = finding.description;
  const attributes = document.createElement("div");
  attributes.className = "finding-attributes";
  for (const [label, value] of [
    ["Category", finding.category],
    ["Confidence", finding.confidence ? `${finding.confidence}/10` : null],
    ["CWE", finding.cwe],
    ["CVSS", Number.isFinite(finding.cvss_score) ? finding.cvss_score.toFixed(1) : null],
  ]) {
    if (!value) continue;
    const item = document.createElement("span");
    item.textContent = `${label}: ${value}`;
    attributes.append(item);
  }
  const recommendation = document.createElement("div");
  recommendation.className = "recommendation";
  const recommendationLabel = document.createElement("span");
  recommendationLabel.textContent = "RECOMMENDED ACTION";
  const recommendationText = document.createElement("p");
  recommendationText.textContent = finding.recommendation;
  recommendation.append(recommendationLabel, recommendationText);
  card.append(top, description, attributes);
  if (finding.evidence) {
    const evidence = document.createElement("details");
    evidence.className = "evidence-details";
    const summary = document.createElement("summary");
    summary.textContent = "Show redacted evidence";
    const code = document.createElement("pre");
    const codeText = document.createElement("code");
    codeText.textContent = finding.evidence;
    code.append(codeText);
    evidence.append(summary, code);
    card.append(evidence);
  }
  card.append(recommendation);
  if (Array.isArray(finding.fix_versions) && finding.fix_versions.length) {
    const fixes = document.createElement("p");
    fixes.className = "finding-fixes";
    fixes.textContent = `Fixed versions reported: ${finding.fix_versions.join(", ")}`;
    card.append(fixes);
  }
  if (Array.isArray(finding.references) && finding.references.length) {
    const references = document.createElement("div");
    references.className = "finding-references";
    for (const value of finding.references.slice(0, 5)) {
      try {
        const url = new URL(value);
        if (url.protocol !== "https:") continue;
        const link = document.createElement("a");
        link.href = url.href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = url.hostname === "osv.dev" ? "OSV advisory" : url.hostname;
        references.append(link);
      } catch {
        continue;
      }
    }
    if (references.childElementCount) card.append(references);
  }
  return card;
}

function renderSonarQube(sonar) {
  const panel = document.querySelector("#sonar-panel");
  panel.hidden = !sonar;
  if (!sonar) return;

  const gate = document.querySelector("#sonar-gate");
  const errorBox = document.querySelector("#sonar-error");
  const metricsBox = document.querySelector("#sonar-metrics");
  const conditionsBox = document.querySelector("#sonar-conditions");
  const issuesBox = document.querySelector("#sonar-issues");
  const note = document.querySelector("#sonar-note");
  for (const box of [metricsBox, conditionsBox, issuesBox]) box.replaceChildren();
  conditionsBox.hidden = true;
  errorBox.hidden = !sonar.error;
  errorBox.textContent = sonar.error ? `SonarQube results unavailable: ${sonar.error}` : "";
  if (sonar.error) {
    gate.className = "gate-badge unknown";
    gate.textContent = "NOT AVAILABLE";
    note.textContent = `${sonar.server || ""} · ${sonar.project_key || ""}`;
    return;
  }

  const status = sonar.quality_gate?.status;
  gate.className = `gate-badge ${status === "OK" ? "passed" : status === "ERROR" ? "failed" : "unknown"}`;
  gate.textContent = status === "OK" ? "GATE PASSED" : status === "ERROR" ? "GATE FAILED" : `GATE ${status || "UNKNOWN"}`;

  const labels = {
    bugs: "Bugs",
    vulnerabilities: "Vulnerabilities",
    security_hotspots: "Security hotspots",
    code_smells: "Code smells",
    coverage: "Coverage %",
    duplicated_lines_density: "Duplication %",
    ncloc: "Lines of code",
    reliability_rating: "Reliability",
    security_rating: "Security",
    security_review_rating: "Security review",
    sqale_rating: "Maintainability",
  };
  for (const [key, label] of Object.entries(labels)) {
    if (!(key in (sonar.metrics || {}))) continue;
    const item = document.createElement("div");
    item.className = "sonar-metric";
    const name = document.createElement("span");
    name.textContent = label;
    const value = document.createElement("strong");
    value.textContent = String(sonar.metrics[key]);
    item.append(name, value);
    metricsBox.append(item);
  }

  const failed = sonar.quality_gate?.failed_conditions || [];
  if (failed.length) {
    conditionsBox.hidden = false;
    for (const condition of failed) {
      const line = document.createElement("p");
      line.textContent = `Failed: ${condition.metric} is ${condition.actual} (threshold ${condition.comparator} ${condition.threshold})`;
      conditionsBox.append(line);
    }
  }

  for (const issue of sonar.issues || []) {
    const row = document.createElement("div");
    row.className = "sonar-issue";
    const badge = document.createElement("span");
    badge.className = `severity-badge ${String(issue.severity || "low").toLowerCase()}`;
    badge.textContent = issue.severity || "LOW";
    const message = document.createElement("span");
    message.textContent = issue.message || issue.rule || "Issue";
    const meta = document.createElement("span");
    meta.className = "issue-meta";
    meta.textContent = `${issue.file}${issue.line ? `:${issue.line}` : ""} · ${issue.rule}`;
    row.append(badge, message, meta);
    issuesBox.append(row);
  }
  const shown = (sonar.issues || []).length;
  note.textContent =
    `${sonar.server} · ${sonar.project_key}${sonar.branch ? ` · ${sonar.branch}` : ""} · ` +
    `${sonar.issues_total} open bugs/vulnerabilities${sonar.issues_truncated ? ` (showing ${shown})` : ""}. ` +
    "Read from the server's latest analysis; not included in the SupplyGuard score.";
}

function renderAnalysisDetails(report) {
  const languages = document.querySelector("#language-list");
  languages.replaceChildren();
  const languageEntries = Object.entries(report.languages || {});
  if (languageEntries.length) {
    for (const [language, count] of languageEntries) {
      const chip = document.createElement("span");
      chip.className = "analysis-chip";
      chip.textContent = `${language} · ${count}`;
      languages.append(chip);
    }
  } else {
    languages.textContent = "No recognized source languages detected.";
  }

  const checks = document.querySelector("#check-list");
  checks.replaceChildren();
  const checkLabels = {
    secret_patterns: "Secret-pattern scan",
    python_ast_rules: "Python AST security rules",
    python_ast_parse_failures: "Python files skipped by AST parser",
    github_actions_rules: "GitHub Actions workflow rules",
    dependency_manifests: "Dependency manifest and lockfile parsing",
    osv_queries: "Unique package versions queried in OSV",
  };
  const checkEntries = Object.entries(report.checks_executed || {});
  for (const [key, count] of checkEntries) {
    const row = document.createElement("div");
    row.className = "check-row";
    const name = document.createElement("span");
    name.textContent = checkLabels[key] || key.replaceAll("_", " ");
    const total = document.createElement("strong");
    total.textContent = String(count);
    row.append(name, total);
    checks.append(row);
  }
  if (!checkEntries.length) checks.textContent = "No analysis checks were reported.";

  const warningContainer = document.querySelector("#analysis-warnings");
  const warnings = [
    ...(Array.isArray(report.analysis_notes) ? report.analysis_notes : []),
    ...(Array.isArray(report.analysis_warnings) ? report.analysis_warnings : []),
  ];
  warningContainer.replaceChildren();
  warningContainer.hidden = warnings.length === 0;
  for (const warning of warnings) {
    const item = document.createElement("p");
    item.textContent = warning;
    warningContainer.append(item);
  }
  const skippedCount = Array.isArray(report.files_skipped) ? report.files_skipped.length : 0;
  const bytes = Number(report.bytes_scanned) || 0;
  document.querySelector("#scan-completeness").textContent =
    `${skippedCount} skipped · ${(bytes / 1_000_000).toFixed(2)} MB analyzed`;
  const skippedDetails = document.querySelector("#skipped-details");
  const skippedList = document.querySelector("#skipped-list");
  const skippedFiles = Array.isArray(report.files_skipped) ? report.files_skipped : [];
  skippedDetails.hidden = skippedFiles.length === 0;
  skippedList.replaceChildren();
  for (const skipped of skippedFiles.slice(0, 100)) {
    const item = document.createElement("li");
    item.textContent = `${skipped.file}: ${skipped.reason}`;
    skippedList.append(item);
  }
  document.querySelector("#skipped-summary").textContent =
    skippedFiles.length > 100
      ? `Skipped files (${skippedFiles.length}; first 100 shown — export JSON for full list)`
      : `Skipped files (${skippedFiles.length})`;
}

function resetFindingPage() {
  visibleFindingLimit = 50;
  renderFindings();
}

findingSearch.addEventListener("input", resetFindingPage);
severityFilter.addEventListener("change", resetFindingPage);
loadMoreFindings.addEventListener("click", () => {
  visibleFindingLimit += 50;
  renderFindings();
});
sourceType.addEventListener("change", updateSourceMode);
updateSourceMode();

downloadButton.addEventListener("click", () => {
  if (!activeReport) return;
  const blob = new Blob([`${JSON.stringify(activeReport, null, 2)}\n`], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "supplyguard-report.json";
  link.hidden = true;
  document.body.append(link);
  link.click();
  window.setTimeout(() => {
    URL.revokeObjectURL(url);
    link.remove();
  }, 1000);
});
