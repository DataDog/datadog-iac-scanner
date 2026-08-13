const DEBOUNCE_MS = 500;

const DEFAULT_REGO = `package datadog

import data.generic.common as common_lib
import data.generic.terraform as tf_lib

DatadogPolicy contains result if {
\tresource := input.document[i].resource.aws_s3_bucket[name]
\tresource.acl == "public-read"
\tresult := {
\t\t"documentId": input.document[i].id,
\t\t"resourceType": "aws_s3_bucket",
\t\t"resourceName": tf_lib.resolve_s3_bucket_name(resource, name),
\t\t"searchKey": sprintf("aws_s3_bucket[%s].acl", [name]),
\t\t"searchLine": common_lib.build_search_line(["resource", "aws_s3_bucket", name, "acl"], []),
\t}
}
`;

const DEFAULT_SAMPLE = `resource "aws_s3_bucket" "public" {
  bucket = "my-bucket"
  acl    = "public-read"
}
`;

const SAMPLE_LANGUAGE = {
  Terraform: "hcl",
  CloudFormation: "json",
  Kubernetes: "yaml",
  Ansible: "yaml",
  CICD: "yaml",
  Dockerfile: "dockerfile",
};

let regoEditor;
let sampleEditor;
let monaco;
let evaluationErrors = [];
let debounceTimer;
let validateSeq = 0;
let lastRun = null;

function errorKey(e) {
  return [e.code, e.message, e.start_line, e.start_col, e.end_line, e.end_col].join(":");
}

function errorsToMarkers(errors) {
  const seen = new Map();
  for (const e of errors) {
    seen.set(errorKey(e), e);
  }
  return [...seen.values()].map((e) => ({
    startLineNumber: Math.max(e.start_line, 1),
    startColumn: e.start_col > 0 ? e.start_col : 1,
    endLineNumber: Math.max(e.end_line > 0 ? e.end_line : e.start_line, 1),
    endColumn: e.end_col > 0 ? e.end_col : Number.MAX_SAFE_INTEGER,
    message: e.message,
    severity: monaco.MarkerSeverity.Error,
  }));
}

function findingsToMarkers(findings) {
  return findings
    .filter((f) => f.start_line > 0)
    .map((f) => ({
      startLineNumber: f.start_line,
      startColumn: 1,
      endLineNumber: Math.max(f.end_line, f.start_line),
      endColumn: Number.MAX_SAFE_INTEGER,
      message: f.resource_type
        ? `${f.resource_type}/${f.resource_name}: ${f.resource}`
        : f.resource,
      severity: monaco.MarkerSeverity.Error,
    }));
}

function setPill(el, text, level) {
  el.textContent = text;
  el.className = "pill" + (level ? ` ${level}` : "");
}

function renderErrorList(container, errors, onClick) {
  container.innerHTML = "";
  if (!errors.length) {
    return;
  }
  for (const e of errors) {
    const item = document.createElement("div");
    item.className = "error-item";
    const loc =
      e.start_line > 0
        ? `L${e.start_line}:${e.start_col || 1}`
        : "no location";
    item.innerHTML = `<strong>${e.code}</strong> <span class="loc">${loc}</span><br>${escapeHtml(e.message)}`;
    if (e.start_line > 0 && onClick) {
      item.addEventListener("click", () => onClick(e));
    }
    container.appendChild(item);
  }
}

function escapeHtml(s) {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

async function api(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || res.statusText);
  }
  return data;
}

async function loadPlatforms() {
  const res = await fetch("/api/platforms");
  const platforms = await res.json();
  const select = document.getElementById("platform");
  select.innerHTML = "";
  for (const p of platforms) {
    const opt = document.createElement("option");
    opt.value = p;
    opt.textContent = p;
    select.appendChild(opt);
  }
  select.value = "Terraform";
}

function getPlatform() {
  return document.getElementById("platform").value;
}

function updateSampleLanguage() {
  const lang = SAMPLE_LANGUAGE[getPlatform()] || "plaintext";
  monaco.editor.setModelLanguage(sampleEditor.getModel(), lang);
}

function updateRegoMarkers() {
  const syntaxPill = document.getElementById("syntax-pill");
  const regoErrorsEl = document.getElementById("rego-errors");
  const allErrors = [...currentSyntaxErrors, ...evaluationErrors];
  monaco.editor.setModelMarkers(regoEditor.getModel(), "playground", errorsToMarkers(allErrors));
  renderErrorList(regoErrorsEl, allErrors, (e) => {
    regoEditor.revealLineInCenter(e.start_line);
    regoEditor.setPosition({ lineNumber: e.start_line, column: e.start_col || 1 });
    regoEditor.focus();
  });
}

let currentSyntaxErrors = [];

async function validateSyntax() {
  const regoQuery = regoEditor.getValue();
  const platform = getPlatform();
  const syntaxPill = document.getElementById("syntax-pill");

  if (!regoQuery.trim()) {
    currentSyntaxErrors = [];
    setPill(syntaxPill, "Idle");
    updateRegoMarkers();
    return;
  }

  const seq = ++validateSeq;
  setPill(syntaxPill, "Checking...", "progress");

  try {
    const { errors } = await api("/api/validate", { platform, regoQuery });
    if (seq !== validateSeq) return;
    currentSyntaxErrors = errors;
    if (errors.length === 0) {
      setPill(syntaxPill, "Valid syntax", "success");
    } else if (errors.length === 1) {
      setPill(syntaxPill, errors[0].start_line === 0 ? "Check failed" : "Syntax error", "danger");
    } else {
      setPill(syntaxPill, `${errors.length} syntax errors`, "danger");
    }
  } catch (err) {
    if (seq !== validateSeq) return;
    currentSyntaxErrors = [{
      code: "request_failed",
      message: err.message,
      start_line: 0,
      start_col: 0,
      end_line: 0,
      end_col: 0,
    }];
    setPill(syntaxPill, "Check failed", "danger");
  }
  updateRegoMarkers();
}

function scheduleValidate() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(validateSyntax, DEBOUNCE_MS);
}

function isStale() {
  if (!lastRun) return false;
  return (
    lastRun.regoQuery !== regoEditor.getValue() ||
    lastRun.sampleFile !== sampleEditor.getValue() ||
    lastRun.platform !== getPlatform()
  );
}

function updateSampleMarkers() {
  const runPill = document.getElementById("run-pill");
  const sampleErrorsEl = document.getElementById("sample-errors");

  if (isStale()) {
    monaco.editor.setModelMarkers(sampleEditor.getModel(), "playground", [{
      startLineNumber: 1,
      startColumn: 1,
      endLineNumber: 1,
      endColumn: 1,
      message: "Policy or sample changed since last run. Run again to refresh.",
      severity: monaco.MarkerSeverity.Warning,
    }]);
    setPill(runPill, "Stale — run again", "warning");
    sampleErrorsEl.innerHTML = "";
    return;
  }

  if (!lastRun) {
    monaco.editor.setModelMarkers(sampleEditor.getModel(), "playground", []);
    setPill(runPill, "Not run");
    sampleErrorsEl.innerHTML = "";
    return;
  }

  if (lastRun.errors?.length) {
    monaco.editor.setModelMarkers(sampleEditor.getModel(), "playground", []);
    setPill(runPill, "Evaluation failed", "danger");
    renderErrorList(sampleErrorsEl, lastRun.errors);
    return;
  }

  const findings = lastRun.findings || [];
  monaco.editor.setModelMarkers(sampleEditor.getModel(), "playground", findingsToMarkers(findings));
  if (findings.length === 0) {
    setPill(runPill, "No findings", "warning");
  } else {
    setPill(runPill, `${findings.length} finding${findings.length === 1 ? "" : "s"}`, "success");
  }
  sampleErrorsEl.innerHTML = "";
}

async function runEvaluation() {
  const runBtn = document.getElementById("run-btn");
  const platform = getPlatform();
  const regoQuery = regoEditor.getValue();
  const sampleFile = sampleEditor.getValue();

  evaluationErrors = [];
  updateRegoMarkers();

  runBtn.disabled = true;
  setPill(document.getElementById("run-pill"), "Running...", "progress");

  try {
    const result = await api("/api/evaluate", { platform, regoQuery, sampleFile });
    lastRun = { platform, regoQuery, sampleFile, ...result };
    if (result.errors?.length) {
      evaluationErrors = result.errors;
      updateRegoMarkers();
    }
  } catch (err) {
    lastRun = {
      platform,
      regoQuery,
      sampleFile,
      findings: [],
      errors: [{
        code: "request_failed",
        message: err.message,
        start_line: 0,
        start_col: 0,
        end_line: 0,
        end_col: 0,
      }],
    };
    evaluationErrors = lastRun.errors;
    updateRegoMarkers();
  } finally {
    runBtn.disabled = false;
    updateSampleMarkers();
  }
}

function initEditors() {
  regoEditor = monaco.editor.create(document.getElementById("rego-editor"), {
    value: DEFAULT_REGO,
    language: "rego",
    theme: "vs-dark",
    automaticLayout: true,
    minimap: { enabled: false },
    fontSize: 13,
    scrollBeyondLastLine: false,
  });

  sampleEditor = monaco.editor.create(document.getElementById("sample-editor"), {
    value: DEFAULT_SAMPLE,
    language: "hcl",
    theme: "vs-dark",
    automaticLayout: true,
    minimap: { enabled: false },
    fontSize: 13,
    scrollBeyondLastLine: false,
  });

  regoEditor.onDidChangeModelContent(() => {
    scheduleValidate();
    updateSampleMarkers();
  });

  sampleEditor.onDidChangeModelContent(() => {
    updateSampleMarkers();
  });
}

require.config({
  paths: { vs: "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min/vs" },
});

require(["vs/editor/editor.main"], async () => {
  monaco = window.monaco;
  await loadPlatforms();
  initEditors();

  document.getElementById("platform").addEventListener("change", () => {
    evaluationErrors = [];
    lastRun = null;
    updateSampleLanguage();
    scheduleValidate();
    updateRegoMarkers();
    updateSampleMarkers();
  });

  document.getElementById("reset-rego").addEventListener("click", () => {
    regoEditor.setValue(DEFAULT_REGO);
    evaluationErrors = [];
    lastRun = null;
    updateRegoMarkers();
    updateSampleMarkers();
  });

  document.getElementById("reset-sample").addEventListener("click", () => {
    sampleEditor.setValue(DEFAULT_SAMPLE);
    lastRun = null;
    updateSampleMarkers();
  });

  document.getElementById("run-btn").addEventListener("click", runEvaluation);

  updateSampleLanguage();
  scheduleValidate();
});
