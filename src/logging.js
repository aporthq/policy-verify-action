function emitRunLog({
  repository,
  prNumber,
  configuredMode,
  verification = {},
  structuralFindings = [],
  warnings = [],
  willFail = false,
} = {}) {
  logLine("APort Repository Guard");
  logLine("-----------------------");
  logLine(`Repository: ${sanitizePlainLogValue(repository || "-")}`);
  logLine(`Pull request: ${prNumber ? `#${prNumber}` : "-"}`);
  logLine(`Mode: ${sanitizePlainLogValue(configuredMode || verification.mode || "auto")}`);
  logLine(`Verification: ${sanitizePlainLogValue(verification.mode || "-")}`);

  const decision = verification.decision;
  if (decision) {
    logLine(`Decision: ${decision.allow ? "allow" : "deny"}`);
    if (decision.decision_id) logLine(`Decision ID: ${sanitizePlainLogValue(decision.decision_id)}`);
    if (decision.outcome) logLine(`Outcome: ${sanitizePlainLogValue(decision.outcome)}`);
    logDecisionReasons(decision.reasons);
  } else if (verification.warning) {
    logLine(`Verification warning: ${sanitizePlainLogValue(verification.warning)}`);
  }

  if (structuralFindings.length) {
    logLine("");
    logLine("Structural findings:");
    for (const finding of structuralFindings) {
      logFinding(finding);
      emitFindingAnnotation(finding, willFail);
    }
  } else {
    logLine("");
    logLine("Structural findings: none");
  }

  if (warnings.length) {
    logLine("");
    logLine("Warnings:");
    for (const warning of warnings) {
      logLine(`- ${sanitizePlainLogValue(warning)}`);
      emitAnnotation("warning", "APort warning", warning);
    }
  }

  if (willFail) {
    emitAnnotation(
      "error",
      "APort Repository Guard blocked this workflow",
      "Hosted enforcement failed because APort returned a deny decision, hosted verification failed, or a high/error structural finding was detected.",
    );
  }

  logLine("-----------------------");
}

function logDecisionReasons(reasons = []) {
  if (!Array.isArray(reasons) || reasons.length === 0) return;
  logLine("Decision reasons:");
  for (const reason of reasons) {
    const code = sanitizePlainLogValue(reason?.code || "reason");
    const message = sanitizePlainLogValue(reason?.message || "");
    logLine(`- ${code}${message ? `: ${message}` : ""}`);
  }
}

function logFinding(finding = {}) {
  const severity = sanitizePlainLogValue(String(finding.severity || "info").toUpperCase());
  const code = sanitizePlainLogValue(finding.code || "OAP.REPO.FINDING");
  const message = sanitizePlainLogValue(finding.message || "Repository finding.");
  const paths = Array.isArray(finding.paths) && finding.paths.length
    ? ` (${finding.paths.map((path) => sanitizePlainLogValue(path)).join(", ")})`
    : "";
  logLine(`- ${severity} ${code}: ${message}${paths}`);
}

function emitFindingAnnotation(finding = {}, willFail = false) {
  const severity = String(finding.severity || "info").toLowerCase();
  const annotationType = ["high", "error"].includes(severity)
    ? "error"
    : severity === "warning"
      ? "warning"
      : "notice";
  const titlePrefix =
    annotationType === "error" && willFail ? "Blocking APort finding" : "APort finding";
  const title = `${titlePrefix}: ${finding.code || "OAP.REPO.FINDING"}`;
  const message = finding.message || "Repository finding.";
  const paths = Array.isArray(finding.paths) ? finding.paths.filter(Boolean) : [];

  if (!paths.length) {
    emitAnnotation(annotationType, title, message);
    return;
  }

  for (const path of paths) {
    emitAnnotation(annotationType, title, `${message} (${path})`, { file: path });
  }
}

function emitAnnotation(type, title, message, properties = {}) {
  const safeType = ["error", "warning", "notice"].includes(type)
    ? type
    : "notice";
  const attrs = {
    title,
    ...properties,
  };
  const attrString = Object.entries(attrs)
    .filter(([, value]) => value !== undefined && value !== null && value !== "")
    .map(([key, value]) => `${key}=${escapeWorkflowCommandProperty(value)}`)
    .join(",");
  const command = attrString ? `::${safeType} ${attrString}::` : `::${safeType}::`;
  logLine(`${command}${escapeWorkflowCommandMessage(message)}`);
}

function escapeWorkflowCommandMessage(value) {
  return stripTerminalControlBytes(value)
    .replace(/%/g, "%25")
    .replace(/\r/g, "%0D")
    .replace(/\n/g, "%0A");
}

function escapeWorkflowCommandProperty(value) {
  return escapeWorkflowCommandMessage(value)
    .replace(/:/g, "%3A")
    .replace(/,/g, "%2C");
}

function sanitizePlainLogValue(value) {
  return stripTerminalControlBytes(value)
    .replace(/[\r\n]+/g, " ")
    .replace(/::/g, ": :");
}

function stripTerminalControlBytes(value) {
  return String(value ?? "")
    .replace(/\u001B\][^\u0007]*(?:\u0007|\u001B\\)/g, "")
    .replace(/\u001B\[[0-?]*[ -/]*[@-~]/g, "")
    .replace(/\u001B[\u0020-\u002F]*[\u0030-\u007E]/g, "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, "");
}

function logLine(message) {
  process.stdout.write(`${message}\n`);
}

module.exports = {
  emitRunLog,
  escapeWorkflowCommandMessage,
  escapeWorkflowCommandProperty,
  sanitizePlainLogValue,
  stripTerminalControlBytes,
};
